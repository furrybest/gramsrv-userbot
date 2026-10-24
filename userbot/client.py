"""WinterGramClient — главный класс юзербота для приватного MTProto-сервера."""

import asyncio
import inspect
import logging
import os

from .errors import (
    WinterGramError,
    RPCError,
    AuthKeyError,
    LayerMismatchError,
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneNumberUnoccupiedError,
)
from .crypto.rsa import parse_public_key, compute_server_fingerprint
from .crypto.rsa import RSA as _RSA
from .network.connection import Connection, connect_with_autodetect
from .network.mtproto import MTProtoConnection
from .session.session import Session
from .session.storage import Storage
from .api.functions import Functions
from .api.updates import MessageHandler, UpdatesProcessor, NewMessage, MessageEdited, MessageDeleted

__log__ = logging.getLogger("wintergram.client")

# ---------------------------------------------------------------- #
#  Публичный API ID Telegram Desktop (не секрет, работает
#  на большинстве приваток). Переопределяется в конструкторе.
# ---------------------------------------------------------------- #
DEFAULT_API_ID = 2040
DEFAULT_API_HASH = "b18441a1ff607e10a989891a5462e627"


class WinterGramClient:
    """Клиент юзербота для приватного MTProto-сервера (одна сессия).

    Использование:

        client = WinterGramClient(
            server_ip="127.0.0.1",
            server_port=2398,
            dc_id=2,
            rsa_keys_pem=["-----BEGIN RSA PUBLIC KEY-----\\n...\\n-----END RSA PUBLIC KEY-----"],
            session_path="session.db",
        )
        await client.start()
        await client.send_message("me", "привет!")
    """

    def __init__(
        self,
        api_id=DEFAULT_API_ID,
        api_hash=DEFAULT_API_HASH,
        session_path=None,
        transport="abridged",
        server_ip=None,
        server_port=None,
        dc_id=None,
        rsa_keys_pem=None,
    ):
        if server_ip is None or server_port is None or dc_id is None:
            raise WinterGramError(
                "server_ip, server_port и dc_id обязательны. "
                "Укажи адрес своего приватного сервера."
            )
        if not rsa_keys_pem:
            raise WinterGramError(
                "rsa_keys_pem обязателен. Передай публичный RSA-ключ(-и) "
                "своего приватного сервера (PEM-строку или список строк)."
            )
        if isinstance(rsa_keys_pem, str):
            rsa_keys_pem = [rsa_keys_pem]

        self.api_id = int(api_id)
        self.api_hash = api_hash
        self.server_ip = server_ip
        self.server_port = int(server_port)
        self.dc_id = int(dc_id)
        self.transport_name = transport
        self.storage = Storage(session_path)
        self.session = Session(dc_id=self.dc_id, transport=transport, storage=self.storage)
        self.connection = None
        self.conn = None          # MTProtoConnection
        self.functions = None
        self.handlers = MessageHandler()
        self.updates = None
        self._connected = False
        self._rsa_keys = None
        self._rsa_keys_pem = list(rsa_keys_pem)
        self._lazy_loaded = False

    # ------------------------------------------------------------------ #
    #  ключи
    # ------------------------------------------------------------------ #

    def rsa_keys(self):
        if self._rsa_keys is None:
            keys = []
            for pem in self._rsa_keys_pem:
                try:
                    rsa = _RSA.from_pem(pem)
                except Exception as e:
                    raise WinterGramError(
                        "Не удалось разобрать RSA-ключ из rsa_keys_pem: %r" % e
                    )
                keys.append(rsa)
                __log__.info("rsa key fingerprint=%016x", rsa.fingerprint)
            self._rsa_keys = keys
        return self._rsa_keys

    # ------------------------------------------------------------------ #
    #  подключение / отключение
    # ------------------------------------------------------------------ #

    async def connect(self):
        if self._connected:
            return self
        if not self._lazy_loaded:
            self.storage.open()
            self.session.load()
            self._lazy_loaded = True

        try:
            t_conn, used = await self._establish(self.transport_name)
        except Exception:
            # автоопределение транспорта (prompt §3.2)
            t_conn, used = await connect_with_autodetect(
                self.server_ip, self.server_port, self.transport_name
            )
        self.transport_name = used
        self.connection = t_conn
        self.conn = MTProtoConnection(
            t_conn.transport, self.session,
            api_id=self.api_id, api_hash=self.api_hash,
            schema_era="latest",
        )
        self.functions = Functions(self.conn, self.api_id, self.api_hash)
        self.updates = UpdatesProcessor(self.conn._schema)

        if not self.session.has_auth_key:
            await self._do_handshake()

        await self.conn.start_reader()
        self.conn.on_push = self._on_push
        try:
            layer = await self.conn.detect_layer()
        except (LayerMismatchError, AuthKeyError) as e:
            __log__.error("layer detection failed: %r", e)
            raise
        self.session.layer = layer
        self.session.save()
        self._connected = True
        __log__.info("connected, layer=%s", layer)
        return self

    async def _establish(self, transport_name):
        conn = Connection(self.server_ip, self.server_port, transport_name)
        await conn.connect()
        return conn, transport_name

    async def _do_handshake(self):
        last_err = None
        for key in self.rsa_keys():
            for use_legacy in (False, True):
                try:
                    await self.conn.handshake(
                        "", key, self.dc_id, use_legacy_pad=use_legacy
                    )
                    self.session.save()
                    return
                except AuthKeyError as e:
                    last_err = e
                    __log__.warning(
                        "handshake attempt key=%016x legacy=%s failed: %r",
                        key.fingerprint, use_legacy, e,
                    )
        raise AuthKeyError("handshake failed: %r" % (last_err,))

    async def disconnect(self):
        if self.conn:
            await self.conn.close()
        if self.connection:
            self.connection.close()
        if self.session:
            self.session.save()
            self.session.close()
        self._connected = False
        __log__.info("disconnected")

    # ------------------------------------------------------------------ #
    #  авторизация (runtime-ввод номера/кода)
    # ------------------------------------------------------------------ #

    async def _input(self, prompt: str) -> str:
        """Блокирующий input() в отдельном потоке (для asyncio)."""
        val = await asyncio.to_thread(input, prompt)
        return (val or "").strip()

    async def start(self, phone=None, code_callback=None, password_callback=None):
        """Логин: номер и код вводятся в рантайме (input или callback)."""
        await self.connect()
        if self.session.user_id is not None:
            __log__.info("already authorized as user %s", self.session.user_id)
            return self

        phone = (phone or await self._input("Номер телефона (с '+') : ")).strip()
        self.session.phone = phone

        sent = await self.functions.send_code(phone)
        phone_code_hash = sent.get("phone_code_hash")
        __log__.info("sendCode ok, phone_code_hash=%s", phone_code_hash)

        if code_callback is not None:
            res = code_callback(phone)
            if inspect.isawaitable(res):
                res = await res
            code = (res or "").strip()
        else:
            code = ""
        code = code or await self._input("Код подтверждения: ")

        try:
            await self.functions.sign_in(phone, code, phone_code_hash)
        except PhoneNumberUnoccupiedError:
            __log__.info("номер не зарегистрирован — регистрирую (signUp)")
            first = await self._input("Имя: ")
            last = await self._input("Фамилия (enter для пропуска): ")
            await self.functions.sign_up(phone, code, phone_code_hash, first, last)
        except SessionPasswordNeededError:
            __log__.info("сервер требует 2FA-пароль")
            pw_obj = await self.functions.get_password()
            if password_callback is not None:
                res = password_callback()
                if inspect.isawaitable(res):
                    res = await res
                password = res
            else:
                password = await self._input("2FA пароль: ")
            await self.functions.check_password(password, pw_obj)

        await self.functions.get_me()
        self.session.save()
        __log__.info("authorized as user %s", self.session.user_id)
        return self

    # ------------------------------------------------------------------ #
    #  события
    # ------------------------------------------------------------------ #

    def on(self, event_type):
        """Декоратор: @client.on(NewMessage)."""
        return self.handlers.on(event_type)

    async def _on_push(self, obj):
        events = self.updates.process(obj)
        if events:
            await self.handlers.dispatch(events)

    # ------------------------------------------------------------------ #
    #  высокоуровневые методы
    # ------------------------------------------------------------------ #

    async def send_message(self, peer, text):
        """Отправляет текстовое сообщение.

        Args:
            peer: ID чата, username или "me"
            text: текст сообщения
        """
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self.resolve_peer(peer)
        if peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (peer,))
        return await self.functions.send_message(peer_obj, text)

    async def send_photo(self, peer, photo_path_or_url, caption="", reply_to=0):
        """Отправляет фото по URL или локальному пути с подписью.

        Args:
            peer: ID чата, username или "me"
            photo_path_or_url: URL фото или путь к локальному файлу
            caption: подпись к фото (опционально)
            reply_to: ID сообщения, на которое отвечаем (опционально)
        """
        import os
        import tempfile

        # Проверяем - это локальный файл или URL
        if os.path.isfile(photo_path_or_url):
            # Локальный файл - используем его напрямую
            tmp_path = photo_path_or_url
            delete_tmp = False
        else:
            # URL - скачиваем
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(photo_path_or_url) as resp:
                    if resp.status != 200:
                        raise WinterGramError(f"Failed to download photo: HTTP {resp.status}")

                    # Сохраняем во временный файл
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp:
                        tmp.write(await resp.read())
                        tmp_path = tmp.name
            delete_tmp = True

        try:
            # Загружаем файл и отправляем
            if isinstance(peer, str) and peer.lower() in ("me", "self"):
                peer_obj = self.functions.input_peer_self()
            else:
                peer_obj = await self.resolve_peer(peer)

            if peer_obj is None:
                raise RPCError(0, "peer %r could not be resolved" % (peer,))

            # Читаем файл
            with open(tmp_path, 'rb') as f:
                file_bytes = f.read()

            # Отправляем через низкоуровневый API
            import random
            file_id = random.randint(1, 2**63 - 1)

            # Загружаем файл
            file_parts = []
            part_size = 524288  # 512 KB
            for i, offset in enumerate(range(0, len(file_bytes), part_size)):
                part = file_bytes[offset:offset + part_size]
                file_parts.append(part)

            # Отправляем части файла
            for part_num, part in enumerate(file_parts):
                await self.conn.rpc("upload.saveFilePart", {
                    "file_id": file_id,
                    "file_part": part_num,
                    "bytes": part
                })

            # Отправляем медиа-сообщение
            media_params = {
                "peer": peer_obj,
                "media": {
                    "_": "inputMediaUploadedPhoto",
                    "file": {
                        "_": "inputFile",
                        "id": file_id,
                        "parts": len(file_parts),
                        "name": "photo.jpg",
                        "md5_checksum": ""
                    }
                },
                "message": caption,
                "random_id": random.randint(1, 2**63 - 1)
            }
            media_params.update(self.functions.reply_params("messages.sendMedia", reply_to))

            try:
                result = await self.conn.rpc("messages.sendMedia", media_params)
            except Exception as e:
                if not reply_to:
                    raise
                # сервер не принял ответ на сообщение — шлём фото без него
                __log__.warning("sendMedia with reply_to failed (%r), retrying without", e)
                media_params.pop("reply_to", None)
                media_params.pop("reply_to_msg_id", None)
                result = await self.conn.rpc("messages.sendMedia", media_params)

            return result

        finally:
            # Удаляем временный файл только если скачивали
            if delete_tmp and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def edit_message(self, peer, msg_id, text):
        """Редактирует существующее сообщение."""
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self.resolve_peer(peer)
        if peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (peer,))
        return await self.functions.edit_message(peer_obj, msg_id, text)

    async def delete_message(self, peer, msg_id, revoke=True):
        """Удаляет одно сообщение.

        Args:
            peer: ID чата, username или "me"
            msg_id: ID сообщения для удаления
            revoke: True - удалить для всех, False - только для себя
        """
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self.resolve_peer(peer)
        if peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (peer,))
        return await self.functions.delete_message(peer_obj, msg_id, revoke)

    async def delete_messages(self, peer, msg_ids, revoke=True):
        """Удаляет несколько сообщений.

        Args:
            peer: ID чата, username или "me"
            msg_ids: список ID сообщений для удаления
            revoke: True - удалить для всех, False - только для себя
        """
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self.resolve_peer(peer)
        if peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (peer,))
        return await self.functions.delete_messages(peer_obj, msg_ids, revoke)

    async def get_history(self, peer, limit=50):
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self.resolve_peer(peer)
        return await self.functions.get_history(peer_obj, limit)

    async def get_me(self):
        if self.functions is None:
            raise WinterGramError("client is not connected")
        return await self.functions.get_me()

    async def get_state(self):
        _, obj = await self.functions.get_state()
        return obj

    async def forward_message(self, from_peer, to_peer, msg_id, drop_author=False):
        """Пересылает одно сообщение из одного чата в другой.

        Args:
            from_peer: ID чата-источника или "me"
            to_peer: ID чата назначения или "me"
            msg_id: ID сообщения для пересылки
            drop_author: скрыть автора оригинального сообщения
        """
        from_peer_obj = await self._resolve_peer_helper(from_peer)
        to_peer_obj = await self._resolve_peer_helper(to_peer)
        return await self.functions.forward_messages(from_peer_obj, to_peer_obj, [msg_id], drop_author)

    async def forward_messages(self, from_peer, to_peer, msg_ids, drop_author=False):
        """Пересылает несколько сообщений из одного чата в другой.

        Args:
            from_peer: ID чата-источника или "me"
            to_peer: ID чата назначения или "me"
            msg_ids: список ID сообщений для пересылки
            drop_author: скрыть автора оригинального сообщения
        """
        from_peer_obj = await self._resolve_peer_helper(from_peer)
        to_peer_obj = await self._resolve_peer_helper(to_peer)
        return await self.functions.forward_messages(from_peer_obj, to_peer_obj, msg_ids, drop_author)

    async def get_dialogs(self, limit=100):
        """Получает список диалогов (чатов).

        Args:
            limit: количество диалогов (макс 100)

        Returns:
            Объект с полями: dialogs, messages, users, chats
        """
        return await self.functions.get_dialogs(limit=limit)

    async def iter_dialogs(self, limit=None):
        """Итератор по всем диалогам.

        Args:
            limit: максимальное количество диалогов (None = все)

        Yields:
            dialog: объект диалога
        """
        offset_date = 0
        offset_id = 0
        offset_peer = self.functions.input_peer_self()
        total = 0

        while True:
            _, result = await self.functions.get_dialogs(
                limit=100,
                offset_date=offset_date,
                offset_id=offset_id,
                offset_peer=offset_peer
            )

            dialogs = result.get("dialogs", [])
            if not dialogs:
                break

            for dialog in dialogs:
                yield dialog
                total += 1
                if limit and total >= limit:
                    return

            # Обновляем offset
            last_msg = result.get("messages", [])[-1] if result.get("messages") else None
            if last_msg:
                offset_date = last_msg.get("date", 0)
                offset_id = last_msg.get("id", 0)
                # Пытаемся получить peer из последнего диалога
                last_dialog = dialogs[-1]
                peer = last_dialog.get("peer")
                if peer:
                    offset_peer = peer
            else:
                break

    async def mark_read(self, peer, max_id=0):
        """Отмечает сообщения как прочитанные.

        Args:
            peer: ID чата или "me"
            max_id: ID последнего прочитанного сообщения (0 = все)
        """
        peer_obj = await self._resolve_peer_helper(peer)
        return await self.functions.mark_read(peer_obj, max_id)

    async def iter_messages(self, peer, limit=None, offset_id=0):
        """Итератор по сообщениям чата.

        Args:
            peer: ID чата или "me"
            limit: максимальное количество сообщений (None = все)
            offset_id: ID сообщения, с которого начать

        Yields:
            message: объект сообщения
        """
        peer_obj = await self._resolve_peer_helper(peer)
        total = 0

        while True:
            _, result = await self.functions.get_history(peer_obj, limit=100)
            messages = result.get("messages", [])

            if not messages:
                break

            for msg in messages:
                if msg.get("id", 0) > offset_id:
                    continue
                yield msg
                total += 1
                if limit and total >= limit:
                    return

            # Обновляем offset
            offset_id = messages[-1].get("id", 0) - 1
            if offset_id <= 0:
                break

    async def update_profile(self, first_name=None, last_name=None, about=None):
        """Обновляет информацию профиля.

        Args:
            first_name: новое имя
            last_name: новая фамилия
            about: новое описание (bio)
        """
        return await self.functions.update_profile(first_name, last_name, about)

    async def update_status(self, offline=False):
        """Обновляет онлайн-статус.

        Args:
            offline: True - показать оффлайн, False - показать онлайн
        """
        return await self.functions.update_status(offline)

    # ------------------------------------------------------------------ #
    #  профиль: юзернейм, аватар, приватность, сессии
    # ------------------------------------------------------------------ #

    async def check_username(self, username):
        """Проверяет, свободен ли юзернейм.

        Args:
            username: имя без @

        Returns:
            True, если можно занять
        """
        return await self.functions.check_username(username)

    async def set_username(self, username):
        """Меняет основной юзернейм аккаунта.

        Args:
            username: новый юзернейм без @

        Raises:
            RPCError: если юзернейм занят или сервер его отклонил
        """
        return await self.functions.update_username((username or "").lstrip("@"))

    async def remove_username(self):
        """Снимает основной юзернейм (то же, что set_username(""))."""
        return await self.functions.update_username("")

    async def toggle_username(self, username, active=True):
        """Включает/выключает дополнительный юзернейм."""
        return await self.functions.toggle_username((username or "").lstrip("@"), active)

    async def reorder_usernames(self, order):
        """Задаёт порядок юзернеймов (первый становится основным)."""
        return await self.functions.reorder_usernames([u.lstrip("@") for u in order])

    async def set_avatar(self, photo, fallback=None):
        """Загружает новую аватарку.

        Args:
            photo: путь к файлу, http(s)-ссылка или сами байты
            fallback: True - поставить как запасную аватарку

        Returns:
            photos.Photo от сервера
        """
        data = await self._load_media(photo)
        if isinstance(photo, str) and not photo.startswith(("http://", "https://")):
            name = os.path.basename(photo) or "avatar.jpg"
        else:
            name = "avatar.jpg"
        return await self.functions.upload_profile_photo(data, file_name=name, fallback=fallback)

    async def remove_avatar(self, photo_id=None):
        """Удаляет аватарки.

        Args:
            photo_id: id фото; если не задан - удаляется самая свежая своя
        """
        if photo_id is None:
            _, res = await self.functions.get_profile_photos(limit=1)
            photos = res.get("photos") or []
            if not photos:
                raise WinterGramError("no profile photos to remove")
            photo_id = photos[0].get("id")
        return await self.functions.delete_profile_photo(photo_id)

    async def get_avatars(self, peer=None, limit=20):
        """Возвращает список аватарок (своих, если peer не задан)."""
        user = await self._resolve_input_user(peer) if peer is not None else None
        _, result = await self.functions.get_profile_photos(user_id=user, limit=limit)
        return result.get("photos", [])

    async def get_profile(self, peer=None):
        """Полная информация о профиле (users.getFullUser)."""
        if peer is None:
            return await self.functions.get_full_user(self.functions.input_user_self())
        return await self.functions.get_full_user(await self._resolve_input_user(peer))

    async def set_privacy(self, key, rules):
        """Меняет правила приватности.

        Args:
            key: last_seen | phone_number | profile_photo | chat_invite | forwards | about
            rules: ['all'] | ['contacts'] | ['close_friends'] | ['nobody'] |
                   ['bots'] | ['premium'] | [('chats', chats)]

        Examples:
            await client.set_privacy("last_seen", ["nobody"])
            await client.set_privacy("profile_photo", ["contacts"])
        """
        return await self.functions.set_privacy(key, rules)

    async def get_privacy(self, key):
        """Текущие правила приватности по ключу."""
        return await self.functions.get_privacy(key)

    async def set_birthday(self, day, month, year=None):
        """Задаёт день рождения в профиле."""
        return await self.functions.update_birthday(day, month, year)

    async def set_profile_color(self, color=None, for_profile=True):
        """Задаёт цвет профиля (None - сбросить)."""
        return await self.functions.update_profile_color(color, for_profile)

    async def set_emoji_status(self, emoji=None):
        """Ставит эмодзи-статус (None - очистить)."""
        return await self.functions.set_emoji_status(emoji)

    async def get_sessions(self):
        """Список активных сессий аккаунта (account.getAuthorizations)."""
        _, result = await self.functions.get_authorizations()
        return result.get("authorizations", [])

    async def terminate_session(self, auth_hash):
        """Завершает чужую сессию по её hash."""
        return await self.functions.reset_authorization(auth_hash)

    async def get_account_ttl(self):
        """Текущая настройка автоудаления аккаунта."""
        return await self.functions.get_account_ttl()

    async def set_account_ttl(self, days=0):
        """Автоудаление аккаунта через N дней (0 — выключить)."""
        return await self.functions.set_account_ttl(days)

    async def _load_media(self, source):
        """Приводит путь / http-ссылку / bytes к байтам файла."""
        if isinstance(source, (bytes, bytearray)):
            return bytes(source)
        import urllib.request

        if isinstance(source, str) and source.startswith(("http://", "https://")):
            def _download():
                with urllib.request.urlopen(source, timeout=30) as resp:
                    return resp.read()
            return await asyncio.to_thread(_download)

        if isinstance(source, str) and os.path.isfile(source):
            def _read():
                with open(source, "rb") as f:
                    return f.read()
            return await asyncio.to_thread(_read)

        raise WinterGramError(
            "expected bytes, file path or http(s) URL, got %r" % type(source).__name__
        )

    async def _resolve_input_user(self, peer):
        """InputPeer (или 'me'/None -> self) -> InputUser для users.*/photos.*."""
        peer_obj = await self._resolve_peer_helper(peer)
        if peer_obj is None or "user_id" not in peer_obj:
            raise WinterGramError("peer %r is not a user" % (peer,))
        _, res = await self.functions.get_users([
            self.functions.input_user(peer_obj["user_id"], peer_obj.get("access_hash"))
        ])
        users = res if isinstance(res, list) else (res.get("users") if isinstance(res, dict) else None)
        if not users:
            raise WinterGramError("cannot resolve user for peer %r" % (peer,))
        user = users[0]
        return self.functions.input_user(user.get("id"), user.get("access_hash"))

    async def join_chat(self, peer):
        """Присоединяется к каналу/супергруппе.

        Args:
            peer: ID канала
        """
        peer_obj = await self._resolve_peer_helper(peer)
        return await self.functions.join_channel(peer_obj)

    async def leave_chat(self, peer):
        """Покидает канал/супергруппу.

        Args:
            peer: ID канала
        """
        peer_obj = await self._resolve_peer_helper(peer)
        return await self.functions.leave_channel(peer_obj)

    async def get_participants(self, peer, limit=100):
        """Получает список участников канала/супергруппы.

        Args:
            peer: ID канала
            limit: количество участников
        """
        peer_obj = await self._resolve_peer_helper(peer)
        return await self.functions.get_participants(peer_obj, limit)

    async def _resolve_peer_helper(self, peer):
        """Вспомогательный метод для resolve_peer с поддержкой 'me'."""
        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            return self.functions.input_peer_self()
        return await self.resolve_peer(peer)

    async def resolve_username(self, username):
        """Ищет пользователя по юзернейму (с @ или без) через contacts.resolveUsername.

        Args:
            username: "@nick" или "nick"

        Returns:
            InputPeer текущей эры

        Raises:
            WinterGramError: если юзернейм не найден
        """
        name = (username or "").strip().lstrip("@")
        if not name:
            raise WinterGramError("empty username")

        _, result = await self.functions.resolve_username(name)

        peer = result.get("peer") or {}
        users = result.get("users") or []
        chats = result.get("chats") or []

        if "user_id" in peer:
            target_id = peer.get("user_id")
            user = next((u for u in users if u.get("id") == target_id), None)
            if user is None and users:
                user = users[0]
            if user is None or user.get("access_hash") is None:
                raise WinterGramError("no access_hash for @%s" % name)
            self.storage.store_peer(user["id"], user["access_hash"], "user")
            return self.functions.input_peer_user(user["id"], user["access_hash"])

        if "chat_id" in peer:
            return self.functions.input_peer_chat(peer["chat_id"])

        if "channel_id" in peer:
            target_id = peer.get("channel_id")
            chat = next((c for c in chats if c.get("id") == target_id), None)
            access_hash = (chat or {}).get("access_hash", 0)
            self.storage.store_peer(target_id, access_hash, "channel")
            return self.functions.input_peer_channel(target_id, access_hash)

        raise WinterGramError("username @%s not found" % name)

    async def resolve_peer(self, peer):
        """Пиринг в InputPeer текущей эры (по возможности через кэш)."""
        if isinstance(peer, str):
            low = peer.lower()
            if low in ("me", "self"):
                return self.functions.input_peer_self()
            if low.startswith("@") or peer[:1].isalpha() or "_" in peer:
                return await self.resolve_username(peer)
            raise RPCError(0, "pass id, 'me' or @username")
        peer_id = int(peer)
        cached = self.storage.get_peer(abs(peer_id)) if self.storage._db else None
        access_hash = cached[0] if cached else 0
        access_hash &= 0xFFFFFFFFFFFFFFFF
        if peer_id > 0:
            return self.functions.input_peer_user(peer_id, access_hash)
        if -1000000000000 < peer_id <= 0:
            return self.functions.input_peer_chat(-peer_id)
        # канал / супергруппа
        return self.functions.input_peer_channel(-peer_id - 1000000000000, access_hash)

    # ------------------------------------------------------------------ #
    #  низкоуровневые вызовы
    # ------------------------------------------------------------------ #

    async def call(self, method: str, params: dict):
        """Произвольный RPC-вызов по имени метода (например 'help.getConfig').
        Возвращает только объект-результат (без msg_id)."""
        _, obj = await self.conn.rpc(method, params)
        return obj

    # ------------------------------------------------------------------ #
    #  подарки (star gifts и NFT)
    # ------------------------------------------------------------------ #

    async def get_available_gifts(self):
        """Получает список всех доступных подарков для отправки.

        Returns:
            Список подарков с информацией о цене, иконке и т.д.
        """
        _, result = await self.functions.get_star_gifts()
        return result.get("gifts", [])

    async def send_gift(self, peer, gift_id, message=None, hide_name=False):
        """Отправляет подарок (мишка, NFT и т.д.) пользователю.

        Args:
            peer: ID пользователя, username или "me"
            gift_id: ID подарка из списка get_available_gifts()
            message: текст сообщения к подарку (опционально)
            hide_name: True - скрыть имя отправителя, False - показать

        Returns:
            Результат отправки подарка

        Example:
            # Получаем список подарков
            gifts = await client.get_available_gifts()
            # Отправляем первый подарок с сообщением
            await client.send_gift(user_id, gifts[0]["id"], "С Днём Рождения!")
        """
        peer_obj = await self._resolve_peer_helper(peer)

        # Проверяем, можно ли отправить этот подарок
        try:
            _, check_result = await self.functions.check_can_send_gift(gift_id)
            result_type = check_result.get("_", "")
            if "Fail" in result_type:
                reason = check_result.get("reason", {})
                reason_text = reason.get("text", "Unknown reason") if isinstance(reason, dict) else str(reason)
                raise RPCError(0, f"Cannot send gift: {reason_text}")
        except RPCError as e:
            if "METHOD_NOT_FOUND" not in str(e):
                raise
            # Метод checkCanSendGift не поддерживается, продолжаем

        # Отправляем подарок
        return await self.functions.send_star_gift(peer_obj, gift_id, message, hide_name)

    async def get_my_gifts(self, exclude_unsaved=False, limit=100):
        """Получает подарки, полученные текущим пользователем.

        Args:
            exclude_unsaved: True - только сохраненные подарки
            limit: максимальное количество подарков

        Returns:
            Список полученных подарков
        """
        peer_obj = self.functions.input_peer_self()
        _, result = await self.functions.get_saved_star_gifts(
            peer_obj,
            offset="",
            limit=limit,
            exclude_unsaved=exclude_unsaved
        )
        return result.get("gifts", [])

    async def convert_gift_to_stars(self, msg_id):
        """Конвертирует полученный подарок в звезды (Stars).

        Args:
            msg_id: ID сообщения с подарком

        Returns:
            Результат конвертации

        Note:
            Конвертированный подарок исчезнет из коллекции!
        """
        return await self.functions.convert_star_gift(msg_id)

    async def transfer_gift(self, msg_id, to_peer):
        """Переводит уникальный подарок (NFT) другому пользователю.

        Args:
            msg_id: ID сообщения с подарком
            to_peer: ID получателя, username или "me"

        Returns:
            Результат перевода

        Note:
            Работает только для уникальных подарков (NFT), которые можно передавать
        """
        to_peer_obj = await self._resolve_peer_helper(to_peer)
        return await self.functions.transfer_star_gift(msg_id, to_peer_obj)

    # ------------------------------------------------------------------ #
    #  сообщения: get/copy/pin + документы
    # ------------------------------------------------------------------ #

    async def get_messages(self, peer, msg_ids):
        """Получает одно или несколько сообщений по их ID.

        Args:
            peer: ID чата, username или "me"
            msg_ids: int или список int

        Returns:
            Список сообщений из ответа messages.getMessages
        """
        if isinstance(msg_ids, (int,)):
            msg_ids = [msg_ids]
        elif isinstance(msg_ids, (tuple,)):
            msg_ids = list(msg_ids)

        if not isinstance(msg_ids, list):
            raise WinterGramError("msg_ids must be int or list/tuple of ints")

        peer_obj = await self._resolve_peer_helper(peer)

        if hasattr(self.functions, "get_messages"):
            try:
                _, result = await self.functions.get_messages(peer_obj, msg_ids)
                if isinstance(result, dict):
                    return result.get("messages", result)
                return result
            except Exception:
                pass

        try:
            _, result = await self.conn.rpc("messages.getMessages", {
                "id": [{"_": "inputMessageID", "id": mid} for mid in msg_ids]
            })
            if isinstance(result, dict):
                return result.get("messages", result)
            return result
        except Exception:
            pass

        # Фолбэк: пытаемся взять из истории
        try:
            hist = await self.get_history(peer, limit=100)
            msgs = hist.get("messages", []) if isinstance(hist, dict) else hist
            if not isinstance(msgs, list):
                return []
            mid_set = set(msg_ids)
            return [m for m in msgs if m.get("id") in mid_set]
        except Exception:
            return []

    async def send_document(self, peer, file, caption="", reply_to=0):
        """Отправляет документ по пути, URL или байтам.

        Args:
            peer: ID чата, username или "me"
            file: путь к файлу, http(s)-ссылка или bytes/bytearray
            caption: подпись к документу
            reply_to: ID сообщения для ответа
        """
        import os
        import random
        import tempfile

        data = await self._load_media(file)

        if isinstance(file, str):
            if file.startswith(("http://", "https://")):
                name = os.path.basename(file.split("?")[0]) or "document.bin"
            elif os.path.isfile(file):
                name = os.path.basename(file)
            else:
                name = "document.bin"
        else:
            name = "document.bin"

        if isinstance(peer, str) and peer.lower() in ("me", "self"):
            peer_obj = self.functions.input_peer_self()
        else:
            peer_obj = await self._resolve_peer_helper(peer)
        if peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (peer,))

        file_id = random.randint(1, 2 ** 63 - 1)
        file_parts = []
        part_size = 524288  # 512 KB
        for i, offset in enumerate(range(0, len(data), part_size)):
            file_parts.append(data[offset:offset + part_size])

        for part_num, part in enumerate(file_parts):
            await self.conn.rpc("upload.saveFilePart", {
                "file_id": file_id,
                "file_part": part_num,
                "bytes": part
            })

        media_params = {
            "peer": peer_obj,
            "media": {
                "_": "inputMediaUploadedDocument",
                "file": {
                    "_": "inputFile",
                    "id": file_id,
                    "parts": len(file_parts),
                    "name": name,
                    "md5_checksum": ""
                },
                "mime_type": "application/octet-stream",
                "attributes": [{"_": "documentAttributeFilename", "file_name": name}]
            },
            "message": caption or "",
            "random_id": random.randint(1, 2 ** 63 - 1)
        }
        media_params.update(self.functions.reply_params("messages.sendMedia", reply_to))

        try:
            result = await self.conn.rpc("messages.sendMedia", media_params)
        except Exception as e:
            if not reply_to:
                raise
            __log__.warning("sendMedia(document) with reply_to failed (%r), retrying without", e)
            media_params.pop("reply_to", None)
            media_params.pop("reply_to_msg_id", None)
            result = await self.conn.rpc("messages.sendMedia", media_params)
        return result

    async def copy_message(self, from_peer, to_peer, msg_id, caption=None):
        """Копирует сообщение без упоминания "Forwarded from".

        Args:
            from_peer: источник (необязателен, берём по peer/ID)
            to_peer: получатель
            msg_id: ID сообщения для копирования
            caption: новый текст подписи (только для медиа)
        """
        import random

        msgs = await self.get_messages(from_peer, msg_id)
        if not msgs:
            raise WinterGramError("message %s not found in %r" % (msg_id, from_peer))
        msg = msgs[0] if isinstance(msgs, list) else msgs

        if isinstance(to_peer, str) and to_peer.lower() in ("me", "self"):
            to_peer_obj = self.functions.input_peer_self()
        else:
            to_peer_obj = await self._resolve_peer_helper(to_peer)
        if to_peer_obj is None:
            raise RPCError(0, "peer %r could not be resolved" % (to_peer,))

        text = msg.get("message") or msg.get("text") or ""
        entities = msg.get("entities") or []
        media = msg.get("media")

        if media and media.get("_"):
            mtype = media.get("_")
            if mtype in ("messageMediaPhoto",):
                # пытаемся переслать через sendMedia по имеющимся данным не всегда возможно
                # fallback на отправку текста с упоминанием при невозможности
                pass
            # для большинства случаев проще переслать как есть через messages.sendMessage с копией
            pass

        params = {
            "peer": to_peer_obj,
            "message": caption if caption is not None else text,
            "random_id": random.randint(1, 2 ** 63 - 1)
        }
        if entities and caption is None:
            params["entities"] = entities
        if media and media.get("_") and media.get("_") not in ("messageMediaWebPage",):
            params["media"] = media

        try:
            _, res = await self.conn.rpc("messages.sendMessage", params)
            return res
        except Exception as e:
            __log__.warning("copy_message: sendMessage failed (%r), trying forward without drop_author as fallback", e)
            from_peer_obj = await self._resolve_peer_helper(from_peer)
            return await self.functions.forward_messages(from_peer_obj, to_peer_obj, [msg_id], drop_author=False)

    async def pin_message(self, peer, msg_id, notify=True):
        """Закрепляет сообщение в чате/канале.

        Args:
            peer: ID чата, username или "me"
            msg_id: ID сообщения
            notify: уведомлять участников о закреплении
        """
        peer_obj = await self._resolve_peer_helper(peer)
        if hasattr(self.functions, "pin_message"):
            return await self.functions.pin_message(peer_obj, msg_id, notify)
        try:
            return await self.conn.rpc("messages.updatePinnedMessage", {
                "peer": peer_obj,
                "id": msg_id,
                "silent": not notify
            })
        except Exception:
            # channels вариант
            return await self.conn.rpc("channels.updatePinnedMessage", {
                "channel": peer_obj,
                "id": msg_id,
                "silent": not notify
            })

    async def unpin_message(self, peer, msg_id):
        """Открепляет сообщение в чате/канале.

        Args:
            peer: ID чата, username или "me"
            msg_id: ID сообщения
        """
        peer_obj = await self._resolve_peer_helper(peer)
        if hasattr(self.functions, "unpin_message"):
            return await self.functions.unpin_message(peer_obj, msg_id)
        try:
            return await self.conn.rpc("messages.updatePinnedMessage", {
                "peer": peer_obj,
                "id": 0,
                "silent": True
            })
        except Exception:
            try:
                return await self.conn.rpc("channels.updatePinnedMessage", {
                    "channel": peer_obj,
                    "id": 0,
                    "silent": True
                })
            except Exception:
                return await self.pin_message(peer, msg_id, notify=False)

    # ------------------------------------------------------------------ #
    #  чаты: редактирование + инфа
    # ------------------------------------------------------------------ #

    async def edit_chat_title(self, peer, title):
        """Меняет название чата/супергруппы/канала.

        Args:
            peer: ID чата/канала, username
            title: новое название
        """
        title = (title or "").strip()
        peer_obj = await self._resolve_peer_helper(peer)
        if hasattr(self.functions, "edit_chat_title"):
            return await self.functions.edit_chat_title(peer_obj, title)
        # Попробуем определить тип
        ptype = peer_obj.get("_", "") if isinstance(peer_obj, dict) else ""
        if "Channel" in ptype:
            try:
                return await self.conn.rpc("channels.editTitle", {"channel": peer_obj, "title": title})
            except Exception:
                pass
        try:
            return await self.conn.rpc("messages.editChatTitle", {"chat_id": peer_obj.get("chat_id") if isinstance(peer_obj, dict) else abs(int(peer)), "title": title})
        except Exception:
            return await self.conn.rpc("channels.editTitle", {"channel": peer_obj, "title": title})

    async def edit_chat_about(self, peer, about):
        """Меняет описание чата/канала.

        Args:
            peer: ID чата/канала, username
            about: новое описание
        """
        about = about or ""
        peer_obj = await self._resolve_peer_helper(peer)
        if hasattr(self.functions, "edit_chat_about"):
            return await self.functions.edit_chat_about(peer_obj, about)
        ptype = peer_obj.get("_", "") if isinstance(peer_obj, dict) else ""
        if "Channel" in ptype:
            try:
                return await self.conn.rpc("channels.editAbout", {"channel": peer_obj, "about": about})
            except Exception:
                pass
        try:
            return await self.conn.rpc("messages.editChatAbout", {"peer": peer_obj, "about": about})
        except Exception:
            return await self.conn.rpc("channels.editAbout", {"channel": peer_obj, "about": about})

    async def get_full_chat(self, peer):
        """Получает полную информацию о чате/канале.

        Args:
            peer: ID чата/канала, username

        Returns:
            Полный объект чата (users/chats/full_chat/full_channel)
        """
        peer_obj = await self._resolve_peer_helper(peer)
        if hasattr(self.functions, "get_full_chat"):
            try:
                _, res = await self.functions.get_full_chat(peer_obj)
                return res
            except Exception:
                pass
        ptype = peer_obj.get("_", "") if isinstance(peer_obj, dict) else ""
        if "Channel" in ptype:
            try:
                _, res = await self.conn.rpc("channels.getFullChannel", {"channel": peer_obj})
                return res
            except Exception:
                pass
        try:
            chat_id = peer_obj.get("chat_id") if isinstance(peer_obj, dict) else abs(int(peer))
            _, res = await self.conn.rpc("messages.getFullChat", {"chat_id": chat_id})
            return res
        except Exception:
            try:
                _, res = await self.conn.rpc("channels.getFullChannel", {"channel": peer_obj})
                return res
            except Exception as e:
                raise WinterGramError("cannot get full chat for %r: %r" % (peer, e))

    # ------------------------------------------------------------------ #
    #  контакты
    # ------------------------------------------------------------------ #

    async def add_contact(self, phone, first_name, last_name=""):
        """Добавляет контакт в адресную книгу.

        Args:
            phone: номер телефона с + или без
            first_name: имя
            last_name: фамилия (опционально)
        """
        phone = (phone or "").strip()
        first_name = (first_name or "").strip()
        last_name = (last_name or "").strip()
        if not phone or not first_name:
            raise WinterGramError("phone and first_name are required")

        if hasattr(self.functions, "add_contact"):
            try:
                return await self.functions.add_contact(phone, first_name, last_name)
            except Exception:
                pass

        try:
            import random
            return await self.conn.rpc("contacts.addContact", {
                "id": {"_": "inputPhoneContact", "client_id": random.randint(1, 2 ** 63 - 1), "phone": phone, "first_name": first_name, "last_name": last_name},
                "add_phone_privacy_exception": False
            })
        except Exception:
            return await self.conn.rpc("contacts.importContacts", {
                "contacts": [{"_": "inputPhoneContact", "client_id": 0, "phone": phone, "first_name": first_name, "last_name": last_name}]
            })

    # ------------------------------------------------------------------ #

    async def __aenter__(self):
        return await self.connect()

    async def __aexit__(self, *exc):
        await self.disconnect()
