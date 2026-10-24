"""Высокоуровневый API: auth, sendMessage, getHistory, получения метаданных.

Каждый метод сам выбирает type_id и поля через SchemaResolver (по текущему слою
соединения), поэтому один и тот же вызов работает на схемах 167..228.
"""

import logging
import os
import time

from ..errors import (
    RPCError,
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneNumberUnoccupiedError,
)
from ..crypto.srp import compute_password_check

__log__ = logging.getLogger("wintergram.api.functions")


class Functions:
    """Обёртка над MTProtoConnection с понятными методами."""

    def __init__(self, conn, api_id=2040, api_hash="b18441a1ff607e10a989891a5462e627"):
        self.conn = conn
        self.api_id = api_id
        self.api_hash = api_hash

    @property
    def schema(self):
        return self.conn._schema

    # ------------------------------------------------------------------ #
    #  авторизация
    # ------------------------------------------------------------------ #

    async def send_code(self, phone: str):
        """auth.sendCode. Возвращает auth.sentCode (phone_code_hash и пр.)."""
        code_settings_desc = self.schema.by_name("codeSettings")
        if code_settings_desc is None:
            raise RPCError(0, "codeSettings not available in schema")
        _, obj = await self.conn.rpc("auth.sendCode", {
            "phone_number": phone,
            "api_id": self.api_id,
            "api_hash": self.api_hash,
            "settings": {"_id": code_settings_desc["id"]},
        })
        return obj

    async def sign_in(self, phone: str, code: str, phone_code_hash: str):
        """auth.signIn (code вводится пользователем в рантайме)."""
        try:
            result = await self.conn.rpc("auth.signIn", {
                "phone_number": phone,
                "phone_code_hash": phone_code_hash,
                "phone_code": code,
            })
        except RPCError as e:
            if e.message == "SESSION_PASSWORD_NEEDED":
                raise SessionPasswordNeededError(e.code, e.message)
            if e.message == "PHONE_CODE_INVALID":
                raise PhoneCodeInvalidError(e.code, e.message)
            if e.message in ("PHONE_NUMBER_UNOCCUPIED", "KEY_UNOCCUPIED"):
                raise PhoneNumberUnoccupiedError(e.code, e.message)
            if e.message == "PHONE_CODE_EXPIRED":
                from ..errors import PhoneCodeExpiredError
                raise PhoneCodeExpiredError(e.code, e.message)
            raise
        self._store_auth(result)
        return result

    async def sign_up(self, phone: str, code: str, phone_code_hash: str,
                      first_name: str, last_name: str = ""):
        """auth.signUp."""
        result = await self.conn.rpc("auth.signUp", {
            "phone_number": phone,
            "phone_code_hash": phone_code_hash,
            "first_name": first_name,
            "last_name": last_name,
        })
        self._store_auth(result)
        return result

    async def get_password(self):
        """account.getPassword — параметры для 2FA."""
        return await self.conn.rpc("account.getPassword", {})

    async def check_password(self, password: str, password_obj):
        """auth.checkPassword (2FA) — считает SRP по текущей схеме."""
        _, pw = password_obj
        algo = pw.get("current_algo")
        if algo is None:
            raise RPCError(0, "server has no current_algo; 2FA flow unclear")
        salt1 = algo.get("salt1")
        salt2 = algo.get("salt2")
        g = algo.get("g")
        p = algo.get("p")
        srp_b = pw.get("srp_B")
        srp_id = pw.get("srp_id")
        if not (salt1 and salt2 and g and p and srp_b):
            raise RPCError(0, "incomplete SRP params from account.getPassword")

        req = compute_password_check(password, srp_id, srp_b, salt1, salt2, g, p)
        input_desc = self.schema.by_name("inputCheckPasswordSRP")
        password_value = {
            "_id": input_desc["id"],
            "srp_id": req["srp_id"],
            "A": req["A"],
            "M1": req["M1"],
        }
        result = await self.conn.rpc("auth.checkPassword", {"password": password_value})
        self._store_auth(result)
        return result

    # ------------------------------------------------------------------ #
    #  пользователи
    # ------------------------------------------------------------------ #

    def input_peer_self(self):
        desc = self.schema.by_name("inputPeerSelf")
        return {"_id": desc["id"]} if desc else None

    def input_peer_user(self, user_id: int, access_hash: int):
        desc = self.schema.by_name("inputPeerUser")
        if desc is None:
            return None
        return {"_id": desc["id"], "user_id": user_id, "access_hash": access_hash}

    def input_peer_chat(self, chat_id: int):
        desc = self.schema.by_name("inputPeerChat")
        if desc is None:
            return None
        return {"_id": desc["id"], "chat_id": chat_id}

    def input_peer_channel(self, channel_id: int, access_hash: int):
        desc = self.schema.by_name("inputPeerChannel")
        if desc is None:
            return None
        return {"_id": desc["id"], "channel_id": channel_id, "access_hash": access_hash}

    def input_user(self, user_id: int, access_hash: int):
        desc = self.schema.by_name("inputUser")
        if desc is None:
            return None
        return {"_id": desc["id"], "user_id": user_id, "access_hash": access_hash}

    def input_user_self(self):
        desc = self.schema.by_name("inputUserSelf")
        return {"_id": desc["id"]} if desc else None

    async def get_me(self):
        """Возвращает текущего юзера. На приват-сервере users.getUsers может
        отсутствовать — тогда берём user, сохранённый при auth.signIn/checkPassword."""
        if self.schema.by_name("users.getUsers") is not None:
            _, obj = await self.conn.rpc("users.getUsers", {
                "id": [self.input_user_self()],
            })
            # ответ может быть Vector<User> напрямую или обёрнут в объект
            if isinstance(obj, list):
                users = obj
            else:
                users = obj.get("users") or obj if isinstance(obj, list) else []
            if not users:
                # если users.getUsers вернул пустоту, используем кешированного юзера
                user = self.conn.session.user
                if user is None:
                    raise RPCError(0, "users.getUsers returned no users and no cached user")
                self.conn.session.user_id = user.get("id")
                return user
            user = users[0]
            self.conn.session.user = user
            self.conn.session.user_id = user.get("id")
            return user
        user = self.conn.session.user
        if user is None:
            raise RPCError(0, "users.getUsers not in schema (layer %d) and no cached user"
                              % self.conn._schema.layer)
        self.conn.session.user_id = user.get("id")
        return user

    async def get_users(self, ids):
        """users.getUsers([InputUser...])."""
        return await self.conn.rpc("users.getUsers", {"id": ids})

    async def resolve_username(self, username: str):
        """contacts.resolveUsername - ищет пользователя по @юзернейму.

        Returns:
            contacts.ResolvedPeer с полями peer, users, chats
        """
        return await self.conn.rpc("contacts.resolveUsername", {
            "username": (username or "").strip().lstrip("@"),
        })

    # ------------------------------------------------------------------ #
    #  отправка / история
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    #  ответы на сообщения (разные эры схемы)
    # ------------------------------------------------------------------ #
    def reply_params(self, method: str, reply_to):
        """Параметры ответа на сообщение для метода - с учётом эры слоя.

        Старые слои ждут int в reply_to_msg_id, новые - объект
        inputReplyToMessage. Возвращает то, что нужно добавить в params.
        """
        if not reply_to:
            return {}
        if not isinstance(reply_to, int):
            return {"reply_to": reply_to}

        out = {}
        names = self._param_names(method)
        if "reply_to_msg_id" in names:
            out["reply_to_msg_id"] = reply_to
        if "reply_to" in names:
            reply_desc = self.schema.by_name("inputReplyToMessage")
            if reply_desc is None:
                out["reply_to_msg_id"] = reply_to
            else:
                out["reply_to"] = {"_id": reply_desc["id"], "reply_to_msg_id": reply_to}
        return out

    async def send_message(self, peer, text: str, random_id=None, reply_to=None, reply_markup=None):
        """messages.sendMessage(peer, text, random_id, reply_to, reply_markup)."""
        params = {
            "peer": peer,
            "message": text,
            "random_id": random_id if random_id is not None else int(
                int.from_bytes(os.urandom(8), "little", signed=True)
            ),
        }
        # разные эры: reply_to_msg_id (int) или reply_to (InputReplyTo)
        params.update(self.reply_params("messages.sendMessage", reply_to))
        if reply_markup is not None:
            params["reply_markup"] = reply_markup
        return await self.conn.rpc("messages.sendMessage", params)

    async def edit_message(self, peer, msg_id: int, text: str):
        """messages.editMessage - редактирует существующее сообщение."""
        params = {
            "peer": peer,
            "id": msg_id,
            "message": text,
        }
        return await self.conn.rpc("messages.editMessage", params)

    async def delete_messages(self, peer, msg_ids, revoke=True):
        """messages.deleteMessages - удаляет сообщения.

        Args:
            peer: InputPeer чата (или None для личных сообщений)
            msg_ids: список ID сообщений для удаления
            revoke: True - удалить для всех, False - только для себя
        """
        if not isinstance(msg_ids, list):
            msg_ids = [msg_ids]

        # Проверяем, канал это или обычный чат
        peer_dict = peer if isinstance(peer, dict) else {}
        peer_name = peer_dict.get("_name", "")

        if "channel" in peer_name.lower():
            # Для каналов используем messages.deleteChannelMessages
            return await self.conn.rpc("messages.deleteMessages", {
                "channel": peer,
                "id": msg_ids,
            })
        else:
            # Для обычных чатов/личек используем messages.deleteMessages
            return await self.conn.rpc("messages.deleteMessages", {
                "id": msg_ids,
                "revoke": revoke,
            })

    async def delete_message(self, peer, msg_id, revoke=True):
        """Удаляет одно сообщение.

        Args:
            peer: InputPeer чата
            msg_id: ID сообщения
            revoke: True - удалить для всех, False - только для себя
        """
        return await self.delete_messages(peer, [msg_id], revoke)

    async def get_history(self, peer, limit=50):
        """messages.getHistory."""
        return await self.conn.rpc("messages.getHistory", {
            "peer": peer,
            "offset_id": 0,
            "offset_date": 0,
            "add_offset": 0,
            "limit": int(limit),
            "max_id": 0,
            "min_id": 0,
            "hash": 0,
        })

    # ------------------------------------------------------------------ #
    #  состояние / различие
    # ------------------------------------------------------------------ #

    async def get_state(self):
        return await self.conn.rpc("updates.getState", {})

    async def get_difference(self, pts, date=0, qts=0, pts_total_limit=None):
        params = {
            "pts": int(pts),
            "pts_total_limit": pts_total_limit,
            "date": int(date),
            "qts": int(qts),
        }
        if "pts_total_limit" not in self._param_names("updates.getDifference"):
            params.pop("pts_total_limit", None)
        return await self.conn.rpc("updates.getDifference", params)

    # ------------------------------------------------------------------ #
    #  пересылка сообщений
    # ------------------------------------------------------------------ #

    async def forward_messages(self, from_peer, to_peer, msg_ids, drop_author=False, silent=False):
        """messages.forwardMessages - пересылает сообщения из одного чата в другой.

        Args:
            from_peer: InputPeer источника
            to_peer: InputPeer назначения
            msg_ids: список ID сообщений для пересылки
            drop_author: скрыть автора оригинального сообщения
            silent: отправить без звука
        """
        if not isinstance(msg_ids, list):
            msg_ids = [msg_ids]

        params = {
            "from_peer": from_peer,
            "to_peer": to_peer,
            "id": msg_ids,
            "random_id": [int.from_bytes(os.urandom(8), "little", signed=True) for _ in msg_ids],
        }

        if "drop_author" in self._param_names("messages.forwardMessages"):
            params["drop_author"] = drop_author
        if "silent" in self._param_names("messages.forwardMessages"):
            params["silent"] = silent

        return await self.conn.rpc("messages.forwardMessages", params)

    # ------------------------------------------------------------------ #
    #  диалоги
    # ------------------------------------------------------------------ #

    async def get_dialogs(self, limit=100, offset_date=0, offset_id=0, offset_peer=None):
        """messages.getDialogs - получает список диалогов.

        Args:
            limit: количество диалогов
            offset_date: дата для пагинации
            offset_id: ID для пагинации
            offset_peer: peer для пагинации
        """
        if offset_peer is None:
            offset_peer = self.input_peer_self()

        params = {
            "offset_date": int(offset_date),
            "offset_id": int(offset_id),
            "offset_peer": offset_peer,
            "limit": int(limit),
            "hash": 0,
        }

        return await self.conn.rpc("messages.getDialogs", params)

    # ------------------------------------------------------------------ #
    #  информация о пользователях/чатах
    # ------------------------------------------------------------------ #

    async def get_full_user(self, user_id):
        """users.getFullUser - получает полную информацию о пользователе."""
        params = {"id": user_id}
        return await self.conn.rpc("users.getFullUser", params)

    async def get_full_chat(self, chat_id):
        """messages.getFullChat - получает полную информацию о чате."""
        params = {"chat_id": int(chat_id)}
        return await self.conn.rpc("messages.getFullChat", params)

    async def get_full_channel(self, channel):
        """channels.getFullChannel - получает полную информацию о канале."""
        params = {"channel": channel}
        return await self.conn.rpc("channels.getFullChannel", params)

    # ------------------------------------------------------------------ #
    #  управление профилем
    # ------------------------------------------------------------------ #

    async def update_profile(self, first_name=None, last_name=None, about=None):
        """account.updateProfile - обновляет информацию профиля."""
        params = {}
        if first_name is not None:
            params["first_name"] = first_name
        if last_name is not None:
            params["last_name"] = last_name
        if about is not None:
            params["about"] = about

        return await self.conn.rpc("account.updateProfile", params)

    async def update_status(self, offline=False):
        """account.updateStatus - обновляет онлайн-статус."""
        params = {"offline": offline}
        return await self.conn.rpc("account.updateStatus", params)

    # ------------------------------------------------------------------ #
    #  профиль: юзернеймы, аватар, приватность, сессии
    # ------------------------------------------------------------------ #

    _PRIVACY_KEYS = {
        "status_timestamp": "inputPrivacyKeyStatusTimestamp",
        "last_seen": "inputPrivacyKeyStatusTimestamp",
        "phone_call": "inputPrivacyKeyPhoneCall",
        "phone_p2p": "inputPrivacyKeyPhoneP2P",
        "chat_invite": "inputPrivacyKeyChatInvite",
        "phone_number": "inputPrivacyKeyPhoneNumber",
        "profile_photo": "inputPrivacyKeyProfilePhoto",
        "forwards": "inputPrivacyKeyForwards",
        "about": "inputPrivacyKeyAbout",
        "voice_messages": "inputPrivacyKeyVoiceMessages",
    }

    _PRIVACY_VALUES = {
        "all": "inputPrivacyValueAllowAll",
        "everyone": "inputPrivacyValueAllowAll",
        "contacts": "inputPrivacyValueAllowContacts",
        "close_friends": "inputPrivacyValueAllowCloseFriends",
        "bots": "inputPrivacyValueAllowBots",
        "premium": "inputPrivacyValueAllowPremium",
        "nobody": "inputPrivacyValueAllowUsers",
        "chats": "inputPrivacyValueAllowChatParticipants",
    }

    def _construct(self, ctor, **fields):
        """Собирает конструктор текущей эры по имени; fields — его поля."""
        desc = self.schema.by_name(ctor)
        if desc is None:
            raise RPCError(0, "%s not available on layer %d" % (ctor, self.schema.layer))
        obj = {"_id": desc["id"]}
        obj.update(fields)
        return obj

    # -------------------------------------------------------------- #
    #  юзернеймы
    # -------------------------------------------------------------- #

    async def check_username(self, username: str):
        """account.checkUsername - свободен ли юзернейм (True/False)."""
        return await self.conn.rpc("account.checkUsername", {"username": username})

    async def update_username(self, username: str):
        """account.updateUsername - ставит основной юзернейм.

        Пустая строка снимает текущий юзернейм.
        """
        return await self.conn.rpc("account.updateUsername", {"username": username})

    async def toggle_username(self, username: str, active=True):
        """account.toggleUsername - вкл/выкл дополнительный юзернейм."""
        return await self.conn.rpc("account.toggleUsername", {
            "username": username,
            "active": bool(active),
        })

    async def reorder_usernames(self, order):
        """account.reorderUsernames - первый в списке становится основным."""
        return await self.conn.rpc("account.reorderUsernames", {"order": list(order)})

    # -------------------------------------------------------------- #
    #  аватар
    # -------------------------------------------------------------- #

    async def upload_file(self, data: bytes, file_name="file", part_size=524288):
        """Заливает байты по кускам через upload.saveFilePart.

        Returns:
            inputFile текущей эры - готов к передаче в photos.* / messages.sendMedia.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("upload_file expects bytes, got %r" % type(data).__name__)
        chunks = [bytes(data[i:i + part_size]) for i in range(0, len(data), part_size)] or [b""]
        file_id = int.from_bytes(os.urandom(8), "little", signed=True)
        for idx, chunk in enumerate(chunks):
            await self.conn.rpc("upload.saveFilePart", {
                "file_id": file_id,
                "file_part": idx,
                "bytes": chunk,
            })
        return self._construct(
            "inputFile", id=file_id, parts=len(chunks), name=file_name, md5_checksum="",
        )

    async def upload_profile_photo(self, data: bytes, file_name="avatar.jpg", fallback=None):
        """photos.uploadProfilePhoto - ставит фото основной аватаркой.

        Args:
            data: байты изображения
            file_name: имя файла (для сервера)
            fallback: True - запасная аватарка (если сервер/слой поддерживает)
        """
        input_file = await self.upload_file(data, file_name=file_name)
        params = {"file": input_file}
        if fallback is not None:
            params["fallback"] = bool(fallback)
        return await self.conn.rpc("photos.uploadProfilePhoto", params)

    async def delete_profile_photo(self, photo_id):
        """photos.deletePhotos - удаляет аватарки по id (списком или по одному)."""
        ids = photo_id if isinstance(photo_id, (list, tuple)) else [photo_id]
        payload = [self._construct("inputPhoto", id=int(i)) for i in ids]
        return await self.conn.rpc("photos.deletePhotos", {"id": payload})

    async def get_profile_photos(self, user_id=None, offset=0, max_id=0, limit=20):
        """photos.getUserPhotos - аватарки пользователя (свои, если user_id не задан)."""
        return await self.conn.rpc("photos.getUserPhotos", {
            "user_id": user_id if user_id is not None else self.input_user_self(),
            "offset": int(offset),
            "max_id": int(max_id),
            "limit": int(limit),
        })

    # -------------------------------------------------------------- #
    #  приватность
    # -------------------------------------------------------------- #

    def privacy_key(self, key):
        """Имя ключа ('last_seen', 'phone_number', ...) -> InputPrivacyKey."""
        if isinstance(key, dict):
            return key
        name = self._PRIVACY_KEYS.get(str(key).lower())
        if name is None:
            raise ValueError("unknown privacy key %r; known: %s"
                             % (key, ", ".join(sorted(self._PRIVACY_KEYS))))
        return self._construct(name)

    def privacy_rule(self, rule, chats=None):
        """Имя правила ('all', 'contacts', 'nobody', ...) -> InputPrivacyRule.

        Для 'chats' передай chats=[InputChat,...].
        """
        if isinstance(rule, dict):
            return rule
        name = self._PRIVACY_VALUES.get(str(rule).lower())
        if name is None:
            raise ValueError("unknown privacy rule %r; known: %s"
                             % (rule, ", ".join(sorted(self._PRIVACY_VALUES))))
        if name == "inputPrivacyValueAllowChatParticipants":
            return self._construct(name, chats=list(chats or []))
        return self._construct(name)

    async def get_privacy(self, key):
        """account.getPrivacy - текущие правила приватности."""
        return await self.conn.rpc("account.getPrivacy", {"key": self.privacy_key(key)})

    async def set_privacy(self, key, rules):
        """account.setPrivacy - правила приватности.

        Args:
            key: ключ ('last_seen', 'profile_photo', ...)
            rules: список правил: ['nobody'], ['contacts'], ['chats'] и т.п.
                   Для конкретных чатов - пара ('chats', [InputChat, ...])
        """
        built = []
        for rule in rules:
            if isinstance(rule, (list, tuple)):
                if not rule:
                    raise ValueError("empty privacy rule")
                built.append(self.privacy_rule(rule[0], chats=rule[1] if len(rule) > 1 else None))
            else:
                built.append(self.privacy_rule(rule))
        return await self.conn.rpc("account.setPrivacy", {
            "key": self.privacy_key(key),
            "rules": built,
        })

    # -------------------------------------------------------------- #
    #  оформление профиля
    # -------------------------------------------------------------- #

    async def update_birthday(self, day, month, year=None):
        """account.updateBirthday - день рождения (layer >= latest only)."""
        return await self.conn.rpc("account.updateBirthday", {
            "birthday": self._construct("birthday", day=int(day), month=int(month), year=int(year or 0)),
        })

    async def update_profile_color(self, color=None, for_profile=True):
        """account.updateColor - цвет профиля/градиент аватарки."""
        return await self.conn.rpc("account.updateColor", {
            "for_profile": bool(for_profile),
            "color": self._construct("peerColor", color=int(color) if color is not None else 0),
        })

    async def set_emoji_status(self, emoji=None):
        """account.updateEmojiStatus - эмодзи-статус.

        emoji=None очищает статус. Установка конкретного эмодзи требует
        конструктор emojiStatusEmoji, которого нет в собранных схемах.
        """
        if emoji is None:
            return await self.conn.rpc("account.updateEmojiStatus", {
                "emoji_status": self._construct("emojiStatusEmpty"),
            })
        desc = self.schema.by_name("emojiStatusEmoji")
        if desc is None:
            raise RPCError(0, "emojiStatusEmoji not available on layer %d; "
                              "only clearing is possible" % self.schema.layer)
        document_id = getattr(emoji, "document_id", None)
        return await self.conn.rpc("account.updateEmojiStatus", {
            "emoji_status": self._construct(
                desc["name"], document_id=int(document_id or emoji), until=None,
            ),
        })

    async def get_recent_emoji_statuses(self, hash=0):
        """account.getRecentEmojiStatuses - недавние эмодзи-статусы."""
        return await self.conn.rpc("account.getRecentEmojiStatuses", {"hash": int(hash)})

    # -------------------------------------------------------------- #
    #  сессии и прочее
    # -------------------------------------------------------------- #

    async def get_authorizations(self):
        """account.getAuthorizations - список активных сессий аккаунта."""
        return await self.conn.rpc("account.getAuthorizations", {})

    async def reset_authorization(self, auth_hash):
        """account.resetAuthorization - завершает чужую сессию по hash."""
        return await self.conn.rpc("account.resetAuthorization", {"hash": int(auth_hash)})

    async def get_account_ttl(self):
        """account.getAccountTTL - настройка автоудаления аккаунта."""
        return await self.conn.rpc("account.getAccountTTL", {})

    async def set_account_ttl(self, days=0):
        """account.setAccountTTL - автоудаление через N дней (0 — выключить)."""
        return await self.conn.rpc("account.setAccountTTL", {
            "ttl": self._construct("accountDaysTTL", days=int(days)),
        })

    # ------------------------------------------------------------------ #
    #  управление чатами
    # ------------------------------------------------------------------ #

    async def join_channel(self, channel):
        """channels.joinChannel - присоединяется к каналу."""
        params = {"channel": channel}
        return await self.conn.rpc("channels.joinChannel", params)

    async def leave_channel(self, channel):
        """channels.leaveChannel - покидает канал."""
        params = {"channel": channel}
        return await self.conn.rpc("channels.leaveChannel", params)

    async def get_participants(self, channel, limit=100, offset=0):
        """channels.getParticipants - получает участников канала."""
        # Создаем фильтр "все участники"
        filter_desc = self.schema.by_name("channelParticipantsRecent")
        if filter_desc is None:
            filter_desc = self.schema.by_name("channelParticipantsSearch")

        params = {
            "channel": channel,
            "filter": {"_id": filter_desc["id"] if filter_desc else 0},
            "offset": int(offset),
            "limit": int(limit),
            "hash": 0,
        }

        return await self.conn.rpc("channels.getParticipants", params)

    # ------------------------------------------------------------------ #
    #  чтение сообщений
    # ------------------------------------------------------------------ #

    async def mark_read(self, peer, max_id=0):
        """messages.readHistory - отмечает сообщения как прочитанные.

        Args:
            peer: InputPeer чата
            max_id: ID последнего прочитанного сообщения (0 = все)
        """
        peer_dict = peer if isinstance(peer, dict) else {}
        peer_name = peer_dict.get("_name", "")

        if "channel" in peer_name.lower():
            # Для каналов
            return await self.conn.rpc("channels.readHistory", {
                "channel": peer,
                "max_id": int(max_id),
            })
        else:
            # Для обычных чатов
            return await self.conn.rpc("messages.readHistory", {
                "peer": peer,
                "max_id": int(max_id),
            })

    # ------------------------------------------------------------------ #
    #  inline кнопки (deprecated - не поддерживается для userbot)
    # ------------------------------------------------------------------ #

    def build_inline_buttons(self, buttons):
        """Создаёт inline keyboard markup из списка кнопок.

        Args:
            buttons: список рядов кнопок, например:
            [
                [{"text": "Кнопка 1", "callback_data": b"data1"}],
                [{"text": "URL", "url": "https://example.com"}],
                [{"text": "Switch", "switch_inline_query": "query"}]
            ]

        Поддерживаемые типы кнопок:
        - callback_data: кнопка с callback (bytes)
        - url: кнопка со ссылкой (str)
        - switch_inline_query: переключение на inline режим (str)
        - switch_inline_query_current_chat: inline в текущем чате (str)
        """
        markup_desc = self.schema.by_name("replyInlineMarkup")
        if markup_desc is None:
            raise RPCError(0, "replyInlineMarkup not available in schema")

        row_desc = self.schema.by_name("keyboardButtonRow")
        callback_desc = self.schema.by_name("keyboardButtonCallback")
        url_desc = self.schema.by_name("keyboardButtonUrl")
        switch_inline_desc = self.schema.by_name("keyboardButtonSwitchInline")

        rows = []
        for row in buttons:
            buttons_row = []
            for btn in row:
                text = btn.get("text", "")

                if "callback_data" in btn:
                    # Inline кнопка с callback
                    if callback_desc:
                        data = btn["callback_data"]
                        if isinstance(data, str):
                            data = data.encode('utf-8')
                        buttons_row.append({
                            "_": callback_desc["name"],
                            "text": text,
                            "data": data
                        })
                elif "url" in btn:
                    # Кнопка со ссылкой
                    if url_desc:
                        buttons_row.append({
                            "_": url_desc["name"],
                            "text": text,
                            "url": btn["url"]
                        })
                elif "switch_inline_query" in btn:
                    # Переключение на inline режим
                    if switch_inline_desc:
                        buttons_row.append({
                            "_": switch_inline_desc["name"],
                            "text": text,
                            "query": btn["switch_inline_query"],
                            "same_peer": False
                        })
                elif "switch_inline_query_current_chat" in btn:
                    # Inline в текущем чате
                    if switch_inline_desc:
                        buttons_row.append({
                            "_": switch_inline_desc["name"],
                            "text": text,
                            "query": btn["switch_inline_query_current_chat"],
                            "same_peer": True
                        })

            if buttons_row:
                if row_desc:
                    rows.append({
                        "_": row_desc["name"],
                        "buttons": buttons_row
                    })

        return {
            "_": markup_desc["name"],
            "rows": rows
        }

    async def answer_callback_query(self, query_id, text=None, alert=False, url=None):
        """Отвечает на нажатие inline кнопки (messages.setBotCallbackAnswer).

        Args:
            query_id: ID callback query из события
            text: текст уведомления (опционально)
            alert: True - показать как alert, False - как toast
            url: URL для открытия (опционально)
        """
        params = {
            "query_id": query_id,
            "alert": alert
        }
        if text is not None:
            params["message"] = text
        if url is not None:
            params["url"] = url

        return await self.conn.rpc("messages.setBotCallbackAnswer", params)

    # ------------------------------------------------------------------ #
    #  подарки (star gifts)
    # ------------------------------------------------------------------ #

    async def get_star_gifts(self, hash=0):
        """payments.getStarGifts - получает список доступных подарков.

        Args:
            hash: хэш для проверки изменений (0 = получить все)

        Returns:
            Объект payments.StarGifts с полями: gifts, chats, users
        """
        params = {"hash": int(hash)}
        return await self.conn.rpc("payments.getStarGifts", params)

    async def send_star_gift(self, peer, gift_id, message=None, hide_name=False):
        """Отправляет StarGift пользователю.

        Args:
            peer: InputPeer получателя подарка
            gift_id: ID подарка (из списка payments.getStarGifts)
            message: текст сообщения к подарку (опционально)
            hide_name: скрыть имя отправителя

        Returns:
            Результат отправки подарка
        """
        # Создаем InputInvoice для подарка
        invoice_params = {
            "_": "inputInvoiceStarGift",
            "peer": peer,
            "gift_id": int(gift_id),
            "flags": 0
        }

        if hide_name:
            invoice_params["flags"] |= 1  # flags.0

        if message:
            invoice_params["flags"] |= 2  # flags.1
            # Создаем TextWithEntities
            invoice_params["message"] = {
                "_": "textWithEntities",
                "text": message,
                "entities": []
            }

        # Получаем форму оплаты
        _, payment_form = await self.conn.rpc("payments.getPaymentForm", {
            "invoice": invoice_params
        })

        form_id = payment_form.get("form_id")
        if form_id is None:
            raise RPCError(0, "payment form has no form_id")

        # Отправляем подарок
        return await self.conn.rpc("payments.sendStarsForm", {
            "form_id": form_id,
            "invoice": invoice_params
        })

    async def get_saved_star_gifts(self, peer, offset="", limit=100, exclude_unsaved=False):
        """payments.getSavedStarGifts - получает сохраненные подарки.

        Args:
            peer: InputPeer пользователя
            offset: смещение для пагинации
            limit: количество подарков
            exclude_unsaved: исключить несохраненные

        Returns:
            Объект payments.SavedStarGifts
        """
        params = {
            "peer": peer,
            "offset": str(offset),
            "limit": int(limit),
            "flags": 0
        }

        if exclude_unsaved:
            params["flags"] |= 1  # flags.0

        return await self.conn.rpc("payments.getSavedStarGifts", params)

    async def convert_star_gift(self, msg_id):
        """payments.convertStarGift - конвертирует подарок в звезды.

        Args:
            msg_id: ID сообщения с подарком

        Returns:
            Результат конвертации
        """
        # Создаем InputSavedStarGift
        stargift = {
            "_": "inputSavedStarGiftUser",
            "msg_id": int(msg_id)
        }

        return await self.conn.rpc("payments.convertStarGift", {
            "stargift": stargift
        })

    async def transfer_star_gift(self, msg_id, to_peer):
        """Переводит уникальный подарок другому пользователю.

        Args:
            msg_id: ID сообщения с подарком
            to_peer: InputPeer получателя

        Returns:
            Результат перевода
        """
        # Создаем InputSavedStarGift
        stargift = {
            "_": "inputSavedStarGiftUser",
            "msg_id": int(msg_id)
        }

        return await self.conn.rpc("payments.transferStarGift", {
            "stargift": stargift,
            "to_id": to_peer
        })

    async def check_can_send_gift(self, gift_id):
        """payments.checkCanSendGift - проверяет возможность отправки подарка.

        Args:
            gift_id: ID подарка

        Returns:
            payments.CheckCanSendGiftResult (Ok или Fail с причиной)
        """
        return await self.conn.rpc("payments.checkCanSendGift", {
            "gift_id": int(gift_id)
        })

    # ------------------------------------------------------------------ #
    def _param_names(self, method_name):
        desc = self.schema.by_name(method_name)
        if desc is None:
            return []
        return [p[0] for p in desc["params"]]

    def _store_auth(self, result):
        _, obj = result
        user = obj.get("user") if hasattr(obj, "get") else (obj or {}).get("user")
        if user:
            self.conn.session.user_id = user.get("id")
            self.conn.session.user = user