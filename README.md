# gramsrv-userbot

**Асинхронный MTProto-юзербот для приватных серверов Telegram** — с нуля, без зависимостей от Telethon/Pyrogram.

Библиотека написана для **приватных MTProto-серверов** (не для официального Telegram), но полностью совместима со стандартом MTProto 2.0 и поддерживает слои от **167 до 228**.

---

## Возможности

### MTProto-ядро

- Полная реализация **MTProto 2.0** с нуля: `req_pq_multi` → `resPQ` → `req_DH_params` → `set_client_DH_params`, вычисление `auth_key`, `msg_key`, AES-IGE, корректный padding.
- Поддержка **RSA_PAD** в двух форматах: актуальном (`temp_key` + AES-IGE + SHA256) и легаси (`SHA1(data)` + padding) — на случай, если приватка на старом handshake.
- **SRP-авторизация 2FA** (`passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`).
- Автоматическая обработка `bad_server_salt`, `bad_msg_notification`, `new_session_created`, `msg_container`, `gzip_packed`.

### Транспорты

- `abridged`, `intermediate`, `padded` (padded intermediate), `full` — с CRC32 для full.
- **Автодетект**: если указанный транспорт не поднимается — клиент перебирает остальные (`connect_with_autodetect`).

### Схемы слоёв

- Поддерживаются слои **167 – 228** (v113, v119, v128, v133, latest).
- Схемы лежат в JSON (`tl/schemas/data/`), ID конструкторов и поля берутся из них — **ничего не захардкожено под конкретную версию сервера**.
- Слой определяется автоматически по `help.getConfig` при подключении; один и тот же вызов `send_message` / `get_history` работает на любой эре.
- Если сервер вернул конструктор, которого нет в текущей схеме — клиент либо падает предсказуемо с `RPCError(unknown constructor ...)`, либо (если конструктор в другой эре) пробует распарсить ответ по ней.

### Сессия

- Хранится в **SQLite** (`session.db`), пишется атомарно одной операцией — таблица `sessions` не остаётся полупустой при обрыве.
- **Автобэкап** (`.db.bak`) только на «заведомо рабочее» состояние (`auth_key` есть и он валиден 256 байт).
- При повреждении файла — **автовосстановление из бэкапа**, при отсутствии бэкапа — пересоздание файла и новый handshake.
- Валидация `auth_key` при загрузке: если сохранённый ключ побит, он игнорируется и запрашивается повторная авторизация.

### API

Высокоуровневые методы (`client.*`):

- **Сообщения**: `send_message`, `send_photo`, `send_document`, `edit_message`, `delete_message(s)`, `forward_message(s)`, `copy_message`, `get_messages`, `get_history`, `pin_message`, `unpin_message`.
- **Диалоги**: `get_dialogs`, `iter_dialogs`.
- **Чаты**: `join_chat`, `leave_chat`, `get_participants`, `get_full_chat`, `edit_chat_title`, `edit_chat_about`, `mark_read`.
- **Профиль**: `set_username`, `remove_username`, `set_avatar`, `remove_avatar`, `get_avatars`, `get_profile`, `update_profile`, `update_status`, `set_birthday`, `set_profile_color`, `set_emoji_status`.
- **Приватность**: `set_privacy`, `get_privacy` (`last_seen`, `profile_photo`, `forwards`, `phone_number`, `about` и др.).
- **Сессии аккаунта**: `get_sessions`, `terminate_session`, `get_account_ttl`, `set_account_ttl`.
- **Контакты**: `add_contact`, `resolve_username`.
- **Подарки (Star Gifts)**: `get_available_gifts`, `send_gift`, `get_my_gifts`, `convert_gift_to_stars`, `transfer_gift`.

Произвольный вызов: `await client.call("method.name", {...})`.

### Хендлеры апдейтов

- `@client.on(NewMessage)`, `@client.on(MessageEdited)`, `@client.on(MessageDeleted)`.
- Работает на любом слое: поля апдейта достаются из разобранного TL-дерева, а не из фиксированных полей класса.
- Хендлеры изолированы: исключение в одном не роняет остальные.

### Зависимости

- **Обязательно**: `pycryptodome` (AES, RSA).
- **Опционально**: `aiohttp` — только если пользуешься `send_photo` / `send_document` с **http(s)-ссылкой** (для загрузки файла).
- Всё остальное — стандартная библиотека Python.

Требуется **Python 3.9+**.

## Установка

```bash
git clone https://github.com/<твой-ник>/gramsrv-userbot
cd gramsrv-userbot
pip install pycryptodome aiohttp
