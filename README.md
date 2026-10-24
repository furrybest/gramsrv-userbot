# gramsrv-userbot

**Асинхронный MTProto-юзербот для приватных серверов Telegram** — с нуля, без зависимостей от Telethon/Pyrogram.

Библиотека написана для **приватных MTProto-серверов** (не для официального Telegram), но полностью совместима со стандартом MTProto 2.0 и поддерживает слои от **167 до 228**.

---

## Возможности

### MTProto-ядро

- Полная реализация **MTProto 2.0** с нуля: `req_pq_multi` → `resPQ` → `req_DH_params` → `set_client_DH_params`, вычисление `auth_key`, `msg_key`, AES-IGE, корректный padding.
- Поддержка **RSA_PAD** в двух форматах: актуальном (`temp_key` + AES-IGE + SHA256) и легаси (`SHA1(data)` + padding).
- **SRP-авторизация 2FA** (`passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`).
- Автоматическая обработка `bad_server_salt`, `bad_msg_notification`, `new_session_created`, `msg_container`, `gzip_packed`.

### Транспорты

- `abridged`, `intermediate`, `padded`, `full` — с CRC32 для full.
- **Автодетект**: если указанный транспорт не поднимается — клиент перебирает остальные.

### Схемы слоёв

- Поддерживаются слои **167 – 228** (v113, v119, v128, v133, latest).
- Схемы лежат в JSON (`userbot/tl/schemas/data/`), ничего не захардкожено под конкретную версию сервера.
- Слой определяется автоматически по `help.getConfig` при подключении.

### Сессия

- Хранится в **SQLite** (`session.db`), пишется атомарно.
- **Автобэкап** (`.db.bak`) только на валидное состояние.
- При повреждении файла — **автовосстановление из бэкапа** или пересоздание.
- Валидация `auth_key` при загрузке.

### API

Высокоуровневые методы (`client.*`):

- **Сообщения**: `send_message`, `send_photo`, `send_document`, `edit_message`, `delete_message(s)`, `forward_message(s)`, `copy_message`, `get_messages`, `get_history`, `pin_message`, `unpin_message`.
- **Диалоги**: `get_dialogs`, `iter_dialogs`.
- **Чаты**: `join_chat`, `leave_chat`, `get_participants`, `get_full_chat`, `edit_chat_title`, `edit_chat_about`, `mark_read`.
- **Профиль**: `set_username`, `remove_username`, `set_avatar`, `remove_avatar`, `get_avatars`, `get_profile`, `update_profile`, `update_status`, `set_birthday`, `set_profile_color`, `set_emoji_status`.
- **Приватность**: `set_privacy`, `get_privacy`.
- **Сессии аккаунта**: `get_sessions`, `terminate_session`, `get_account_ttl`, `set_account_ttl`.
- **Контакты**: `add_contact`, `resolve_username`.
- **Подарки (Star Gifts)**: `get_available_gifts`, `send_gift`, `get_my_gifts`, `convert_gift_to_stars`, `transfer_gift`.

Произвольный вызов: `await client.call("method.name", {...})`.

### Хендлеры апдейтов

- `@client.on(NewMessage)`, `@client.on(MessageEdited)`, `@client.on(MessageDeleted)`.
- Работает на любом слое: поля апдейта достаются из разобранного TL-дерева.
- Хендлеры изолированы: исключение в одном не роняет остальные.

### Зависимости

- **Обязательно**: `pycryptodome` (AES, RSA).
- **Опционально**: `aiohttp` — только если пользуешься `send_photo` / `send_document` с http(s)-ссылкой.
- Всё остальное — стандартная библиотека Python.

Требуется **Python 3.9+**.

---

## Установка

1. Клонируй репо:

    ```bash
    git clone https://github.com/furrybest/gramsrv-userbot
    cd gramsrv-userbot
    ```

2. Установи зависимости:

    ```bash
    pip install -r requirements.txt
    ```

3. Скопируй шаблон и впиши свои данные:

    ```bash
    cp bot.example.py bot.py
    nano bot.py
    ```

    Заполни:
    - `server_ip` — IP твоей приватки
    - `server_port` — порт (обычно `2398`)
    - `dc_id` — DC id (обычно `2`)
    - `rsa_keys_pem` — публичный RSA-ключ сервера (PEM целиком, `-----BEGIN RSA PUBLIC KEY-----` … `-----END RSA PUBLIC KEY-----`)

4. Запусти:

    ```bash
    python bot.py
    ```

При первом запуске библиотека:
- определит слой сервера через `help.getConfig`,
- сделает DH-handshake и сохранит `auth_key` в `session.db`,
- спросит номер телефона и код (2FA — если включён).

При следующих запусках ввод не потребуется — всё берётся из `session.db`.

---

## Пример `bot.py`

```python
import asyncio
from userbot import WinterGramClient, NewMessage

client = WinterGramClient(
    server_ip="127.0.0.1",
    server_port=2398,
    dc_id=2,
    rsa_keys_pem="""-----BEGIN RSA PUBLIC KEY-----
ВСТАВЬ СЮДА СВОЙ КЛЮЧ
-----END RSA PUBLIC KEY-----""",
    session_path="session.db",
)


@client.on(NewMessage)
async def on_msg(event: NewMessage):
    if event.text.lower() == "!ping":
        await client.send_message(event.chat_id, "pong")


async def main():
    await client.start()
    await client.send_message("me", "на связи")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Структура

```
gramsrv-userbot/
├── bot.example.py        # шаблон твоего скрипта
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── userbot/
    ├── client.py         # WinterGramClient
    ├── errors.py
    ├── api/
    ├── crypto/
    ├── network/
    ├── session/
    └── tl/
        └── schemas/data/ # JSON-схемы слоёв 167–228
```

---

## FAQ

**Почему свой клиент, а не Telethon/Pyrogram?**
Официальные библиотеки не работают с приватными серверами: другой набор RSA-ключей, отличающийся набор конструкторов, иногда кастомный handshake. Здесь всё можно поправить.

**Как обновить схему под новый слой?**
Положи JSON-файл в `userbot/tl/schemas/data/` и добавь якорь в `LAYER_ANCHORS` в `userbot/tl/schema_resolver.py`.

**`AUTH_KEY_UNREGISTERED`?**
Удали `session.db` и `session.db.bak` — будет новый handshake и повторный вход.

**Падает на handshake?**
Чаще всего: неверный `dc_id`, сервер не поддерживает `p_q_inner_data_dc` (ждёт `p_q_inner_data`), или не тот RSA-ключ. В логах `handshake: resPQ ok ... fps=[...]` — сверь отпечатки.

---

## Лицензия

MIT.

---

## Дисклеймер

Проект предназначен **только для приватных MTProto-серверов**, которые ты администрируешь или к которым имеешь легальный доступ. Автор не несёт ответственности за использование против официальных серверов Telegram или чужих аккаунтов.
