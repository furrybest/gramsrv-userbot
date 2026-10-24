# gramsrv-userbot

**Асинхронный MTProto-юзербот для приватных серверов Telegram** — с нуля, без зависимостей от Telethon/Pyrogram.

Библиотека написана для **приватных MTProto-серверов** (не для официального Telegram), но полностью совместима со стандартом MTProto 2.0 и поддерживает слои от **167 до 228**.

---

## Возможности

- 📡 **Свой MTProto-клиент**: handshake, DH, AES-IGE, auth_key, msg_key — всё написано вручную.
- 🌐 **4 транспорта**: `abridged`, `intermediate`, `padded`, `full` (с автодетектом).
- 🧩 **Схемы слоёв 167–228**: ID конструкторов подгружаются из JSON, а не захардкожены — один и тот же вызов работает на любой эре сервера.
- 💾 **Надёжная сессия в SQLite**: атомарная запись, авто-бэкап, восстановление после битого файла.
- 🔐 **SRP/2FA**, RSA_PAD нового и легаси-формата.
- 📨 **Хендлеры апдейтов**: `@client.on(NewMessage)`, `MessageEdited`, `MessageDeleted`.
- 🎁 **Подарки (Star Gifts)**, реакции, приватность, юзернеймы, аватарки, диалоги, история, forward, pin, контакты, чаты.
- 🚫 **Ноль тяжёлых зависимостей**: только `pycryptodome` и `aiohttp`.

---

## Установка

```bash
git clone https://github.com/<твой-ник>/gramsrv-userbot
cd gramsrv-userbot
pip install pycryptodome aiohttp
