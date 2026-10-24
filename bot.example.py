"""Пример юзербота. Скопируй в bot.py и впиши свои данные."""
import asyncio
from userbot import WinterGramClient, NewMessage

client = WinterGramClient(
    server_ip="127.0.0.1",          # IP твоей приватки
    server_port=2398,               # порт
    dc_id=2,                        # DC id
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
