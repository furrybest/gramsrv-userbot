"""wintergram_userbot - переписанный с нуля асинхронный MTProto-клиент.

Пишется для ПРИВАТНОГО MTProto-сервера (не официального Telegram).
Поддерживаются слои (layers) от 167 до 228 включительно.
"""

__version__ = "1.4"

from .client import WinterGramClient
from .errors import (
    RPCError,
    FloodWaitError,
    AuthKeyError,
    LayerMismatchError,
    ConnectionClosedError,
    UnknownLayerError,
    AuthorizationExpiredError,
    TimeoutError,
    TransportError,
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneNumberUnoccupiedError,
)
from .tl.types import TL, TLObject
from .api.updates import NewMessage, MessageEdited, MessageDeleted

__all__ = [
    "WinterGramClient",
    "RPCError",
    "FloodWaitError",
    "AuthKeyError",
    "LayerMismatchError",
    "ConnectionClosedError",
    "UnknownLayerError",
    "AuthorizationExpiredError",
    "TimeoutError",
    "TransportError",
    "SessionPasswordNeededError",
    "PhoneCodeInvalidError",
    "PhoneNumberUnoccupiedError",
    "TL",
    "TLObject",
    "NewMessage",
    "MessageEdited",
    "MessageDeleted",
    "__version__",
]