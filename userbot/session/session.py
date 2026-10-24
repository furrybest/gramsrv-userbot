"""Состояние сессии: auth_key, salt, session_id, метаданные пользователя."""

import logging
import os
import time

from ..crypto.auth_key import auth_key_id as compute_auth_key_id
from .storage import Storage

__log__ = logging.getLogger("wintergram.session")

_U64 = 0xFFFFFFFFFFFFFFFF


class Session:
    """Состояние сессии; загружается/сохраняется в SQLite (Storage)."""

    def __init__(self, dc_id=2, transport="abridged", storage: Storage = None):
        self.dc_id = int(dc_id)
        self.transport = transport
        self.storage = storage
        self.auth_key = None          # bytes 256
        self.auth_key_id = None       # bytes 8
        self.server_salt = 0
        self.session_id = int.from_bytes(os.urandom(8), "little")
        self.layer = None             # объявленный сервером слой
        self.schema_era = "latest"    # имя файла схемы по умолчанию
        self.user_id = None
        self.phone = None
        self.user = None              # последний разобранный User

    # --------------------------------------------------------------- #
    @property
    def is_authorized(self):
        return self.user_id is not None

    @property
    def has_auth_key(self):
        return self.auth_key is not None and len(self.auth_key) == 256

    def regen_session_id(self):
        self.session_id = int.from_bytes(os.urandom(8), "little")
        return self.session_id

    # --------------------------------------------------------------- #
    # персистентность
    # --------------------------------------------------------------- #
    @staticmethod
    def _sqlite64(value):
        """SQLite INTEGER — знаковый 64-бит; храним unsigned как знаковое."""
        if isinstance(value, int) and value > 0x7FFFFFFFFFFFFFFF:
            return value - 0x10000000000000000
        return value

    def save(self):
        """Сохраняет состояние; ошибка хранилища не должна ронять бота."""
        if self.storage is None:
            return
        try:
            self.storage.save_session({
                "dc_id": self.dc_id,
                "server_salt": self._sqlite64(self.server_salt),
                "session_id": self._sqlite64(self.session_id),
                "auth_key_id": bytes(self.auth_key_id) if self.auth_key_id else None,
                "user_id": self.user_id,
                "layer": self.layer,
                "phone": self.phone,
                "transport": self.transport,
            })
            if self.auth_key and len(self.auth_key) == 256:
                self.storage.save_auth_key(
                    self.auth_key, bytes(self.auth_key_id or b"")
                )
            __log__.info("session saved")
        except Exception as e:   # noqa: BLE001 - сессия переживает любой сбой
            __log__.error("session save failed: %r", e)

    def load(self):
        if self.storage is None:
            return
        self.storage.open()
        row = self.storage.load_session()
        if row:
            self.dc_id = int(row.get("dc_id") or self.dc_id)
            self.server_salt = (int(row.get("server_salt") or 0)) & _U64
            session_id = int(row.get("session_id") or 0) & _U64
            # битая/нулевая session_id ломает все запросы — генерируем новую
            self.session_id = session_id or self.regen_session_id()
            if row.get("auth_key_id"):
                self.auth_key_id = bytes(row["auth_key_id"])
            self.user_id = row.get("user_id")
            self.layer = row.get("layer")
            self.phone = row.get("phone")
            if row.get("transport"):
                self.transport = row["transport"]
        key = self.storage.load_auth_key(self.auth_key_id)
        if key and len(bytes(key)) == 256:
            self.auth_key = bytes(key)
            # auth_key_id обязан соответствовать ключу, иначе сервер
            # отвергнет кадры и клиент не подключится
            self.auth_key_id = compute_auth_key_id(self.auth_key)
            __log__.info("auth_key restored (%d bytes)", len(self.auth_key))
        else:
            if key is not None:
                __log__.error("stored auth_key is broken, re-handshake required")
            self.auth_key = None
            self.auth_key_id = None
        __log__.info("session loaded")

    def close(self):
        if self.storage:
            self.storage.close()