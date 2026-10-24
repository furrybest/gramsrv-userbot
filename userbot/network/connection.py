"""TCP-соединение к серверу приватки + выбор транспорта."""

import asyncio
import logging

from ..errors import TransportError
from .transport import TRANSPORTS, TRANSPORT_NAMES

__log__ = logging.getLogger("wintergram.network.connection")


class Connection:
    """asyncio TCP к ``ip:port`` с одним транспортом."""

    def __init__(self, ip, port, transport_name="abridged", timeout=15):
        self.ip = ip
        self.port = port
        self.transport_name = transport_name
        self.timeout = timeout
        self.reader = None
        self.writer = None
        self.transport = None

    @property
    def is_connected(self):
        return self.transport is not None and not self.transport._closed

    async def connect(self):
        """Открывает TCP и делает магию транспорта (без MTProto-полезной нагрузки)."""
        if self.transport_name not in TRANSPORTS:
            raise TransportError("unknown transport %r" % self.transport_name)
        __log__.info("connecting %s:%d (transport=%s)",
                     self.ip, self.port, self.transport_name)
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port), timeout=self.timeout
            )
        except OSError as e:
            raise TransportError("cannot connect to %s:%d: %r" % (self.ip, self.port, e))

        transport_cls = TRANSPORTS[self.transport_name]
        self.transport = transport_cls()
        self.transport.attach(self.reader, self.writer)
        try:
            await asyncio.wait_for(self.transport._send_handshake(), timeout=self.timeout)
        except Exception as e:
            self.close()
            raise TransportError("transport handshake failed: %r" % e)
        __log__.info("connected (transport=%s)", self.transport_name)
        return self.transport

    async def reconnect(self):
        self.close()
        await self.connect()

    def close(self):
        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.transport = None

    async def send(self, data: bytes):
        if not self.is_connected:
            raise TransportError("connection is not established")
        await self.transport.send(data)

    async def recv(self) -> bytes:
        if not self.is_connected:
            raise TransportError("connection is not established")
        return await self.transport.recv()


async def connect_with_autodetect(ip, port, preferred="abridged", timeout=15):
    """Пробует транспорты по порядку (prompt §3.2): abridged -> intermediate -> full.

    Возвращает (Connection, transport_name).
    """
    order = [preferred] + [t for t in ("abridged", "intermediate", "full", "padded") if t != preferred]
    last_err = None
    for name in order:
        conn = Connection(ip, port, name, timeout)
        try:
            await conn.connect()
            return conn, name
        except Exception as e:
            __log__.warning("transport %s failed: %r", name, e)
            last_err = e
            conn.close()
    raise TransportError("all transports failed (%r)" % (last_err,))