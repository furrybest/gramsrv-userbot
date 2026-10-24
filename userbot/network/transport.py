"""Транспорты MTProto: Abridged / Intermediate / Padded Intermediate / Full.

Инкапсулируют шифрованное сообщение в пакеты уровня TCP.
"""

import asyncio
import binascii
import logging
import struct

from ..errors import TransportError

__log__ = logging.getLogger("wintergram.network.transport")

ABRIDGED = b"\xef"
INTERMEDIATE = b"\xee\xee\xee\xee"
PADDED = b"\xdd\xdd\xdd\xdd"
FULL = b"\xff\xff\xff\xff"  # маркер "отдельный транспорт", не отправляется

TRANSPORT_NAMES = ("abridged", "intermediate", "padded", "full")


class BaseTransport:
    name = None
    recv_magic = None
    send_magic = None
    has_header = False  # Full не шлёт магию
    requires_padding_16 = False

    def __init__(self):
        self._reader = None
        self._writer = None
        self._closed = False

    def attach(self, reader, writer):
        self._reader = reader
        self._writer = writer

    async def _send_handshake(self):
        if self.send_magic:
            self._writer.write(self.send_magic)
            await self._writer.drain()

    async def send(self, data: bytes):
        if self._closed:
            raise TransportError("transport closed")
        packet = self._pack(data)
        self._writer.write(packet)
        await self._writer.drain()

    async def recv(self) -> bytes:
        if self._closed:
            raise TransportError("transport closed")
        parts = await self._next_packet_parts()
        payload = b"".join(parts)
        return self._unpack(payload)

    def _pack(self, data: bytes) -> bytes:
        raise NotImplementedError

    async def _next_packet_parts(self):
        raise NotImplementedError

    def _unpack(self, payload: bytes) -> bytes:
        return payload

    def close(self):
        self._closed = True
        try:
            self._writer.close()
        except Exception:
            pass


class AbridgedTransport(BaseTransport):
    """[0xef] затем frames: len < 127 октетов -> 1 байт; иначе 0x7f + 3 байта LE."""

    name = "abridged"
    send_magic = ABRIDGED

    def _pack(self, data: bytes) -> bytes:
        if len(data) % 4:
            data += b"\x00" * (4 - len(data) % 4)
        words = len(data) // 4
        if words < 127:
            return bytes([words]) + data
        return b"\x7f" + words.to_bytes(3, "little") + data

    async def _next_packet_parts(self):
        b = (await self._reader.readexactly(1))[0]
        if b == 0x7F:
            length = int.from_bytes(await self._reader.readexactly(3), "little") * 4
        else:
            length = b * 4
        if length == 0:
            return [b""]
        return [await self._reader.readexactly(length)]


class IntermediateTransport(BaseTransport):
    """[0xeeeeeeee] + 4-байтная длина LE + payload."""

    name = "intermediate"
    send_magic = INTERMEDIATE

    def _pack(self, data: bytes) -> bytes:
        if len(data) % 4:
            data += b"\x00" * (4 - len(data) % 4)
        return struct.pack("<i", len(data)) + data

    async def _next_packet_parts(self):
        length = struct.unpack("<i", await self._reader.readexactly(4))[0]
        if length == 0:
            return [b""]
        return [await self._reader.readexactly(length)]


class PaddedIntermediateTransport(IntermediateTransport):
    """[0xdddddddd] + 4-байтная длина (с дотяжкой до 16) + payload."""

    name = "padded"
    send_magic = PADDED

    def _pack(self, data: bytes) -> bytes:
        # длина кратна 16; сам payload дополнит в _send (но сошлёмся на это место)
        pad = (16 - len(data) % 16) % 16
        if pad:
            data += b"\x00" * pad
        return struct.pack("<i", len(data)) + data


class FullTransport(BaseTransport):
    """len (4Б, реверс) + seqno (4Б, реверс) + payload (len кратно 4) + CRC32 (4Б, реверс).

    Магия не шлётся (сервер сам понимает по формату).
    """

    name = "full"
    has_header = True

    def __init__(self):
        super().__init__()
        self._send_seq = 0
        self._recv_seq = 0

    def _pack(self, data: bytes) -> bytes:
        if len(data) % 4:
            data += b"\x00" * (4 - len(data) % 4)
        length = len(data) // 4
        crc = binascii.crc32(data) & 0xFFFFFFFF
        header = (
            struct.pack("<I", length)[::-1]
            + struct.pack("<I", self._send_seq)[::-1]
        )
        self._send_seq += 1
        return header + data + struct.pack("<I", crc)[::-1]

    async def _next_packet_parts(self):
        length = struct.unpack("<I", (await self._reader.readexactly(4))[::-1])[0]
        length *= 4
        seq = struct.unpack("<I", (await self._reader.readexactly(4))[::-1])[0]
        payload = await self._reader.readexactly(length)
        crc = struct.unpack("<I", (await self._reader.readexactly(4))[::-1])[0]
        if binascii.crc32(payload) & 0xFFFFFFFF != crc:
            raise TransportError(
                "CRC mismatch on full transport: got %08x, expected %08x"
                % (binascii.crc32(payload) & 0xFFFFFFFF, crc)
            )
        self._recv_seq = seq
        return [payload]


TRANSPORTS = {
    "abridged": AbridgedTransport,
    "intermediate": IntermediateTransport,
    "padded": PaddedIntermediateTransport,
    "full": FullTransport,
}


async def try_connect_transport(reader, writer, name: str):
    """Подключение транспортом ``name``; возвращает объект транспорта."""
    transport = TRANSPORTS[name]()
    transport.attach(reader, writer)
    await transport._send_handshake()
    return transport