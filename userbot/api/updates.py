"""Обработка updates: разбор, события, роутинг в зарегистрированные хендлеры.

События создаются независимо от эры схемы: поля достаются из разобранного
дерева TLObject (dict-like), поэтому одна логика работает и на слое 167,
и на слое 228.
"""

import logging

from ..tl.types import TLObject

__log__ = logging.getLogger("wintergram.api.updates")

# имена апдейтов (по stdout 'name' поля в схемах)
_UPDATE_NEW_MESSAGE = {"updateNewMessage", "updateNewChannelMessage"}
_UPDATE_EDIT = {"updateEditMessage", "updateEditChannelMessage"}
_UPDATE_DELETE = {"updateDeleteMessages", "updateDeleteChannelMessages"}


def _as_dict(obj):
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, TLObject):
        return obj.as_dict()
    return dict(obj)


def _as_text(value):
    """TL-строки приходят как bytes - приводим к str."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


class Event:
    """Базовое событие."""

    def __init__(self, raw):
        self.raw = raw  # исходный TLObject (или dict)

    @property
    def raw_dict(self):
        return _as_dict(self.raw)

    @property
    def message(self):
        """Внутренний dict сообщения (updateNewMessage.message и т.п.).

        Для updateShort* апдейтов, где сообщение лежит прямо в update,
        возвращается сам update. Текст нормализован в str.
        """
        d = _as_dict(self.raw)
        inner = d.get("message")
        # у updateNew* поле message - вложенный dict, у updateShort* - строка
        if isinstance(inner, (dict, TLObject)):
            m = _as_dict(inner)
            if isinstance(m.get("message"), (bytes, bytearray)):
                m = dict(m)
                m["message"] = _as_text(m["message"])
            return m
        if isinstance(inner, (bytes, bytearray)):
            d = dict(d)
            d["message"] = _as_text(inner)
        return d


class NewMessage(Event):
    """Новое сообщение.

    Поля: id, text, date, chat_id, sender_id, out, reply_to_msg_id, raw.
    """

    def __init__(self, raw, id=None, text=None, date=None, chat_id=None,
                 sender_id=None, out=False, from_channel=False):
        super().__init__(raw)
        self.id = id
        self.text = _as_text(text)
        self.date = date
        self.chat_id = chat_id
        self.sender_id = sender_id
        self.out = bool(out)
        self.from_channel = from_channel

    @property
    def is_private(self):
        return not self.from_channel and self.chat_id is not None and self.sender_id is not None

    @property
    def is_channel(self):
        return self.from_channel

    def __repr__(self):
        return "<NewMessage id=%s chat=%s from=%s text=%r>" % (
            self.id, self.chat_id, self.sender_id, (self.text or "")[:40]
        )


class MessageEdited(NewMessage):
    pass


class MessageDeleted(Event):

    def __init__(self, raw, deleted_ids=(), chat_id=None, channel_id=None):
        super().__init__(raw)
        self.deleted_ids = list(deleted_ids)
        self.chat_id = chat_id
        self.channel_id = channel_id

    def __repr__(self):
        return "<MessageDeleted ids=%s>" % (self.deleted_ids,)


class MessageHandler:
    """Реестр хендлеров по типу события."""

    def __init__(self):
        self._handlers = {}   # "NewMessage" -> list[callable]

    def on(self, event_type):
        name = getattr(event_type, "__name__", str(event_type))
        def decorator(func):
            self._handlers.setdefault(name, []).append(func)
            return func
        return decorator

    async def dispatch(self, events):
        results = []
        for ev in events:
            name = type(ev).__name__
            for handler in self._handlers.get(name, []):
                try:
                    r = handler(ev)
                    if hasattr(r, "__await__"):
                        await r
                    results.append(r)
                except Exception as e:
                    __log__.error("handler %s raised: %r", getattr(handler, "__qualname__", handler), e)
        return results


class UpdatesProcessor:
    """Превращает входящий объект Updates в список событий."""

    def __init__(self, schema):
        self.schema = schema

    def process(self, obj) -> list:
        d = _as_dict(obj)
        name = d.get("_")
        events = []
        if name in ("updates", "updatesCombined", "updateShort"):
            inner = d.get("update")
            if inner is not None:
                events += self.process(inner)
            for u in (d.get("updates") or []):
                events += self.process(u)
            return events
        if name == "updateShortMessage":
            return [NewMessage(
                raw=d, id=d.get("id"), text=d.get("message"),
                date=d.get("date"), chat_id=d.get("user_id"),
                sender_id=d.get("user_id") if not d.get("out") else None,
                out=d.get("out", False),
            )]
        if name == "updateShortChatMessage":
            return [NewMessage(
                raw=d, id=d.get("id"), text=d.get("message"),
                date=d.get("date"), chat_id=d.get("chat_id"),
                sender_id=d.get("from_id"), out=d.get("out", False),
            )]
        if name == "updateShortSentMessage":
            return []   # подтверждение собственной отправки
        if name in _UPDATE_NEW_MESSAGE:
            message = d.get("message") or {}
            md = _as_dict(message)
            chat_id = self._chat_id(md)
            sender = self._sender_id(md)
            return [NewMessage(
                raw=d, id=md.get("id") or d.get("id"), text=md.get("message"),
                date=md.get("date"), chat_id=chat_id, sender_id=sender,
                out=md.get("out", False), from_channel=name == "updateNewChannelMessage",
            )]
        if name in _UPDATE_EDIT:
            message = d.get("message") or {}
            md = _as_dict(message)
            chat_id = self._chat_id(md)
            sender = self._sender_id(md)
            return [MessageEdited(
                raw=d, id=md.get("id"), text=md.get("message"),
                date=md.get("date"), chat_id=chat_id, sender_id=sender,
                out=md.get("out", False), from_channel=name == "updateEditChannelMessage",
            )]
        if name in _UPDATE_DELETE:
            return [MessageDeleted(
                raw=d,
                deleted_ids=d.get("messages") or [],
                chat_id=(d.get("channel_id") if "channel_id" in d else None),
                channel_id=d.get("channel_id"),
            )]
        return []

    @staticmethod
    def _chat_id(message_dict):
        to_id = message_dict.get("to_id") or {}
        td = _as_dict(to_id)
        if td:
            return td.get("user_id") or td.get("chat_id") or td.get("channel_id")
        peer_id = message_dict.get("peer_id")
        if isinstance(peer_id, (dict, TLObject)):
            pd = _as_dict(peer_id)
            return pd.get("user_id") or pd.get("chat_id") or pd.get("channel_id")
        return None

    @staticmethod
    def _sender_id(message_dict):
        from_id = message_dict.get("from_id")
        if isinstance(from_id, (dict, TLObject)):
            fd = _as_dict(from_id)
            return fd.get("user_id") or fd.get("channel_id") or fd.get("chat_id")
        return from_id