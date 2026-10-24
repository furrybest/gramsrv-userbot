"""Базовые типы TL: TLObject, хелперы для построения объектов.

TLObject хранит разобранные поля и даёт доступ по атрибутам и по ключам.
"""

from .serializer import TLWriter, TLReader, encode_constructor, decode_constructor

__all__ = ["TLObject", "TL", "encode_tl", "decode_tl", "TLWriter", "TLReader"]


class TLObject:
    """Объект TL: ``_id``, ``_name`` и разобранные поля в ``_fields``."""

    __slots__ = ("_id", "_name", "_fields")

    def __init__(self, id_=None, name=None, **fields):
        self._id = id_
        self._name = name
        self._fields = fields

    def __getattr__(self, item):
        if item.startswith("_"):
            raise AttributeError(item)
        fields = object.__getattribute__(self, "_fields")
        if item in fields:
            return fields[item]
        raise AttributeError(item)

    def __getitem__(self, item):
        return self._fields[item]

    def __setitem__(self, key, value):
        self._fields[key] = value

    def __contains__(self, item):
        return item in self._fields

    def get(self, key, default=None):
        return self._fields.get(key, default)

    def as_dict(self):
        out = dict(self._fields)
        out["_id"] = self._id
        out["_"] = self._name
        return out

    def __repr__(self):
        return "<TL %s %s>" % (self._name, self._fields)


# Алиас для краткой записи: TL("typingPeerUser", user_id=123, access_hash=456)
def TL(name, id_=None, **fields):
    if id_ is None:
        id_ = fields.pop("_id", None)
    return TLObject(id_, name, **fields)


def encode_tl(desc, values, registry=None) -> bytes:
    """Короткая обёртка над encode_constructor."""
    w = TLWriter()
    encode_constructor(w, desc, values, registry)
    return w.getvalue()


def decode_tl(data: bytes, desc, registry=None):
    """Короткая обёртка над decode_constructor (без id)."""
    return decode_constructor(TLReader(data), desc, registry)