"""Бинарная TL-сериализация (int, long, int128, int256, string, vector, flags).

Схема-независимый движок: все конструкторы описываются дескрипторами вида

    {"id": 0x..., "name": "...", "params": [["имя", "TL-тип"], ...], "result": "Type"}

TL-типы в params:
    int / long / int128 / int256 / double / string / bytes / bool / true
    flags                      - 32-битная битовая маска (ах *optional fields*)
    flags.N?<тип>              - условное поле (присутствует при установленном бите N)
    Vector<<X>>                - вектор объектов/скаляров X
    имя_типа / имя_метода      - boxed конструктор (резолвится через реестр слоя)
"""

import struct

TRUE_ID = 0x997275B5
FALSE_ID = 0xBC799737
VECTOR_ID = 0x1CB5C415


class TLParseError(Exception):
    pass


class TLWriter:
    __slots__ = ("buf",)

    def __init__(self, buf=None):
        self.buf = bytearray(buf) if buf is not None else bytearray()

    # ---- примитивы ----
    def write_int(self, value):
        self.buf += struct.pack("<i", self._signed32(value))

    @staticmethod
    def _signed32(value):
        v = int(value) & 0xFFFFFFFF
        return v if v < 0x80000000 else v - 0x100000000

    @staticmethod
    def _signed64(value):
        v = int(value) & 0xFFFFFFFFFFFFFFFF
        return v if v < 0x8000000000000000 else v - 0x10000000000000000

    def write_uint(self, value):
        # для битовых масок, где знак ни на что не влияет
        self.buf += struct.pack("<I", int(value) & 0xFFFFFFFF)

    def write_long(self, value):
        self.buf += struct.pack("<q", self._signed64(value))

    def write_double(self, value):
        self.buf += struct.pack("<d", float(value))

    def write_fixed(self, data, size):
        if len(data) != size:
            raise TLParseError("expected %d bytes, got %d" % (size, len(data)))
        self.buf += data

    def write_int128(self, data):
        self.write_fixed(data, 16)

    def write_int256(self, data):
        self.write_fixed(data, 32)

    def write_bytes(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        length = len(data)
        if length < 254:
            pad = (4 - (length + 1) % 4) % 4
            self.buf += bytes((length,))
            self.buf += data
            self.buf += b"\x00" * pad
        else:
            pad = (4 - length % 4) % 4
            self.buf += b"\xfe" + struct.pack("<I", length)[:3]
            self.buf += data
            self.buf += b"\x00" * pad

    def write_bool(self, value):
        self.write_uint(TRUE_ID if value else FALSE_ID)

    def write_true(self):
        self.write_uint(TRUE_ID)

    def write_vector(self, items, item_type, registry):
        self.write_int(VECTOR_ID)
        self.write_int(len(items))
        for item in items:
            self._write_value(item_type, item, registry)

    def _write_value(self, type_str, value, registry):
        _write_value(self, type_str, value, registry)

    def getvalue(self):
        return bytes(self.buf)


class TLReader:
    __slots__ = ("data", "pos")

    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def remaining(self):
        return len(self.data) - self.pos

    def read(self, size):
        if self.pos + size > len(self.data):
            raise TLParseError(
                "not enough data: need %d at %d, have %d" % (size, self.pos, len(self.data))
            )
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def peek(self, size):
        if self.pos + size > len(self.data):
            raise TLParseError("not enough data for peek")
        return self.data[self.pos:self.pos + size]

    # ---- примитивы ----
    def read_int(self):
        return struct.unpack("<i", self.read(4))[0]

    def read_uint(self):
        return struct.unpack("<I", self.read(4))[0]

    def read_long(self):
        return struct.unpack("<q", self.read(8))[0]

    def read_double(self):
        return struct.unpack("<d", self.read(8))[0]

    def read_int128(self):
        return self.read(16)

    def read_int256(self):
        return self.read(32)

    def read_bytes(self):
        first = self.data[self.pos]
        self.pos += 1
        if first < 254:
            length = first
        elif first == 254:
            length = int.from_bytes(self.read(3), "little")
        else:
            raise TLParseError("invalid string marker byte 0x%02x" % first)
        if length:
            out = self.read(length)
        else:
            out = b""
        # отбросить выравнивание
        while self.pos % 4:
            self.pos += 1
        return out

    def read_bool(self):
        ident = self.read_uint()
        if ident == TRUE_ID:
            return True
        if ident == FALSE_ID:
            return False
        raise TLParseError("expected bool, got 0x%08x" % ident)

    def read_vector_raw(self):
        ident = self.read_uint()
        if ident != VECTOR_ID:
            raise TLParseError("expected vector 0x1cb5c415, got 0x%08x" % ident)
        return self.read_int()

    def _read_value(self, type_str, registry):
        return _read_value(self, type_str, registry)


def _write_value(w, type_str, value, registry):
    """Запись значения по строке TL-типа."""
    if value is None:
        if type_str == "true":
            return
        raise TLParseError("value is None but field type is %r" % type_str)

    if type_str == "int":
        w.write_int(value)
    elif type_str == "long":
        w.write_long(value)
    elif type_str == "double":
        w.write_double(value)
    elif type_str == "int128":
        if isinstance(value, int):
            value = int(value).to_bytes(16, "little", signed=True)
        w.write_int128(value)
    elif type_str == "int256":
        if isinstance(value, int):
            value = int(value).to_bytes(32, "little", signed=True)
        w.write_int256(value)
    elif type_str in ("string", "bytes"):
        w.write_bytes(value)
    elif type_str == "bool":
        w.write_bool(bool(value))
    elif type_str == "true":
        w.write_true()
    elif type_str == "flags":
        # битовая маска уже посчитана вызывающим кодом
        w.write_uint(int(value) & 0xFFFFFFFF)
    elif type_str.startswith("Vector<") and type_str.endswith(">"):
        inner = type_str[len("Vector<"):-1]
        w.write_vector(value or [], inner, registry)
    else:
        # boxed конструктор: value - TLObject или dict
        _write_boxed(w, type_str, value, registry)


def _write_boxed(w, expected_type, value, registry):
    if isinstance(value, bool) or expected_type == "Bool":
        w.write_bool(bool(value))
        return
    if isinstance(value, dict):
        data = dict(value)
        name = data.pop("_", None)
        ident = data.get("_id")
        if len(data) == 0 or ident is not None or name is not None:
            if ident is not None:
                desc = registry.by_id(int(ident)) if registry else None
            elif name is not None:
                desc = registry.by_name(str(name)) if registry else None
            else:
                desc = _resolve_boxed(registry, expected_type)
        else:
            desc = _resolve_boxed(registry, expected_type)
        if desc is None:
            raise TLParseError("unknown boxed type %r" % expected_type)
        encode_constructor(w, desc, data, registry)
    elif isinstance(value, TLObject):
        desc = registry.by_id(value._id) if (registry and value._id is not None) else None
        if desc is None:
            desc = registry.by_name(value._name) if (registry and value._name) else None
        if desc is None:
            raise TLParseError("unknown object id %r" % value._id)
        encode_constructor(w, desc, value.as_dict(), registry)
    else:
        raise TLParseError("cannot serialize %r as %s" % (value, expected_type))


def _camel(name):
    parts = name.split(".")
    return parts[-1]


def _resolve_boxed(registry, expected_type):
    """Поиск конструктора для boxed-типа: по полному имени, C-имени и по result."""
    if registry is None:
        return None
    return (
        registry.by_name(expected_type)
        or registry.by_name(_camel(expected_type))
        or registry.by_result(expected_type)
    )


def _flags_fields(params):
    """Возвращает {префикс_флагов: [(имя, бит, тип)]}."""
    flags = {}
    for name, type_str in params:
        if type_str == "flags":
            continue
        if "?" in type_str and "." in type_str:
            prefix, rest = type_str.split(".", 1)
            bit, typ = rest.split("?", 1)
            flags.setdefault(prefix, []).append((name, int(bit), typ))
    return flags


def _compute_flags(params, values):
    """Считаем все flags-маски (flags, flags2, ...) из переданных значений.

    Для `flags.N?true` бит ставим только при истинном значении (False — это
    «поле отсутствует»); для остальных условных полей — по присутствию (not None).
    """
    groups = _flags_fields(params)
    masks = {}
    for prefix, fields in groups.items():
        mask = 0
        for name, bit, typ in fields:
            v = values.get(name)
            if (v is not None) if typ != "true" else v:
                mask |= 1 << bit
        masks[prefix] = mask
    return masks


def encode_constructor(w, desc, values, registry=None):
    """Сериализация конструктора по дескриптору (включая id).

    ВАЖНО: флаговые слова (flags, flags2, ...) пишутся ТОЛЬКО на своём
    месте в порядке объявления. Поля типа `flags.N?true` не пишут
    никаких байтов (признак — сам бит маски).
    """
    w.write_uint(desc["id"])
    if not isinstance(values, dict):
        raise TLParseError("values must be a dict for %s" % desc["name"])
    masks = _compute_flags(desc["params"], values)

    for name, type_str in desc["params"]:
        if type_str == "flags":
            w.write_uint(masks.get(name, 0) & 0xFFFFFFFF)
        elif "?" in type_str and "." in type_str:
            prefix, rest = type_str.split(".", 1)
            bit, typ = rest.split("?", 1)
            bit = int(bit)
            if typ == "true":
                continue  # байтов не пишем
            if masks.get(prefix, 0) & (1 << bit):
                v = values.get(name)
                if v is not None:
                    _write_value(w, typ, v, registry)
        else:
            _write_value(w, type_str, values.get(name), registry)


def decode_constructor(r, desc, registry=None):
    """Десериализация содержимого конструктора (БЕЗ чтения его id).

    Однопроходный разбор строго в порядке объявления параметров:
    флаговое слово читается на своём месте, поля `flags.N?true`
    занимают 0 байт (True, если бит выставлен).
    """
    params = desc.get("params", [])
    value = {"_": desc["name"], "_id": desc["id"]}
    masks = {}
    for name, type_str in params:
        if type_str == "flags":
            masks[name] = r.read_uint()
            value[name] = masks[name]
            continue
        if "?" in type_str and "." in type_str:
            prefix, rest = type_str.split(".", 1)
            bit, typ = rest.split("?", 1)
            bit = int(bit)
            fv = masks.get(prefix, 0)
            if typ == "true":
                value[name] = bool(fv & (1 << bit))
            elif fv & (1 << bit):
                value[name] = _read_value(r, typ, registry)
            else:
                value[name] = None
        else:
            value[name] = _read_value(r, type_str, registry)
    return value


def encode_object(desc, values, registry=None) -> bytes:
    w = TLWriter()
    encode_constructor(w, desc, values, registry)
    return w.getvalue()


def decode_object(reader_or_bytes, desc, registry=None):
    r = reader_or_bytes if isinstance(reader_or_bytes, TLReader) else TLReader(reader_or_bytes)
    return decode_constructor(r, desc, registry)


def _read_value(r, type_str, registry):
    if type_str == "int":
        return r.read_int()
    if type_str == "long":
        return r.read_long()
    if type_str == "double":
        return r.read_double()
    if type_str == "int128":
        return r.read_int128()
    if type_str == "int256":
        return r.read_int256()
    if type_str in ("string", "bytes"):
        return r.read_bytes()
    if type_str == "bool":
        return r.read_bool()
    if type_str == "true":
        if r.peek(4) == struct.pack("<I", TRUE_ID):
            r.read(4)
            return True
        return False
    if type_str.startswith("Vector<") and type_str.endswith(">"):
        inner = type_str[len("Vector<"):-1]
        count = r.read_vector_raw()
        return [_read_value(r, inner, registry) for _ in range(count)]
    # boxed
    ident = r.read_uint()
    return _read_boxed(r, ident, registry)


def _read_boxed(r, ident, registry):
    if registry is None:
        raise TLParseError("no registry to resolve 0x%08x" % ident)
    desc = registry.by_id(ident)
    if desc is None:
        pos = r.pos
        raise TLParseError(
            "unknown constructor id 0x%08x at offset %d (layer schema does not know it)"
            % (ident, pos - 4)
        )
    return decode_constructor(r, desc, registry)