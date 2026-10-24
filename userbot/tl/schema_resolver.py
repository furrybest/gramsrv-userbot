"""Реестр схемы слоя + выбор ближайшей эры для текущего layer сервера."""

import functools
import json
import os

from ..errors import SchemaError

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas", "data")

# Рукописное ядро: отсутствует в mtproto.tl (в оригинале "parsed manually"),
# но эти id НИКОГДА не менялись и не изменятся.
BUILTIN_ID_NAMES = {
    0x3072CFA1: "gzip_packed",      # gzip_packed#3072cfa1
    0xF35C6D01: "rpc_result",       # rpc_result#f35c6d01
    0x73F1F8DC: "msg_container",    # msg_container#73f1f8dc
}


class Schema:
    """Индекс конструкторов одного слоя: id->desc, name->desc."""

    def __init__(self, layer, constructors):
        self.layer = layer
        self._by_id = {}
        self._by_name = {}
        self._by_result = {}
        for c in constructors:
            self._by_id[c["id"]] = c
            self._by_name.setdefault(c["name"], c)
            self._by_result.setdefault(c.get("result"), c)

    def by_id(self, ident):
        return self._by_id.get(ident)

    def by_name(self, name):
        return self._by_name.get(name)

    def by_result(self, result):
        return self._by_result.get(result)

    def __len__(self):
        return len(self._by_id)


# якорь layer -> файл данных эры
LAYER_ANCHORS = {
    167: "v113",
    181: "v119",
    198: "v128",
    202: "v133",
    216: "v133",
    224: "latest",
    228: "latest",
}


def _load_data(name):
    with open(os.path.join(DATA_DIR, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


@functools.lru_cache(maxsize=None)
def _base_schema(layer: int) -> Schema:
    anchors = sorted(LAYER_ANCHORS)
    best = None
    for a in anchors:
        if a <= layer:
            best = a
    if best is None:
        raise SchemaError("layer %d is older than the oldest supported layer (167)" % layer)
    data_name = LAYER_ANCHORS[best]
    cons = list(_load_data("core"))
    cons += _load_data(data_name)
    # ручное ядро
    for ident, name in BUILTIN_ID_NAMES.items():
        cons.append({"id": ident, "name": name, "params": _builtin_params(name), "result": "Object"})
    return Schema(min(layer, max(LAYER_ANCHORS)), cons)


def _builtin_params(name):
    if name == "gzip_packed":
        return [["packed_data", "bytes"]]
    if name == "rpc_result":
        return [["req_msg_id", "long"], ["result", "Object"]]
    if name == "msg_container":
        return [["messages", "Vector<Message>"]]
    return []


def schema_for(layer: int) -> Schema:
    """Схема для данного layer (ближайшая эра <= layer).

    Русолов: 167->v1.13, 181->v1.19, 198->v1.28, 202/216->v1.33, 224/228->current.
    """
    return _base_schema(layer)


def composite_schema(layer: int) -> Schema:
    """Схема для вложенных запросов (initConnection+invokeWithLayer)."""
    return schema_for(layer)


# Таблица совместимости методов, чей id/поля менялись между слоями
# (для диагностики и быстрых справок; фактическое разрешение идёт по данным эр).
LAYER_COMPAT = {
    "auth.sendCode": {167: "a677244f", 228: "a677244f"},
    "auth.signIn": {167: "bcd51581", 198: "8d52a951", 228: "8d52a951"},
    "auth.signUp": {167: "80eee427", 228: "aac7b717"},
    "auth.importAuthorization": {167: "e3ef9613", 228: "7ab8d271"},
    "messages.sendMessage": {167: "520c3870", 198: "1cc20387", 202: "280d096f", 228: "545cd15a"},
    "messages.getHistory": {167: "dcbb8260", 181: "4423e6c5", 228: "4423e6c5"},
    "messages.getDifference": {167: "25939651", 228: "19c2f763"},
    "users.getUsers": {167: "d91a548", 228: "d91a548"},
    "users.getFullUser": {167: "ca30a5b1", 228: "b60bcd52"},
    "updates.getState": {167: "edd4882a", 228: "edd4882a"},
    "help.getConfig": {167: "c4f9186b", 228: "c4f9186b"},
    "account.getPassword": {167: "548a30f5", 228: "548a30f5"},
}


class SchemaResolver:
    """Точка входа для выбора схемы по слою (API из ТЗ).

    Использует генеративные данных блоки `tl/schemas/data/*.json`:
    ---- type_id -> параметры конструктора берутся из JSON, а не из классов.
    """

    def __init__(self):
        self._schemas = {}

    def register_schema(self, layer, schema: Schema):
        self._schemas[layer] = schema

    def register_layer(self, layer, schema_module=None):
        """Совместимость с API из ТЗ: схема строится по данным эры."""
        self._schemas[layer] = schema_for(layer)

    def get_schema_for_layer(self, layer: int) -> Schema:
        """Ближайшая доступная схема <= layer."""
        base = schema_for(layer)
        for k in sorted(self._schemas, reverse=True):
            if k <= layer:
                return self._schemas[k]
        return base

    def resolve_type(self, type_id, layer: int):
        """type_id -> дескриптор конструктора."""
        return schema_for(layer).by_id(type_id)

    def resolve_method(self, method_name: str, layer: int):
        """method_name -> (type_id, поля)."""
        desc = schema_for(layer).by_name(method_name)
        if desc is None:
            return None, None
        return desc["id"], desc["params"]


_global_resolver = SchemaResolver()