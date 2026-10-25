    """MTProto: шифрованный обмен, handshake, RPC-диспетчеризация, updates.
    
    Маршрут: transport -> MTProtoConnection (вузащие шифрованные сообщения,
    pending-фьючеры по msg_id) -> клиентский API.
    """
    
    import asyncio
    import hashlib
    import logging
    import os
    import struct
    import time
    import zlib
    
    from ..crypto.aes import ige_encrypt, ige_decrypt, ctr_encrypt
    from ..crypto.auth_key import (
        auth_key_id,
        compute_msg_key_v2,
        aes_key_iv_v2,
        build_new_nonce_hash,
        auth_key_aux_hash,
        compute_aes_key_iv_tmp,
    )
    from ..crypto.dh import (
        factorize_pq,
        dh_generate_a,
        dh_calculate_g_b,
        compute_auth_key,
    )
    from ..crypto.rsa import rsa_pad
    from ..errors import (
        TransportError,
        AuthKeyError,
        LayerMismatchError,
        RPCError,
        FloodWaitError,
    )
    from ..tl.serializer import (
        TLWriter,
        TLReader,
        TLParseError,
        encode_constructor,
        encode_object,
        decode_constructor,
    )
    from ..tl.schema_resolver import schema_for
    
    __log__ = logging.getLogger("wintergram.network.mtproto")
    
    ID_RES_PQ = 0x05162463
    ID_REQ_PQ_MULTI = 0xBE7E8EF1
    ID_REQ_DH_PARAMS = 0xD712E4BE
    ID_SERVER_DH_PARAMS_OK = 0xD0E8075C
    ID_SERVER_DH_PARAMS_FAIL = 0x79CB045D
    ID_SET_CLIENT_DH_PARAMS = 0xF5045F1F
    ID_DH_GEN_OK = 0x3BCBF734
    ID_DH_GEN_RETRY = 0x46DC1FB9
    ID_DH_GEN_FAIL = 0xA69DAE02
    ID_MSG_CONTAINER = 0x73F1F8DC
    ID_RPC_RESULT = 0xF35C6D01
    ID_RPC_ERROR = 0x2144CA19
    ID_MSGS_ACK = 0x62D6B459
    ID_BAD_MSG_NOTIFICATION = 0xA7EFF811
    ID_BAD_SERVER_SALT = 0xEDAB447B
    ID_NEW_SESSION_CREATED = 0x9EC20908
    ID_PONG = 0x347773C5
    ID_GZIP_PACKED = 0x3072CFA1
    ID_PING = 0x7ABE77EC
    
    # little-endian сигнатура gzip_packed в начале тела ответа
    GZIP_MAGIC_LE = struct.pack("<I", ID_GZIP_PACKED)
    
    
    def inflate(data: bytes) -> bytes:
        """Распаковывает gzip/zlib/deflate - сервер встречается со всеми тремя."""
        if not data:
            raise ValueError("empty packed payload")
        for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(data, wbits)
            except zlib.error:
                continue
        raise ValueError("cannot inflate %d bytes" % len(data))
    
    # якоря эр (по убыванию) для определения layer
    ERA_ORDER = (228, 202, 198, 181, 167)
    
    
    def _le8(v: int) -> bytes:
        v = v & 0xFFFFFFFFFFFFFFFF
        if v >= (1 << 63):
            v -= 1 << 64
        return struct.pack("<q", v)
    
    
    def _le4(v: int) -> bytes:
        return struct.pack("<i", v & 0xFFFFFFFF)
    
    
    class MTProtoConnection:
        """Одно TCP-соединение + одна сессия + обработка сообщений."""
    
        def __init__(
            self,
            transport,
            session,
            api_id=2040,
            api_hash="b18441a1ff607e10a989891a5462e627",
            schema_era="latest",
        ):
            self.transport = transport
            self.session = session
            self.api_id = api_id
            self.api_hash = api_hash
            era_layer = schema_for(228).layer if schema_era == "latest" else {
                "v113": 167, "v119": 181, "v128": 198, "v133": 202,
            }.get(schema_era, 228)
            self._edge_layer = era_layer
            self._schema = schema_for(self._edge_layer)
            self._reader_task = None
            self._pending = {}   # msg_id -> {"future": Future, "raw": bool, "body": bytes}
            self._last_msg_id = 0
            self._last_mapped_msg_id = 0
            self._seq_n = 0
            self._handshake_done = False
            self._closed = False
            self._send_lock = asyncio.Lock()
            self.on_push = None   # Callable[[TLObject], Awaitable]
    
            # На каждом новом транспорте MTProto требует НОВУЮ session_id.
            # Раньше она генерировалась только в handshake(), поэтому при
            # переподключении с готовым auth_key сервер рвал соединение.
            self.session.session_id = int.from_bytes(os.urandom(8), "little")
            self.session.server_salt = 0
    
        # ------------------------------------------------------------------ #
        # msg_id / seq_no
        # ------------------------------------------------------------------ #
    
        def new_msg_id(self) -> int:
            now = int(time.time() * 2 ** 32)
            now &= ~3                       # кратность 4
            if now <= self._last_msg_id:
                now = self._last_msg_id + 4
            self._last_msg_id = now
            return now
    
        def _alloc_seq(self, content: bool = True) -> int:
            # MTProto: seq_no = (n << 1) | (0 для non-content, 1 для content);
            # n = число уже отправленных content-сообщений.
            n = self._seq_n
            if content:
                self._seq_n += 1
                return (n << 1) | 1
            return n << 1
    
        # ------------------------------------------------------------------ #
        #  крипто
        # ------------------------------------------------------------------ #
    
        def _encrypt_outer(self, inner: bytes) -> bytes:
            msg_key = compute_msg_key_v2(self.session.auth_key, inner, client_to_server=True)
            key, iv = aes_key_iv_v2(self.session.auth_key, msg_key, client_to_server=True)
            encrypted = ige_encrypt(inner, key, iv)
            return auth_key_id(self.session.auth_key) + msg_key + encrypted
    
        def _decrypt_outer(self, frame: bytes) -> bytes:
            if len(frame) < 24:
                raise TransportError("encrypted frame too short: %d" % len(frame))
            expected_key_id = auth_key_id(self.session.auth_key)
            if frame[:8] != expected_key_id:
                raise TransportError(
                    "auth_key_id mismatch: got %s, want %s"
                    % (frame[:8].hex(), expected_key_id.hex())
                )
            msg_key = frame[8:24]
            key, iv = aes_key_iv_v2(self.session.auth_key, msg_key, client_to_server=False)
            inner = ige_decrypt(frame[24:], key, iv)
            expected = compute_msg_key_v2(self.session.auth_key, inner, client_to_server=False)
            if expected != msg_key:
                __log__.warning("msg_key mismatch on response (have %s want %s)",
                                expected.hex(), msg_key.hex())
            return inner
    
        def _build_inner(self, body: bytes, msg_id: int, seq_no: int) -> bytes:
            header = (
                _le8(self.session.server_salt)
                + _le8(self.session.session_id)
                + _le8(msg_id)
                + _le4(seq_no)
                + _le4(len(body))
            )
            total = len(header) + len(body)
            pad = (16 - total % 16) % 16
            if pad < 12:
                pad += 16
            return header + body + os.urandom(pad)
    
        async def _send_encrypted(self, body: bytes, msg_id: int, content: bool = True) -> None:
            seq_no = self._alloc_seq(content)
            inner = self._build_inner(body, msg_id, seq_no)
            outer = self._encrypt_outer(inner)
            await self.transport.send(outer)
    
        # ------------------------------------------------------------------ #
        #  приём / диспетчеризация
        # ------------------------------------------------------------------ #
    
        async def _reader_loop(self):
            while not self._closed:
                try:
                    frame = await self.transport.recv()
                except (asyncio.IncompleteReadError, ConnectionError, TransportError) as e:
                    __log__.warning("transport read failed: %r", e)
                    await self._interrupt_pending(TransportError("connection closed: %r" % (e,)))
                    return
                except Exception as e:
                    __log__.error("transport error: %r", e)
                    await self._interrupt_pending(TransportError("transport error: %r" % (e,)))
                    return
                try:
                    inner = self._decrypt_outer(frame)
                    self._on_decrypted(inner)
                except Exception as e:
                    __log__.error("failed processing frame (%s): %s", e, frame.hex()[:128])
                    continue
    
        async def _interrupt_pending(self, error: Exception):
            self._closed = True
            for item in self._pending.values():
                fut = item["future"]
                if not fut.done():
                    fut.set_exception(error)
            self._pending.clear()
    
        def _on_decrypted(self, inner: bytes):
            if len(inner) < 32:
                raise TLParseError("inner message too short")
            salt, session_id, msg_id, seq_no, length = struct.unpack(
                "<qqqii", inner[:32]
            )
            body = inner[32:32 + length]
            if (session_id & 0xFFFFFFFFFFFFFFFF) != (self.session.session_id & 0xFFFFFFFFFFFFFFFF):
                __log__.debug("skip message from old session %016x (expected %016x)",
                              session_id & 0xFFFFFFFFFFFFFFFF, self.session.session_id & 0xFFFFFFFFFFFFFFFF)
                return
            if msg_id < self._last_mapped_msg_id:
                __log__.info("skip old msg_id %016x", msg_id)
                return
            if salt and salt != self.session.server_salt:
                __log__.info("server_salt: %016x -> %016x", self.session.server_salt, salt)
                self.session.server_salt = salt & 0xFFFFFFFFFFFFFFFF
            self._last_mapped_msg_id = msg_id
            __log__.debug("INNER msg_id=%016x seq=%d len=%d bodyid=%s (%s)",
                          msg_id & 0xFFFFFFFFFFFFFFFF, seq_no, length,
                          body[:4].hex(), body.hex()[:120])
            try:
                self._handle_message(msg_id, body)
            except Exception as e:
                __log__.error("error handling msg_id %016x: %r", msg_id, e)
    
        def _handle_message(self, msg_id: int, body: bytes):
            r = TLReader(body)
            ident = r.read_uint()
            if ident == ID_MSG_CONTAINER:
                count = r.read_int()
                for _ in range(count):
                    inner_id = r.read_long()
                    inner_seq = r.read_int()
                    inner_len = r.read_int()
                    inner_body = r.read(inner_len)
                    self._handle_message(inner_id, inner_body)
                return
            if ident == ID_RPC_RESULT:
                req_msg_id = r.read_long()
                self._handle_rpc_result(req_msg_id, r)
                return
            if ident == ID_MSGS_ACK:
                return
            if ident == ID_BAD_SERVER_SALT:
                self._handle_bad_server_salt(r)
                return
            if ident == ID_BAD_MSG_NOTIFICATION:
                self._handle_bad_msg(r)
                return
            if ident == ID_NEW_SESSION_CREATED:
                r.read_long()  # first_msg_id
                new_salt = r.read_long()
                __log__.info("new_session_created: salt=%016x", new_salt)
                self.session.server_salt = new_salt & 0xFFFFFFFFFFFFFFFF
                return
            if ident == ID_PONG:
                return
            if ident == ID_GZIP_PACKED:
                packed = r.read_bytes()
                uncompressed = zlib.decompress(packed)
                self._handle_message(msg_id, uncompressed)
                return
            # push-update (или неизвестный системный объект)
            self._dispatch_push(body)
    
        def _dispatch_push(self, body: bytes):
            r = TLReader(body)
            try:
                obj = self._decode_generic(r)
            except TLParseError as e:
                __log__.warning("cannot parse update (raw=%s): %r", body.hex(), e)
                try:
                    import os, tempfile
                    with open(os.path.join(tempfile.gettempdir(), "wg_update_dump.log"), "ab") as f:
                        f.write(body.hex().encode() + b"\n")
                except Exception:
                    pass
                return
            handler = self.on_push
            if handler:
                try:
                    asyncio.get_event_loop().create_task(handler(obj))
                except Exception as e:
                    __log__.error("push handler error: %r", e)
    
        def _decode_generic(self, r: TLReader):
            ident = r.read_uint()
            desc = self._schema.by_id(ident)
            if desc is None:
                raise TLParseError("unknown constructor 0x%08x" % ident)
            return self.unpack_object(decode_constructor(r, desc, self._schema))
    
        @staticmethod
        def _is_gzip(obj) -> bool:
            if not isinstance(obj, dict):
                return False
            if obj.get("_id") == ID_GZIP_PACKED:
                return True
            return str(obj.get("_", "")).lower() == "gzip_packed"
    
        def unpack_object(self, obj, depth=0):
            """Распаковывает gzip_packed и декодирует то, что внутри.
    
            Сервер заворачивает крупные ответы (messages.getDialogs и др.)
            в gzip_packed: он приходит полем result у rpc_result, поэтому
            проверка по сигнатуре тела ответа его не ловит.
            """
            while depth < 4 and self._is_gzip(obj):
                packed = obj.get("packed_data") or obj.get("bytes") or b""
                raw = inflate(packed)
                rr = TLReader(raw)
                desc = self._schema.by_id(rr.read_uint())
                if desc is None:
                    raise TLParseError("unknown constructor inside gzip_packed")
                obj = decode_constructor(rr, desc, self._schema)
                depth += 1
            return obj
    
        def _handle_rpc_result(self, req_msg_id: int, r: TLReader):
            raw = bytes(r.data[r.pos:])
            item = self._pending.get(req_msg_id)
            if item is None:
                __log__.debug("rpc_result for unknown msg_id %016x", req_msg_id)
                return
            fut = item["future"]
            if item["raw"]:
                fut.set_result(raw)
                self._pending.pop(req_msg_id, None)
                return
            body = raw
            if body[:4] == GZIP_MAGIC_LE:
                pack_r = TLReader(body)
                pack_r.read_uint()
                body = inflate(pack_r.read_bytes())
            rr = TLReader(body)
            ident = rr.read_uint()
            if ident == ID_RPC_ERROR:
                err = decode_constructor(rr, _DESC_RPC_ERROR, self._schema)
                code = int(err.get("error_code", -1))
                message = err.get("error_message", "RPC error %d" % code)
                resolved = _map_rpc_error(code, message)
                fut.set_exception(resolved)
                self._pending.pop(req_msg_id, None)
                return
            desc = self._schema.by_id(ident)
            if desc is None:
                fut.set_exception(
                    RPCError(0, "unknown result constructor 0x%08x (raw=%s)" % (ident, body.hex()))
                )
                self._pending.pop(req_msg_id, None)
                return
            try:
                obj = decode_constructor(rr, desc, self._schema)
                obj = self.unpack_object(obj)
            except TLParseError as e:
                fut.set_exception(
                    RPCError(0, "parse failed for 0x%08x: %s (raw=%s)" % (ident, e, body.hex()))
                )
                self._pending.pop(req_msg_id, None)
                return
            fut.set_result((desc["name"], obj))
            self._pending.pop(req_msg_id, None)
    
        def _handle_bad_server_salt(self, r: TLReader):
            bad_msg_id = r.read_long()
            r.read_int()      # bad_msg_seqno
            r.read_int()      # error_code
            new_salt = r.read_long()
            __log__.warning("bad_server_salt: %016x salt=%016x", bad_msg_id, new_salt)
            self.session.server_salt = new_salt & 0xFFFFFFFFFFFFFFFF
            item = self._pending.pop(bad_msg_id, None)
            if item:
                self._resend_future(item)
    
        def _handle_bad_msg(self, r: TLReader):
            bad_msg_id = r.read_long()
            r.read_int()      # bad_msg_seqno
            code = r.read_int()
            __log__.warning("bad_msg_notification: id=%016x code=%d", bad_msg_id, code)
            item = self._pending.pop(bad_msg_id, None)
            if not item:
                return
            if 16 <= code <= 19:
                self._resend_future(item)          # неверный msg_id — перепослать
                return
            item["future"].set_exception(RPCError(code, "bad_msg_notification code %d" % code))
    
        def _resend_future(self, item):
            fut = item["future"]
            body = item["body"]
            raw = item["raw"]
            new_id = self.new_msg_id()
            self._pending[new_id] = {"future": fut, "raw": raw, "body": body}
    
            async def go():
                try:
                    await self._send_encrypted(body, new_id)
                except Exception as e:
                    if not fut.done():
                        fut.set_exception(e)
            asyncio.get_event_loop().create_task(go())
    
        # ------------------------------------------------------------------ #
        #  RPC
        # ------------------------------------------------------------------ #
    
        def _wrap_request(self, schema, desc, params, first: bool) -> bytes:
            w = TLWriter()
            if first:
                init_desc = schema.by_name("initConnection")
                method_value = dict(params)
                method_value["_id"] = desc["id"]
                init_values = {
                    "_id": init_desc["id"],
                    "api_id": self.api_id,
                    "device_model": "@userbot",
                    "system_version": "UserBot Test",
                    "app_version": "12.9.0",
                    "system_lang_code": "en",
                    "lang_pack": "",
                    "lang_code": "en",
                    "proxy": None,
                    "params": None,
                    "query": method_value,
                }
                query = init_values
            else:
                query = dict(params)
                query["_id"] = desc["id"]
            inv_desc = schema.by_name("invokeWithLayer")
            enc_params = {"layer": schema.layer, "query": query}
            encode_constructor(w, inv_desc, enc_params, schema)
            return w.getvalue()
    
        async def rpc(self, method_name, params, schema=None, first=False, timeout=30):
            """Выполнить метод; возвращает (name, TLObject)."""
            schema = schema or self._schema
            desc = schema.by_name(method_name)
            if desc is None:
                raise RPCError(0, "method %r not in schema (layer %d)"
                               % (method_name, schema.layer))
            body = self._wrap_request(schema, desc, params, first)
    
            async with self._send_lock:
                msg_id = self.new_msg_id()
                future = asyncio.get_event_loop().create_future()
                self._pending[msg_id] = {"future": future, "raw": False, "body": body}
                __log__.info("rpc %s (msg_id=%016x, layer=%d, first=%s)",
                             method_name, msg_id, schema.layer, first)
                try:
                    await self._send_encrypted(body, msg_id)
                except Exception as e:
                    self._pending.pop(msg_id, None)
                    raise TransportError("failed to send %s: %r" % (method_name, e))
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                self._pending.pop(msg_id, None)
                raise TransportError("timeout waiting for %s (msg_id=%016x)" % (method_name, msg_id))
    
        async def rpc_raw(self, method_name, params, schema=None, first=False, timeout=30):
            """Как rpc, но вернёт СЫРОЙ байтовый ответ (нелити) — для определения layer."""
            schema = schema or self._schema
            desc = schema.by_name(method_name)
            if desc is None:
                raise RPCError(0, "method %r not in schema" % method_name)
            body = self._wrap_request(schema, desc, params, first)
            async with self._send_lock:
                msg_id = self.new_msg_id()
                future = asyncio.get_event_loop().create_future()
                self._pending[msg_id] = {"future": future, "raw": True, "body": body}
                __log__.info("rpc_raw %s (msg_id=%016x)", method_name, msg_id)
                try:
                    await self._send_encrypted(body, msg_id)
                except Exception as e:
                    self._pending.pop(msg_id, None)
                    raise
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                self._pending.pop(msg_id, None)
                raise TransportError("timeout waiting for %s" % method_name)
    
        # ------------------------------------------------------------------ #
        #  PLAIN handshake
        # ------------------------------------------------------------------ #
    
        async def _send_plain(self, body: bytes) -> None:
            msg_id = self.new_msg_id()
            header = b"\x00" * 8 + _le8(msg_id) + _le4(len(body))
            await self.transport.send(header + body)
    
        async def _recv_plain(self, timeout=15) -> bytes:
            frame = await asyncio.wait_for(self.transport.recv(), timeout=timeout)
            __log__.info("plain recv first8=%s len=%d", frame[:8].hex(), len(frame))
            if len(frame) < 20:
                raise TransportError("short plain frame: %d bytes" % len(frame))
            if frame[:8] != b"\x00" * 8:
                raise TransportError("expected plain message, got encrypted frame")
            length = struct.unpack("<i", frame[16:20])[0]
            return frame[20:20 + length]
    
        async def handshake(self, good_prime_hex: str, rsa_key, dc_id: int = 2,
                        use_legacy_pad: bool = False):
            """Полный DH-обмен (req_pq_multi -> resPQ -> req_DH_params -> set_client_DH_params)."""
            if self.session.auth_key:
                __log__.info("handshake skipped: auth_key already present")
                self._handshake_done = True
                return
            core = schema_for(167)
    
            # 1. req_pq_multi
            nonce = os.urandom(16)
            __log__.info("handshake: req_pq_multi nonce=%s", nonce.hex())
            w = TLWriter()
            w.write_int(ID_REQ_PQ_MULTI)
            w.write_int128(nonce)
            await self._send_plain(w.getvalue())
    
            resp = await self._recv_plain()
            r = TLReader(resp)
            cid = r.read_uint()
            if cid != ID_RES_PQ:
                raise AuthKeyError("expected resPQ, got 0x%08x (raw=%s)" % (cid, resp.hex()))
            recv_nonce = r.read_int128()
            server_nonce = r.read_int128()
            pq = r.read_bytes()
            if r.read_uint() != 0x1CB5C415:
                raise AuthKeyError("resPQ: expected fingerprint vector header")
            n_fps = r.read_int()
            fingerprints = [r.read_long() for _ in range(n_fps)]
            fps_unsigned = [int(fp) & 0xFFFFFFFFFFFFFFFF for fp in fingerprints]
            __log__.info("handshake: resPQ ok nonce=%s server_nonce=%s pq=%s fps=%s",
                         recv_nonce.hex(), server_nonce.hex(), pq.hex(),
                         [hex(f) for f in fps_unsigned])
            if recv_nonce != nonce:
                raise AuthKeyError("resPQ nonce mismatch")
            if isinstance(rsa_key.fingerprint, int):
                fp_int = rsa_key.fingerprint
            else:
                fp_int = int.from_bytes(rsa_key.fingerprint, "little")
            if fp_int not in fps_unsigned:
                raise AuthKeyError(
                    "server did not offer our RSA key (fps=%s, ours=%x)"
                    % ([hex(f) for f in fps_unsigned], fp_int)
                )
    
            # 2. факторизация
            pq_int = int.from_bytes(pq, "big")
            p, q = factorize_pq(pq_int)
            __log__.info("handshake: pq factored -> p=%d q=%d", p, q)
            p_b = p.to_bytes((p.bit_length() + 7) // 8 or 1, "big")
            q_b = q.to_bytes((q.bit_length() + 7) // 8 or 1, "big")
    
            # 3. req_DH_params (RSA_PAD нового формата)
            new_nonce = os.urandom(32)
            inner_desc = core.by_name("p_q_inner_data_dc")
            inner_bytes = encode_object(inner_desc, {
                "pq": pq,
                "p": p_b,
                "q": q_b,
                "nonce": nonce,
                "server_nonce": server_nonce,
                "new_nonce": new_nonce,
                "dc": dc_id,
            }, core)
            if use_legacy_pad:
                from ..crypto.rsa import rsa_pad_legacy
                rsa_enc = rsa_pad_legacy(inner_bytes, rsa_key.key, server_nonce=server_nonce)
            else:
                rsa_enc = rsa_pad(inner_bytes, rsa_key.key)
            __log__.info("handshake: req_DH_params (encrypted %d bytes, pad=%s)",
                         len(rsa_enc), "legacy" if use_legacy_pad else "new")
    
            dh_params_desc = core.by_name("req_DH_params")
            w = TLWriter()
            encode_constructor(w, dh_params_desc, {
                "nonce": nonce,
                "server_nonce": server_nonce,
                "p": p_b,
                "q": q_b,
                "public_key_fingerprint": fp_int,
                "encrypted_data": rsa_enc,
            }, core)
            await self._send_plain(w.getvalue())
    
            resp2 = await self._recv_plain()
            r2 = TLReader(resp2)
            if r2.read_uint() != ID_SERVER_DH_PARAMS_OK:
                raise AuthKeyError("expected server_DH_params_ok")
            check_nonce = r2.read_int128()
            check_snonce = r2.read_int128()
            if check_nonce != nonce or check_snonce != server_nonce:
                raise AuthKeyError("server_DH_params_ok nonce mismatch")
            encrypted_answer = r2.read_bytes()
            __log__.info("handshake: server_DH_params_ok, decrypting inner (aes-ige)")
    
            tmp_key, tmp_iv = compute_aes_key_iv_tmp(new_nonce, server_nonce)
            dec = ige_decrypt(encrypted_answer, tmp_key, tmp_iv)
            # приватка кладёт inner data после случайного 20-байтового префикса
            id_off = dec.find(struct.pack("<I", 0xB5890DBA))
            if id_off < 0:
                raise AuthKeyError("server_DH_inner_data id not found")
            rd = TLReader(dec[id_off:])
            inner_id = rd.read_uint()
            if inner_id != 0xB5890DBA:
                raise AuthKeyError("bad server_DH_inner_data id 0x%08x" % inner_id)
            dn = rd.read_int128()
            ds = rd.read_int128()
            g = rd.read_int()
            dh_prime_b = rd.read_bytes()
            g_a_b = rd.read_bytes()
            server_time = rd.read_int()
            __log__.info("handshake: g=%d server_time=%d", g, server_time)
            if dn != nonce or ds != server_nonce:
                raise AuthKeyError("server_DH_inner_data nonce mismatch")
    
            dh_prime = int.from_bytes(dh_prime_b, "big")
            # приватка отдаёт prime в server_DH_inner_data — используем именно его
            # (в конфиге GOOD_PRIME_HEX может отличаться хвостом, сверяться нельзя)
            if not (dh_prime > 1 and dh_prime % 2 == 1):
                raise AuthKeyError("server dh_prime is invalid")
            if g not in (2, 3, 4, 5, 6, 7):
                raise AuthKeyError("server g is unsupported: %d" % g)
    
            # 4. client_DH_inner_data
            b = dh_generate_a(dh_prime, g)
            g_b_b = dh_calculate_g_b(b, g, dh_prime)
            auth_key = compute_auth_key(g_a_b, b, dh_prime)
            __log__.info("handshake: auth_key computed (%d bits)", len(auth_key) * 8)
    
            client_desc = core.by_name("client_DH_inner_data")
            client_inner = encode_object(client_desc, {
                "nonce": nonce,
                "server_nonce": server_nonce,
                "retry_id": 0,
                "g_b": g_b_b,
            }, core)
            pad_len = (16 - (20 + len(client_inner)) % 16) % 16
            client_dh = hashlib.sha1(client_inner).digest() + client_inner + os.urandom(pad_len)
            client_enc = ige_encrypt(client_dh, tmp_key, tmp_iv)
    
            set_desc = core.by_name("set_client_DH_params")
            w = TLWriter()
            encode_constructor(w, set_desc, {
                "nonce": nonce,
                "server_nonce": server_nonce,
                "encrypted_data": client_enc,
            }, core)
            await self._send_plain(w.getvalue())
    
            resp3 = await self._recv_plain()
            r3 = TLReader(resp3)
            dh_gen_id = r3.read_uint()
            g_nonce = r3.read_int128()
            g_snonce = r3.read_int128()
            if g_nonce != nonce or g_snonce != server_nonce:
                raise AuthKeyError("dh_gen nonce mismatch")
            if dh_gen_id == ID_DH_GEN_RETRY:
                raise AuthKeyError("dh_gen_retry not handled (retry not implemented)")
            if dh_gen_id == ID_DH_GEN_FAIL:
                raise AuthKeyError("dh_gen_fail")
            if dh_gen_id != ID_DH_GEN_OK:
                raise AuthKeyError("expected dh_gen_ok, got 0x%08x" % dh_gen_id)
            new_nonce_hash1 = r3.read_int128()
            expected = build_new_nonce_hash(new_nonce, 1, auth_key_aux_hash(auth_key))
            if new_nonce_hash1 != expected:
                raise AuthKeyError("new_nonce_hash1 mismatch len(%d) got=%s exp=%s resp3=%s n16=%s new_nonce=%s aux=%s" % (
                    len(resp3), new_nonce_hash1.hex(), expected.hex(), resp3.hex(),
                    nonce.hex(), new_nonce.hex(),
                    auth_key_aux_hash(auth_key).hex()))
            __log__.info("handshake: dh_gen_ok, auth key accepted")
    
            self.session.auth_key = auth_key
            self.session.auth_key_id = auth_key_id(auth_key)
            self.session.server_salt = int.from_bytes(
                bytes(a ^ b for a, b in zip(new_nonce[:8], server_nonce[:8])), "little"
            )
            self.session.session_id = int.from_bytes(os.urandom(8), "little")
            self._handshake_done = True
    
        # ------------------------------------------------------------------ #
        #  определение layer / переключение схемы
        # ------------------------------------------------------------------ #
    
        def set_schema(self, layer: int):
            self._schema = schema_for(layer)
            self.session.layer = layer
            __log__.info("schema switched to layer %d", layer)
    
        async def detect_layer(self, rsa_key=None) -> int:
            """help.getConfig + посик по эрам; возвращает объявленный layer."""
            raw = await self.rpc_raw(
                "help.getConfig", {}, first=True, timeout=30
            )
            r = TLReader(raw)
            ident = r.read_uint()
            desc_candidates = []
            for era_layer in ERA_ORDER:
                sch = schema_for(era_layer)
                desc = sch.by_id(ident)
                if desc:
                    desc_candidates.append((era_layer, desc, sch))
            if not desc_candidates:
                raise LayerMismatchError(
                    "unknown config constructor 0x%08x (raw=%s)" % (ident, raw.hex())
                )
            config_obj = None
            used_era = None
            last_err = None
            for era_layer, desc, sch in desc_candidates:
                try:
                    rr = TLReader(raw)
                    rr.read_uint()
                    config_obj = decode_constructor(rr, desc, sch)
                    used_era = era_layer
                    break
                except TLParseError as e:
                    last_err = e
            if config_obj is None:
                raise LayerMismatchError(
                    "config could not be parsed in any era (%r); raw=%s"
                    % (last_err, raw.hex())
                )
            announced = config_obj.get("layer")
            if announced is None:
                announced = used_era
            __log__.info("detect_layer: config 0x%08x (era=%d) announced layer=%s",
                         ident, used_era, announced)
            if announced < 167 or announced > 228:
                raise LayerMismatchError("server layer %s outside supported 167..228" % announced)
            self.set_schema(announced)
            return announced
    
        # ------------------------------------------------------------------ #
        #  жизнь соединения
        # ------------------------------------------------------------------ #
    
        async def start_reader(self):
            if self._reader_task is None or self._reader_task.done():
                self._reader_task = asyncio.get_event_loop().create_task(self._reader_loop())
    
        async def close(self):
            self._closed = True
            if self._reader_task and not self._reader_task.done():
                self._reader_task.cancel()
                try:
                    await self._reader_task
                except (asyncio.CancelledError, Exception):
                    pass
            try:
                self.transport.close()
            except Exception:
                pass
            for item in list(self._pending.values()):
                fut = item["future"]
                if not fut.done():
                    fut.set_exception(TransportError("connection closed"))
    
    
    _DESC_RPC_ERROR = {
        "id": ID_RPC_ERROR,
        "name": "rpc_error",
        "params": [["error_code", "int"], ["error_message", "string"]],
        "result": "RpcError",
    }
    
    
    def _map_rpc_error(code: int, message: str):
        message = message.decode("utf-8", "replace") if isinstance(message, bytes) else str(message)
        if code in (420, 429):
            return FloodWaitError(code, message)
        if message.startswith("FLOOD_WAIT_") or message.startswith("SLOWMODE_WAIT_"):
            seconds = int(message.rsplit("_", 1)[-1])
            return FloodWaitError(code, message)
        return RPCError(code, message)
