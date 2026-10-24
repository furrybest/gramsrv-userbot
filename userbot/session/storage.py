"""SQLite-хранилище сессии."""

import logging
import os
import shutil
import sqlite3
import time
from pathlib import Path

__log__ = logging.getLogger("wintergram.session")


class Storage:
    """Хранение сессии: auth_key, peer-кэш и пр.

    Таблицы:
      sessions  - одна строка с текущим состоянием сессии
      auth_keys - auth_key + auth_key_id (история)
      peers     - кэш (peer_id, access_hash, type)
    """

    def __init__(self, path=None):
        self.path = path or os.path.join(
            os.getcwd(), "wintergram_session.db"
        )
        self._db = None

    # ------------------------------------------------------------------ #
    #  целостность файла
    # ------------------------------------------------------------------ #
    @property
    def backup_path(self):
        return self.path + ".bak"

    def _readable(self, con):
        con.execute("SELECT 1 FROM auth_keys LIMIT 1").fetchone()
        con.execute("SELECT 1 FROM sessions LIMIT 1").fetchone()
        return True

    def _state_is_good(self):
        """Есть ли в файле годная сессия (есть user_id и ключ 256 байт)."""
        try:
            row = self._session_row(self._db)
            if not row or not row.get("user_id"):
                return False
            keys = self._db.execute(
                "SELECT 1 FROM auth_keys WHERE length(auth_key)=256 LIMIT 1"
            ).fetchone()
            return keys is not None
        except sqlite3.Error:
            return False

    def _make_backup(self):
        """Резервная копия последнего заведомо рабочего состояния.

        Битое/неполное состояние никогда не попадает в бэкап, иначе
        следующий запуск «закрепит» поломку.
        """
        if not self._state_is_good():
            __log__.debug("backup skipped: current session state is not usable")
            return
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > 0:
                shutil.copy2(self.path, self.backup_path)
        except OSError as e:
            __log__.debug("backup failed: %r", e)

    def _restore_backup(self):
        bak = self.backup_path
        if not os.path.exists(bak):
            return False
        try:
            con = sqlite3.connect(bak)
            try:
                self._readable(con)
            finally:
                con.close()
        except sqlite3.Error:
            return False
        try:
            shutil.copy2(bak, self.path)
        except OSError as e:
            __log__.warning("cannot restore session from backup: %r", e)
            return False
        __log__.warning("session file was broken - restored from backup")
        return True

    def _open_db(self):
        con = sqlite3.connect(self.path)
        try:
            self._readable(con)
            return con
        except sqlite3.DatabaseError as e:
            con.close()
            __log__.warning("session file is corrupt (%r)", e)
            if self._restore_backup():
                con = sqlite3.connect(self.path)
                try:
                    self._readable(con)
                    return con
                except sqlite3.DatabaseError:
                    con.close()
            # ключа не восстановить — создаём файл заново, юзербот
            # переhandshake-ится вместо падения
            __log__.error("session file unrecoverable, creating a new one")
            try:
                os.remove(self.path)
            except OSError:
                pass
            return sqlite3.connect(self.path)

    def open(self):
        if self._db is None:
            self._db = self._open_db()
            self._create_tables()
            self._make_backup()
        return self

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    def _create_tables(self):
        cur = self._db.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "  id INTEGER PRIMARY KEY,"
            "  dc_id INTEGER, server_salt INTEGER, session_id INTEGER,"
            "  auth_key_id BLOB, user_id INTEGER, layer INTEGER,"
            "  phone TEXT, transport TEXT"
            ")"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS auth_keys ("
            "  auth_key_id BLOB PRIMARY KEY, auth_key BLOB, created_at INTEGER"
            ")"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS peers ("
            "  peer_id INTEGER PRIMARY KEY, access_hash INTEGER, type TEXT"
            ")"
        )
        self._db.commit()
        cur.close()

    # ---------------- sessions ----------------
    def _session_row(self, con):
        row = con.execute("SELECT * FROM sessions ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        cols = [c[1] for c in con.execute("PRAGMA table_info(sessions)").fetchall()]
        return dict(zip(cols, row))

    def _session_row_from_backup(self):
        bak = self.backup_path
        if not os.path.exists(bak):
            return None
        try:
            con = sqlite3.connect(Path(bak).as_uri() + "?mode=ro", uri=True)
            try:
                return self._session_row(con)
            finally:
                con.close()
        except sqlite3.Error as e:
            __log__.debug("backup session unreadable: %r", e)
            return None

    def load_session(self):
        row = self._session_row(self._db)
        if row is None or not row.get("user_id"):
            # файл мог остаться без строки сессии (обрыв во время записи)
            bak = self._session_row_from_backup()
            if bak and bak.get("user_id"):
                __log__.warning("session row missing - taking it from backup")
                return bak
        return row

    def save_session(self, data: dict):
        cols = ["dc_id", "server_salt", "session_id", "auth_key_id",
                "user_id", "layer", "phone", "transport"]
        keys = [c for c in cols if c in data]
        values = [data[c] for c in keys]
        cur = self._db.cursor()
        try:
            # одна атомарная операция: таблица никогда не остаётся пустой
            cur.execute(
                "INSERT OR REPLACE INTO sessions (id, %s) VALUES (1, %s)"
                % (", ".join(keys), ", ".join("?" * len(values))),
                values,
            )
            self._db.commit()
        except sqlite3.Error as e:
            self._db.rollback()
            __log__.error("cannot save session: %r", e)
        finally:
            cur.close()

    # ---------------- auth_keys ----------------
    def load_auth_key(self, auth_key_id=None):
        """Возвращает только корректный ключ в 256 байт.

        Приоритет: ключ из строки сессии, затем самый свежий валидный.
        Битые/пустые ключи игнорируются, иначе клиент не сможет
        подключиться и потребует повторной авторизации.
        """
        try:
            rows = self._db.execute(
                "SELECT auth_key_id, auth_key, created_at FROM auth_keys"
                " ORDER BY created_at DESC"
            ).fetchall()
        except sqlite3.Error as e:
            __log__.error("cannot read auth keys: %r", e)
            return None
        valid = [
            (bytes(aid) if aid else b"", bytes(key))
            for aid, key, _ in rows
            if key is not None and len(bytes(key)) == 256
        ]
        if auth_key_id:
            wanted = bytes(auth_key_id)
            for aid, key in valid:
                if aid == wanted:
                    return key
        return valid[0][1] if valid else None

    def save_auth_key(self, auth_key: bytes, auth_key_id_hex: bytes):
        auth_key = bytes(auth_key or b"")
        if len(auth_key) != 256:
            __log__.error("refusing to save broken auth_key (%d bytes)", len(auth_key))
            return
        cur = self._db.cursor()
        try:
            cur.execute(
                "INSERT OR REPLACE INTO auth_keys (auth_key_id, auth_key, created_at)"
                " VALUES (?, ?, ?)",
                (bytes(auth_key_id_hex or b""), auth_key, int(time.time())),
            )
            self._db.commit()
        except sqlite3.Error as e:
            self._db.rollback()
            __log__.error("cannot save auth_key: %r", e)
        finally:
            cur.close()

    # ---------------- peers ----------------
    def store_peer(self, peer_id: int, access_hash: int, ptype: str):
        cur = self._db.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO peers (peer_id, access_hash, type)"
            " VALUES (?, ?, ?)",
            (peer_id, access_hash, ptype),
        )
        self._db.commit()
        cur.close()

    def get_peer(self, peer_id: int):
        cur = self._db.cursor()
        row = cur.execute(
            "SELECT access_hash, type FROM peers WHERE peer_id=?", (peer_id,)
        ).fetchone()
        cur.close()
        return row