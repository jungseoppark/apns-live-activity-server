import sqlite3
import time
from pathlib import Path


class TokenStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tokens (
                user_id TEXT NOT NULL, token TEXT NOT NULL, token_type TEXT NOT NULL,
                environment TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, token_type, environment)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS app_attest_challenges (
                challenge_id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL,
                purpose TEXT NOT NULL,
                key_id TEXT,
                expires_at INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS app_attest_keys (
                key_id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL,
                environment TEXT NOT NULL,
                validation_category INTEGER,
                bundle_version TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def connect(self):
        db = sqlite3.connect(self.database_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def register(self, user_id: str, token: str, token_type: str, environment: str):
        with self.connect() as db:
            db.execute("""INSERT INTO tokens(user_id, token, token_type, environment)
                VALUES (?, ?, ?, ?) ON CONFLICT(user_id, token_type, environment)
                DO UPDATE SET token=excluded.token, updated_at=CURRENT_TIMESTAMP""",
                (user_id, token, token_type, environment))

    def get(self, user_id: str, token_type: str, environment: str):
        with self.connect() as db:
            row = db.execute("SELECT token FROM tokens WHERE user_id=? AND token_type=? AND environment=?",
                             (user_id, token_type, environment)).fetchone()
        return row["token"] if row else None

    def create_attest_challenge(self, challenge_id: str, challenge: str, purpose: str,
                                key_id: str | None, now: int, ttl_seconds: int):
        with self.connect() as db:
            db.execute("DELETE FROM app_attest_challenges WHERE expires_at <= ?", (now,))
            db.execute("""INSERT INTO app_attest_challenges
                (challenge_id, challenge, purpose, key_id, expires_at) VALUES (?, ?, ?, ?, ?)""",
                (challenge_id, challenge, purpose, key_id, now + ttl_seconds))

    def consume_attest_challenge(self, challenge_id: str, purpose: str, key_id: str, now: int):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT challenge FROM app_attest_challenges
                WHERE challenge_id=? AND purpose=? AND key_id=? AND expires_at > ?""",
                (challenge_id, purpose, key_id, now)).fetchone()
            if row:
                db.execute("DELETE FROM app_attest_challenges WHERE challenge_id=?", (challenge_id,))
            else:
                db.execute("DELETE FROM app_attest_challenges WHERE challenge_id=? AND expires_at <= ?",
                           (challenge_id, now))
            return row["challenge"] if row else None

    def register_attested_key(self, key_id: str, installation_id: str, public_key: bytes,
                              sign_count: int, environment: str, validation_category: int | None,
                              bundle_version: str | None):
        with self.connect() as db:
            db.execute("""INSERT INTO app_attest_keys
                (key_id, installation_id, public_key, sign_count, environment,
                 validation_category, bundle_version)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (key_id, installation_id, public_key, sign_count, environment,
                 validation_category, bundle_version))

    def get_attested_key(self, key_id: str):
        with self.connect() as db:
            row = db.execute("""SELECT key_id, installation_id, public_key, sign_count,
                environment, validation_category, bundle_version
                FROM app_attest_keys WHERE key_id=?""", (key_id,)).fetchone()
        return dict(row) if row else None

    def advance_attest_counter(self, key_id: str, expected_counter: int, new_counter: int) -> bool:
        with self.connect() as db:
            cursor = db.execute("""UPDATE app_attest_keys SET sign_count=?
                WHERE key_id=? AND sign_count=? AND sign_count < ?""",
                (new_counter, key_id, expected_counter, new_counter))
            return cursor.rowcount == 1
