import sqlite3
from pathlib import Path


class TokenStore:
    def __init__(self, database_path: str, default_bundle_id: str = ""):
        self.database_path = database_path
        self.default_bundle_id = default_bundle_id
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def _initialize(self) -> None:
        with self.connect() as db:
            token_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='tokens'"
            ).fetchone()
            if token_table:
                columns = {row[1] for row in db.execute("PRAGMA table_info(tokens)")}
                if "bundle_id" not in columns:
                    db.execute("ALTER TABLE tokens RENAME TO tokens_legacy")
                    self._create_tokens_table(db)
                    db.execute(
                        """INSERT INTO tokens(user_id, bundle_id, token, token_type, environment, updated_at)
                        SELECT user_id, ?, token, token_type, environment, updated_at FROM tokens_legacy""",
                        (self.default_bundle_id,),
                    )
                    db.execute("DROP TABLE tokens_legacy")
            else:
                self._create_tokens_table(db)

            db.execute(
                """CREATE TABLE IF NOT EXISTS app_attest_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    challenge TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    key_id TEXT,
                    bundle_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                )"""
            )
            challenge_columns = {
                row[1] for row in db.execute("PRAGMA table_info(app_attest_challenges)")
            }
            if "bundle_id" not in challenge_columns:
                db.execute("ALTER TABLE app_attest_challenges ADD COLUMN bundle_id TEXT NOT NULL DEFAULT ''")
                db.execute(
                    "UPDATE app_attest_challenges SET bundle_id=? WHERE bundle_id=''",
                    (self.default_bundle_id,),
                )

            db.execute(
                """CREATE TABLE IF NOT EXISTS app_attest_keys (
                    key_id TEXT PRIMARY KEY,
                    installation_id TEXT NOT NULL UNIQUE,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL,
                    environment TEXT NOT NULL,
                    validation_category INTEGER,
                    bundle_version TEXT,
                    bundle_id TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            key_columns = {row[1] for row in db.execute("PRAGMA table_info(app_attest_keys)")}
            if "bundle_id" not in key_columns:
                db.execute("ALTER TABLE app_attest_keys ADD COLUMN bundle_id TEXT NOT NULL DEFAULT ''")
                db.execute(
                    "UPDATE app_attest_keys SET bundle_id=? WHERE bundle_id=''",
                    (self.default_bundle_id,),
                )

    @staticmethod
    def _create_tokens_table(db: sqlite3.Connection) -> None:
        db.execute(
            """CREATE TABLE tokens (
                user_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL,
                token TEXT NOT NULL,
                token_type TEXT NOT NULL,
                environment TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, bundle_id, token_type, environment)
            )"""
        )

    def register(
        self, user_id: str, token: str, token_type: str, environment: str,
        bundle_id: str | None = None,
    ) -> None:
        bundle_id = bundle_id or self.default_bundle_id
        with self.connect() as db:
            db.execute(
                """INSERT INTO tokens(user_id, bundle_id, token, token_type, environment)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id, bundle_id, token_type, environment)
                DO UPDATE SET token=excluded.token, updated_at=CURRENT_TIMESTAMP""",
                (user_id, bundle_id, token, token_type, environment),
            )

    def get(
        self, user_id: str, token_type: str, environment: str,
        bundle_id: str | None = None,
    ) -> str | None:
        with self.connect() as db:
            if bundle_id or self.default_bundle_id:
                row = db.execute(
                    """SELECT token FROM tokens
                    WHERE user_id=? AND bundle_id=? AND token_type=? AND environment=?""",
                    (user_id, bundle_id or self.default_bundle_id, token_type, environment),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT token FROM tokens
                    WHERE user_id=? AND token_type=? AND environment=?
                    ORDER BY updated_at DESC LIMIT 1""",
                    (user_id, token_type, environment),
                ).fetchone()
            return row["token"] if row else None

    def create_attest_challenge(
        self,
        challenge_id: str,
        challenge: str,
        purpose: str,
        key_id: str | None,
        now: int,
        ttl_seconds: int,
        bundle_id: str | None = None,
    ) -> None:
        bundle_id = bundle_id or self.default_bundle_id
        with self.connect() as db:
            db.execute("DELETE FROM app_attest_challenges WHERE expires_at <= ?", (now,))
            db.execute(
                """INSERT INTO app_attest_challenges
                (challenge_id, challenge, purpose, key_id, bundle_id, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (challenge_id, challenge, purpose, key_id, bundle_id, now + ttl_seconds),
            )

    def consume_attest_challenge_record(
        self,
        challenge_id: str,
        purpose: str,
        key_id: str | None,
        now: int,
        bundle_id: str | None = None,
    ) -> dict[str, str] | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            query = """SELECT challenge, bundle_id FROM app_attest_challenges
                WHERE challenge_id=? AND purpose=? AND key_id IS ? AND expires_at > ?"""
            params: tuple[object, ...] = (challenge_id, purpose, key_id, now)
            if bundle_id is not None:
                query += " AND bundle_id=?"
                params += (bundle_id,)
            row = db.execute(query, params).fetchone()
            if row:
                db.execute("DELETE FROM app_attest_challenges WHERE challenge_id=?", (challenge_id,))
                return dict(row)
            db.execute(
                "DELETE FROM app_attest_challenges WHERE challenge_id=? AND expires_at <= ?",
                (challenge_id, now),
            )
        return None

    def consume_attest_challenge(
        self, challenge_id: str, purpose: str, key_id: str | None, now: int
    ) -> str | None:
        row = self.consume_attest_challenge_record(challenge_id, purpose, key_id, now)
        return row["challenge"] if row else None

    def register_attested_key(
        self,
        key_id: str,
        installation_id: str,
        public_key: bytes,
        sign_count: int,
        environment: str,
        validation_category: int | None,
        bundle_version: str | None,
        bundle_id: str = "",
    ) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO app_attest_keys
                (key_id, installation_id, public_key, sign_count, environment,
                 validation_category, bundle_version, bundle_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (key_id, installation_id, public_key, sign_count, environment,
                 validation_category, bundle_version, bundle_id),
            )

    def get_attested_key(self, key_id: str) -> dict[str, object] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT key_id, installation_id, public_key, sign_count,
                    environment, validation_category, bundle_version, bundle_id
                FROM app_attest_keys WHERE key_id=?""",
                (key_id,),
            ).fetchone()
            return dict(row) if row else None

    def advance_attest_counter(self, key_id: str, expected_counter: int, new_counter: int) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                """UPDATE app_attest_keys SET sign_count=?
                WHERE key_id=? AND sign_count=? AND sign_count < ?""",
                (new_counter, key_id, expected_counter, new_counter),
            )
            return cursor.rowcount == 1
