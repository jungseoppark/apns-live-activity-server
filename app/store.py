import sqlite3
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

