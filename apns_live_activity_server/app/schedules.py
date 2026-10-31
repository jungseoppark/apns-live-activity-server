import json
import sqlite3
import time
from datetime import datetime, time as local_time, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ScheduledPushStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS scheduled_pushes (
                    user_id TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    schedule_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    event TEXT NOT NULL CHECK(event IN ('start', 'update', 'end')),
                    run_at INTEGER NOT NULL,
                    anchor_at INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    repeat_rule TEXT,
                    priority INTEGER NOT NULL CHECK(priority IN (5, 10)),
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at INTEGER NOT NULL,
                    lease_until INTEGER,
                    apns_id TEXT,
                    last_error TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (user_id, bundle_id, schedule_id)
                )"""
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS scheduled_pushes_due "
                "ON scheduled_pushes(status, run_at, next_attempt_at)"
            )

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def put(
        self,
        user_id: str,
        bundle_id: str,
        schedule_id: str,
        environment: str,
        event: str,
        run_at: int,
        payload: dict[str, Any],
        repeat_rule: dict[str, Any] | None,
        priority: int,
    ) -> bool:
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                """SELECT status FROM scheduled_pushes
                   WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (user_id, bundle_id, schedule_id),
            ).fetchone()
            if existing and existing["status"] == "processing":
                return False
            db.execute(
                """INSERT INTO scheduled_pushes
                    (user_id, bundle_id, schedule_id, environment, event, run_at, anchor_at,
                     payload, repeat_rule, priority, next_attempt_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, bundle_id, schedule_id) DO UPDATE SET
                        environment=excluded.environment, event=excluded.event,
                        run_at=excluded.run_at, anchor_at=excluded.anchor_at,
                        payload=excluded.payload,
                        repeat_rule=excluded.repeat_rule,
                        priority=excluded.priority, status='pending', attempts=0,
                        next_attempt_at=excluded.next_attempt_at, lease_until=NULL,
                        apns_id=NULL, last_error=NULL, updated_at=excluded.updated_at""",
                (user_id, bundle_id, schedule_id, environment, event, run_at, run_at,
                 json.dumps(payload, separators=(",", ":")),
                 json.dumps(repeat_rule, separators=(",", ":")) if repeat_rule else None,
                 priority, run_at, now),
            )
        return True

    def get(self, user_id: str, bundle_id: str, schedule_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT schedule_id, event, run_at, repeat_rule, status, attempts, apns_id, last_error
                   FROM scheduled_pushes WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (user_id, bundle_id, schedule_id),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["repeat_rule"] = json.loads(result["repeat_rule"]) if result["repeat_rule"] else None
        return result

    def cancel(self, user_id: str, bundle_id: str, schedule_id: str) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT status FROM scheduled_pushes
                   WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (user_id, bundle_id, schedule_id),
            ).fetchone()
            if row is None:
                return "missing"
            if row["status"] in ("sent", "processing"):
                return "too_late"
            db.execute(
                """UPDATE scheduled_pushes SET status='cancelled', updated_at=?
                   WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (int(time.time()), user_id, bundle_id, schedule_id),
            )
        return "cancelled"

    def claim_due(self, now: int, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                """SELECT * FROM scheduled_pushes
                   WHERE (status='pending' AND run_at<=? AND next_attempt_at<=?)
                      OR (status='processing' AND lease_until<=?)
                   ORDER BY run_at LIMIT ?""",
                (now, now, now, limit),
            ).fetchall()
            for row in rows:
                db.execute(
                    """UPDATE scheduled_pushes SET status='processing', attempts=attempts+1,
                       lease_until=?, updated_at=?
                       WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                    (now + 60, now, row["user_id"], row["bundle_id"], row["schedule_id"]),
                )
            jobs = []
            for row in rows:
                job = dict(row)
                job["payload"] = json.loads(job["payload"])
                job["repeat_rule"] = json.loads(job["repeat_rule"]) if job["repeat_rule"] else None
                job["attempts"] += 1
                jobs.append(job)
            return jobs

    def sent(self, job: dict[str, Any], apns_id: str) -> None:
        repeat = job["repeat_rule"]
        if repeat:
            next_run = next_occurrence(job["anchor_at"], job["run_at"], repeat, int(time.time()))
            if next_run is not None:
                with self.connect() as db:
                    db.execute(
                        """UPDATE scheduled_pushes SET run_at=?, status='pending', attempts=0,
                           next_attempt_at=?, lease_until=NULL, apns_id=?, last_error=NULL,
                           updated_at=? WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                        (next_run, next_run, apns_id, int(time.time()),
                         job["user_id"], job["bundle_id"], job["schedule_id"]),
                    )
                return
        self._finish(job, "sent", apns_id=apns_id)

    def retry(self, job: dict[str, Any], now: int, error: str) -> None:
        delay = min(60, 2 ** (job["attempts"] - 1))
        status = "failed" if job["attempts"] >= 8 else "pending"
        with self.connect() as db:
            db.execute(
                """UPDATE scheduled_pushes SET status=?, next_attempt_at=?, lease_until=NULL,
                   last_error=?, updated_at=?
                   WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (status, now + delay, error[:300], now,
                 job["user_id"], job["bundle_id"], job["schedule_id"]),
            )

    def fail(self, job: dict[str, Any], now: int, error: str) -> None:
        self._finish(job, "failed", now=now, error=error[:300])

    def _finish(
        self, job: dict[str, Any], status: str, apns_id: str | None = None,
        now: int | None = None, error: str | None = None,
    ) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE scheduled_pushes SET status=?, apns_id=?, last_error=?,
                   lease_until=NULL, updated_at=?
                   WHERE user_id=? AND bundle_id=? AND schedule_id=?""",
                (status, apns_id, error, now or int(time.time()),
                 job["user_id"], job["bundle_id"], job["schedule_id"]),
            )


def next_occurrence(anchor_at: int, run_at: int, rule: dict[str, Any], now: int) -> int | None:
    timezone = ZoneInfo(rule["timezone"])
    anchor = datetime.fromtimestamp(anchor_at, timezone)
    previous = datetime.fromtimestamp(run_at, timezone)
    current = datetime.fromtimestamp(now, timezone)
    interval = rule.get("interval", 1)
    weekdays = set(rule.get("weekdays", []))
    until = rule.get("until")
    first_offset = max(1, (current.date() - previous.date()).days)
    for offset in range(first_offset, first_offset + 366 * interval * 2 + 8):
        candidate_date = previous.date() + timedelta(days=offset)
        if rule["frequency"] == "daily":
            matches = (candidate_date - anchor.date()).days % interval == 0
        else:
            anchor_week = anchor.date() - timedelta(days=anchor.isoweekday() - 1)
            week = (candidate_date - anchor_week).days // 7
            matches = week % interval == 0 and candidate_date.isoweekday() in weekdays
        if not matches:
            continue
        candidate = datetime.combine(candidate_date, local_time(previous.hour, previous.minute), timezone)
        timestamp = int(candidate.timestamp())
        if timestamp <= int(current.timestamp()):
            continue
        if until is not None and timestamp > until:
            return None
        return timestamp
    return None
