import asyncio
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx
import pytest

from app import main
from app.schedules import ScheduledPushStore, next_occurrence
from app.store import TokenStore


class FakeAPNS:
    def __init__(self):
        self.calls = []

    async def send(self, token, environment, payload, event, timestamp=None, priority=10):
        self.calls.append((token, environment, payload, event, timestamp, priority))
        return "apns-test-id"


async def request(app, method, path, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_recurring_weekdays_keep_local_time_and_respect_interval():
    timezone = ZoneInfo("Asia/Seoul")
    monday = int(datetime(2026, 11, 2, 11, 50, tzinfo=timezone).timestamp())
    rule = {"frequency": "weekly", "timezone": "Asia/Seoul", "weekdays": [1, 2, 3, 4, 5], "interval": 1}

    assert next_occurrence(monday, monday, rule, monday + 60) == int(
        datetime(2026, 11, 3, 11, 50, tzinfo=timezone).timestamp()
    )

    every_other_week = {**rule, "interval": 2}
    friday = int(datetime(2026, 11, 6, 11, 50, tzinfo=timezone).timestamp())
    assert next_occurrence(monday, friday, every_other_week, friday + 60) == int(
        datetime(2026, 11, 16, 11, 50, tzinfo=timezone).timestamp()
    )


def test_daily_recurrence_preserves_wall_time_across_dst():
    timezone = ZoneInfo("America/New_York")
    first = int(datetime(2026, 3, 7, 8, 30, tzinfo=timezone).timestamp())
    next_run = next_occurrence(first, first, {
        "frequency": "daily", "timezone": "America/New_York", "interval": 1,
    }, first + 60)

    assert next_run == int(datetime(2026, 3, 8, 8, 30, tzinfo=timezone).timestamp())


def test_schedule_store_persists_and_repeats_after_success(tmp_path):
    timezone = ZoneInfo("Asia/Seoul")
    run_at = int(datetime(2026, 11, 2, 11, 50, tzinfo=timezone).timestamp())
    repeat = {"frequency": "weekly", "timezone": "Asia/Seoul", "weekdays": [1, 2, 3, 4, 5], "interval": 1}
    store = ScheduledPushStore(str(tmp_path / "schedules.db"))
    store.put("u1", "com.example.app", "lunch", "sandbox", "start", run_at,
              {"content_state": {"menu": "rice"}}, repeat, 10)

    job = store.claim_due(run_at)[0]
    assert job["attempts"] == 1
    assert store.cancel("u1", "com.example.app", "lunch") == "too_late"
    store.sent(job, "apns-id")

    reloaded = ScheduledPushStore(str(tmp_path / "schedules.db"))
    schedule = reloaded.get("u1", "com.example.app", "lunch")
    assert schedule["status"] == "pending"
    assert schedule["run_at"] == int(datetime(2026, 11, 3, 11, 50, tzinfo=timezone).timestamp())
    assert schedule["repeat_rule"] == repeat


@pytest.mark.parametrize("event,token_type", [
    ("start", "push_to_start"),
    ("update", "activity"),
    ("end", "activity"),
])
def test_scheduled_event_uses_matching_token_and_payload(tmp_path, event, token_type):
    bundle_id = "com.example.app"
    tokens = TokenStore(str(tmp_path / f"{event}.db"), bundle_id)
    tokens.register("u1", "ab" * 32, token_type, "sandbox", bundle_id)
    schedules = ScheduledPushStore(str(tmp_path / f"{event}.db"))
    payload = {"content_state": {"status": "ready"}}
    if event == "start":
        payload.update({"attributes_type": "ExampleAttributes", "attributes": {"id": "1"},
                        "alert": {"title": "Started"}})
    if event == "end":
        payload["dismissal_date"] = 1_800_000_000
    run_at = int(time.time())
    schedules.put("u1", bundle_id, "event-1", "sandbox", event, run_at, payload, None, 10)
    job = schedules.claim_due(run_at)[0]
    apns = FakeAPNS()

    asyncio.run(main.send_scheduled_push(job, tokens, schedules, apns))

    token, environment, push, sent_event, _, priority = apns.calls[0]
    assert (token, environment, sent_event, priority) == ("ab" * 32, "sandbox", event, 10)
    assert push["aps"]["content-state"] == payload["content_state"]
    if event == "start":
        assert push["aps"]["attributes-type"] == "ExampleAttributes"
        assert push["aps"]["alert"] == payload["alert"]
    if event == "end":
        assert push["aps"]["dismissal-date"] == payload["dismissal_date"]
    assert schedules.get("u1", bundle_id, "event-1")["status"] == "sent"


def test_schedule_api_upserts_reports_and_cancels(tmp_path, monkeypatch):
    bundle_id = "com.example.app"
    monkeypatch.setattr(main.settings, "database_path", str(tmp_path / "api.db"))
    monkeypatch.setattr(main.settings, "api_key", "")
    monkeypatch.setattr(main.settings, "apns_bundle_id", bundle_id)
    monkeypatch.setattr(main.settings, "additional_bundle_ids", "")
    main.app.state.store = TokenStore(main.settings.database_path, bundle_id)
    main.app.state.scheduled_pushes = ScheduledPushStore(main.settings.database_path)
    main.app.state.store.register("u1", "ab" * 32, "push_to_start", "sandbox", bundle_id)
    run_at = int(time.time()) + 3600
    body = {
        "schedule_id": "morning-status",
        "user_id": "u1",
        "bundle_id": bundle_id,
        "environment": "sandbox",
        "event": "start",
        "run_at": run_at,
        "attributes_type": "ExampleAttributes",
        "attributes": {"id": "1"},
        "content_state": {"status": "ready"},
        "alert": {"title": "Started"},
    }

    async def exercise():
        response = await request(main.app, "PUT", "/api/live-activity/schedules", json=body)
        assert response.status_code == 200
        updated = {**body, "run_at": run_at + 60}
        response = await request(main.app, "PUT", "/api/live-activity/schedules", json=updated)
        assert response.status_code == 200
        lookup = {"schedule_id": body["schedule_id"], "user_id": "u1", "bundle_id": bundle_id}
        response = await request(main.app, "POST", "/api/live-activity/schedules/status", json=lookup)
        assert response.json()["run_at"] == run_at + 60
        response = await request(main.app, "POST", "/api/live-activity/schedules/cancel", json=lookup)
        assert response.json()["status"] == "cancelled"

    asyncio.run(exercise())
