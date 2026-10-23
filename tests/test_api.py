import asyncio

import httpx

from app import main


class FakeAPNS:
    def __init__(self):
        self.calls = []

    async def send(self, token, environment, payload, event, timestamp=None, priority=10):
        self.calls.append((token, environment, payload, event, timestamp, priority))
        return "apns-test-id"

    async def close(self):
        pass


async def request(app, method, path, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_token_register_and_activity_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(main.settings, "database_path", str(tmp_path / "tokens.db"))
    monkeypatch.setattr(main.settings, "api_key", "")
    async def run():
        main.app.state.store = main.TokenStore(main.settings.database_path)
        fake = FakeAPNS()
        main.app.state.apns = fake
        token = "ab" * 32
        response = await request(main.app, "POST", "/api/token/register", json={"user_id": "u1", "token": token,
            "token_type": "push_to_start", "environment": "sandbox"})
        assert response.status_code == 200
        response = await request(main.app, "POST", "/api/live-activity/start", json={"user_id": "u1", "environment": "sandbox",
            "attributes_type": "OrderAttributes", "attributes": {"orderId": "o1"},
            "content_state": {"status": "Preparing"}})
        assert response.status_code == 200
        assert fake.calls[0][3] == "start"
        assert fake.calls[0][2]["aps"]["attributes"]["orderId"] == "o1"

        await request(main.app, "POST", "/api/token/register", json={"user_id": "u1", "token": "cd" * 32,
            "token_type": "activity", "environment": "sandbox"})
        for path, event in (("update", "update"), ("end", "end")):
            response = await request(main.app, "POST", f"/api/live-activity/{path}", json={"user_id": "u1",
                "environment": "sandbox", "content_state": {"status": "Done"}})
            assert response.status_code == 200
            assert fake.calls[-1][3] == event
    asyncio.run(run())


def test_environment_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(main.settings, "database_path", str(tmp_path / "tokens.db"))
    monkeypatch.setattr(main.settings, "api_key", "")
    async def run():
        main.app.state.store = main.TokenStore(main.settings.database_path)
        response = await request(main.app, "POST", "/api/live-activity/start", json={"user_id": "missing",
            "environment": "production", "attributes_type": "A", "attributes": {}, "content_state": {}})
        assert response.status_code == 404
    asyncio.run(run())


def test_health(tmp_path, monkeypatch):
    monkeypatch.setattr(main.settings, "database_path", str(tmp_path / "health.db"))
    response = asyncio.run(request(main.app, "GET", "/health"))
    assert response.json() == {"status": "ok"}
