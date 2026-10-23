import asyncio
import base64

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


def test_app_attest_challenges_are_bound_and_single_use(tmp_path):
    store = main.TokenStore(str(tmp_path / "attest.db"))
    store.create_attest_challenge("challenge-1", "opaque", "attestation", "a" * 64, 100, 300)

    assert store.consume_attest_challenge("challenge-1", "assertion", "a" * 64, 101) is None
    assert store.consume_attest_challenge("challenge-1", "attestation", "a" * 64, 101) == "opaque"
    assert store.consume_attest_challenge("challenge-1", "attestation", "a" * 64, 102) is None


def test_api_key_and_app_attest_can_both_register_tokens(tmp_path, monkeypatch):
    class FakeAppAttest:
        def verify_request(self, key_id, challenge_id, assertion, request_body):
            assert key_id == "a" * 64
            assert challenge_id == "challenge-id"
            assert assertion == b"test-assertion"
            assert b'"token_type":"activity"' in request_body
            return "anonymous-installation-1"

    monkeypatch.setattr(main.settings, "database_path", str(tmp_path / "dual-auth.db"))
    monkeypatch.setattr(main.settings, "api_key", "test-api-key")

    async def run():
        store = main.TokenStore(main.settings.database_path)
        main.app.state.store = store
        main.app.state.app_attest = FakeAppAttest()

        api_key_response = await request(main.app, "POST", "/api/token/register", headers={
            "Authorization": "Bearer test-api-key"}, json={"user_id": "backend-user",
            "token": "ab" * 32, "token_type": "push_to_start", "environment": "sandbox"})
        assert api_key_response.status_code == 200

        app_attest_response = await request(main.app, "POST", "/api/token/register", headers={
            "X-App-Attest-Key-Id": "a" * 64,
            "X-App-Attest-Challenge-Id": "challenge-id",
            "X-App-Attest-Assertion": base64.b64encode(b"test-assertion").decode("ascii")}, json={
                "token": "cd" * 32, "token_type": "activity", "environment": "sandbox"})
        assert app_attest_response.status_code == 200
        assert store.get("backend-user", "push_to_start", "sandbox") == "ab" * 32
        assert store.get("anonymous-installation-1", "activity", "sandbox") == "cd" * 32

    asyncio.run(run())
