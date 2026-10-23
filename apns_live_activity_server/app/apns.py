import time
from typing import Any

import httpx
import jwt


APNS_HOSTS = {
    "sandbox": "https://api.sandbox.push.apple.com",
    "production": "https://api.push.apple.com",
}


class APNSError(Exception):
    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason
        super().__init__(reason)


class APNSClient:
    def __init__(self, settings, http_client=None):
        self.settings = settings
        self.http = http_client or httpx.AsyncClient(http2=True, timeout=settings.apns_timeout_seconds)
        self._key = None
        self._jwt = None
        self._issued_at = 0

    def _provider_token(self):
        now = int(time.time())
        if self._jwt is None or now - self._issued_at >= 50 * 60:
            self._key = self.settings.signing_key()
            self._jwt = jwt.encode(
                {"iss": self.settings.apns_team_id, "iat": now}, self._key,
                algorithm="ES256", headers={"kid": self.settings.apns_key_id},
            )
            self._issued_at = now
        return self._jwt

    async def send(self, token: str, environment: str, payload: dict[str, Any], event: str,
                   timestamp: int | None = None, priority: int = 10):
        host = APNS_HOSTS[environment]
        headers = {
            "authorization": f"bearer {self._provider_token()}",
            "apns-topic": f"{self.settings.apns_bundle_id}.push-type.liveactivity",
            "apns-push-type": "liveactivity",
            "apns-priority": str(priority),
        }
        aps = payload.setdefault("aps", {})
        if timestamp is not None:
            aps["timestamp"] = timestamp
        aps["event"] = event
        response = await self.http.post(f"{host}/3/device/{token}", headers=headers, json=payload)
        if response.status_code != 200:
            try:
                reason = response.json().get("reason", "Unknown")
            except ValueError:
                reason = "Unknown"
            raise APNSError(response.status_code, reason)
        return response.headers.get("apns-id")

    async def close(self):
        await self.http.aclose()
