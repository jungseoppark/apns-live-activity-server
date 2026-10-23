import logging
import re
import time
import base64
import binascii
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .apns import APNSError, APNSClient
from .app_attest import AppAttestService
from .config import get_settings
from .store import TokenStore

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("apns_api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = TokenStore(settings.database_path, settings.apns_bundle_id)
    app.state.apns = APNSClient(settings)
    app.state.app_attest = AppAttestService(settings, app.state.store)
    yield
    await app.state.apns.close()


app = FastAPI(title="APNs Live Activity Push-to-Start API", version="1.2.0", lifespan=lifespan)


class RegisterToken(BaseModel):
    user_id: str | None = Field(default=None, min_length=1, max_length=200)
    bundle_id: str | None = Field(default=None, min_length=1, max_length=200)
    token: str = Field(min_length=32, max_length=4096)
    token_type: Literal["push_to_start", "activity"]
    environment: Literal["sandbox", "production"]


class StartActivity(BaseModel):
    user_id: str | None = Field(default=None, min_length=1, max_length=200)
    bundle_id: str | None = Field(default=None, min_length=1, max_length=200)
    environment: Literal["sandbox", "production"]
    attributes_type: str = Field(min_length=1, max_length=200)
    attributes: dict[str, Any]
    content_state: dict[str, Any]
    alert: dict[str, Any] | None = None
    timestamp: int | None = None
    priority: Literal[5, 10] = 10


class ActivityEvent(BaseModel):
    user_id: str | None = Field(default=None, min_length=1, max_length=200)
    bundle_id: str | None = Field(default=None, min_length=1, max_length=200)
    environment: Literal["sandbox", "production"]
    content_state: dict[str, Any] | None = None
    alert: dict[str, Any] | None = None
    timestamp: int | None = None
    dismissal_date: int | None = None
    priority: Literal[5, 10] = 10


class AppAttestChallenge(BaseModel):
    purpose: Literal["attestation", "assertion"]
    key_id: str = Field(min_length=64, max_length=64)
    bundle_id: str | None = Field(default=None, min_length=1, max_length=200)


class AppAttestRegistration(BaseModel):
    key_id: str = Field(min_length=64, max_length=64)
    challenge_id: str = Field(min_length=20, max_length=100)
    attestation: str = Field(min_length=1, max_length=100_000)
    bundle_id: str | None = Field(default=None, min_length=1, max_length=200)


async def authorize(request: Request, authorization: str | None = Header(default=None),
                    attest_key_id: str | None = Header(default=None, alias="X-App-Attest-Key-Id"),
                    attest_challenge_id: str | None = Header(default=None,
                                                             alias="X-App-Attest-Challenge-Id"),
                    attest_assertion: str | None = Header(default=None, alias="X-App-Attest-Assertion")):
    key = settings.api_key
    if key and authorization == f"Bearer {key}":
        request.state.auth_mode = "api_key"
        return
    if attest_key_id and attest_challenge_id and attest_assertion:
        try:
            assertion = base64.b64decode(attest_assertion, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(status_code=401, detail="App Attest assertion is invalid") from exc
        attested = request.app.state.app_attest.verify_request(
            attest_key_id, attest_challenge_id, assertion, await request.body())
        if isinstance(attested, tuple):
            installation_id, bundle_id = attested
        else:
            installation_id, bundle_id = attested, settings.apns_bundle_id
        request.state.auth_mode = "app_attest"
        request.state.installation_id = installation_id
        request.state.bundle_id = bundle_id
        return
    if key or settings.app_attest_enabled:
        raise HTTPException(status_code=401, detail="Valid API key or App Attest assertion required")
    request.state.auth_mode = "legacy"


def resolve_user_id(request: Request, user_id: str | None) -> str:
    if getattr(request.state, "auth_mode", None) == "app_attest":
        installation_id = request.state.installation_id
        if user_id is not None and user_id != installation_id:
            raise HTTPException(status_code=403, detail="user_id does not match attested installation")
        return installation_id
    if not user_id:
        raise HTTPException(status_code=422, detail="user_id is required for API key requests")
    return user_id


def resolve_bundle_id(request: Request, bundle_id: str | None) -> str:
    resolved = bundle_id or settings.apns_bundle_id
    if resolved not in settings.bundle_ids:
        raise HTTPException(status_code=422, detail="bundle_id is not configured on this server")
    if (getattr(request.state, "auth_mode", None) == "app_attest"
            and request.state.bundle_id != resolved):
        raise HTTPException(status_code=403, detail="App Attest key belongs to another app")
    return resolved


async def store_for(request: Request) -> TokenStore:
    return request.app.state.store


async def apns_for(request: Request) -> APNSClient:
    return request.app.state.apns


def current_timestamp(value: int | None) -> int:
    return value if value is not None else int(time.time())


def token_for(store: TokenStore, user_id: str, bundle_id: str, token_type: str, environment: str) -> str:
    token = store.get(user_id, token_type, environment, bundle_id)
    if not token:
        raise HTTPException(status_code=404, detail=f"No {token_type} token registered for this user and environment")
    return token


async def send_or_raise(client: APNSClient, token: str, environment: str, bundle_id: str,
                        payload: dict[str, Any], event: str, timestamp: int | None, priority: int):
    try:
        send_for_bundle = getattr(client, "send_for_bundle", None)
        if send_for_bundle:
            apns_id = await send_for_bundle(
                token, environment, payload, event, bundle_id, timestamp, priority
            )
        else:
            apns_id = await client.send(token, environment, payload, event, timestamp, priority)
        return {"status": "sent", "apns_id": apns_id}
    except APNSError as exc:
        logger.warning("APNs rejected event=%s environment=%s status=%s reason=%s", event, environment,
                       exc.status_code, exc.reason)
        status = 502 if exc.status_code >= 500 else 400
        raise HTTPException(status_code=status, detail={"message": "APNs rejected the request", "reason": exc.reason,
                                                        "apns_status": exc.status_code}) from exc
    except Exception as exc:
        logger.exception("APNs request failed event=%s environment=%s error_type=%s", event, environment,
                         type(exc).__name__)
        raise HTTPException(status_code=502, detail="APNs request failed") from exc


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/app-attest/challenge")
async def app_attest_challenge(body: AppAttestChallenge, request: Request):
    bundle_id = resolve_bundle_id(request, body.bundle_id)
    return request.app.state.app_attest.issue_challenge(body.purpose, body.key_id, bundle_id)


@app.post("/api/app-attest/attest")
async def app_attest_register(body: AppAttestRegistration, request: Request):
    try:
        attestation = base64.b64decode(body.attestation, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="attestation must be valid base64") from exc
    return request.app.state.app_attest.register_key(
        body.key_id, body.challenge_id, attestation, body.bundle_id
    )


@app.post("/api/token/register", dependencies=[Depends(authorize)])
async def register_token(body: RegisterToken, request: Request, store: TokenStore = Depends(store_for)):
    if not re.fullmatch(r"[0-9a-fA-F]+", body.token):
        raise HTTPException(status_code=422, detail="token must be a hexadecimal APNs token")
    user_id = resolve_user_id(request, body.user_id)
    bundle_id = resolve_bundle_id(request, body.bundle_id)
    store.register(user_id, body.token.lower(), body.token_type, body.environment, bundle_id)
    logger.info("APNs token registered bundle_id=%s token_type=%s environment=%s",
                bundle_id, body.token_type, body.environment)
    return {"status": "registered", "bundle_id": bundle_id,
            "token_type": body.token_type, "environment": body.environment}


@app.post("/api/live-activity/start", dependencies=[Depends(authorize)])
async def start_activity(body: StartActivity, request: Request, store: TokenStore = Depends(store_for),
    client: APNSClient = Depends(apns_for)):
    user_id = resolve_user_id(request, body.user_id)
    bundle_id = resolve_bundle_id(request, body.bundle_id)
    token = token_for(store, user_id, bundle_id, "push_to_start", body.environment)
    aps: dict[str, Any] = {"attributes-type": body.attributes_type, "attributes": body.attributes,
                           "content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    return await send_or_raise(client, token, body.environment, bundle_id, {"aps": aps}, "start",
                               current_timestamp(body.timestamp), body.priority)


@app.post("/api/live-activity/update", dependencies=[Depends(authorize)])
async def update_activity(body: ActivityEvent, request: Request, store: TokenStore = Depends(store_for),
    client: APNSClient = Depends(apns_for)):
    user_id = resolve_user_id(request, body.user_id)
    bundle_id = resolve_bundle_id(request, body.bundle_id)
    if body.content_state is None:
        raise HTTPException(status_code=422, detail="content_state is required for update")
    token = token_for(store, user_id, bundle_id, "activity", body.environment)
    aps: dict[str, Any] = {"content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    return await send_or_raise(client, token, body.environment, bundle_id, {"aps": aps}, "update",
                               current_timestamp(body.timestamp), body.priority)


@app.post("/api/live-activity/end", dependencies=[Depends(authorize)])
async def end_activity(body: ActivityEvent, request: Request, store: TokenStore = Depends(store_for),
    client: APNSClient = Depends(apns_for)):
    user_id = resolve_user_id(request, body.user_id)
    bundle_id = resolve_bundle_id(request, body.bundle_id)
    if body.content_state is None:
        raise HTTPException(status_code=422, detail="content_state is required for end")
    token = token_for(store, user_id, bundle_id, "activity", body.environment)
    aps: dict[str, Any] = {"content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    if body.dismissal_date is not None:
        aps["dismissal-date"] = body.dismissal_date
    return await send_or_raise(client, token, body.environment, bundle_id, {"aps": aps}, "end",
                               current_timestamp(body.timestamp), body.priority)
