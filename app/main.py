import logging
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .apns import APNSError, APNSClient
from .config import get_settings
from .store import TokenStore

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("apns_api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = TokenStore(settings.database_path)
    app.state.apns = APNSClient(settings)
    yield
    await app.state.apns.close()


app = FastAPI(title="APNs Live Activity Push-to-Start API", version="1.0.0", lifespan=lifespan)


class RegisterToken(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    token: str = Field(min_length=32, max_length=4096)
    token_type: Literal["push_to_start", "activity"]
    environment: Literal["sandbox", "production"]


class StartActivity(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    environment: Literal["sandbox", "production"]
    attributes_type: str = Field(min_length=1, max_length=200)
    attributes: dict[str, Any]
    content_state: dict[str, Any]
    alert: dict[str, Any] | None = None
    timestamp: int | None = None
    priority: Literal[5, 10] = 10


class ActivityEvent(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    environment: Literal["sandbox", "production"]
    content_state: dict[str, Any] | None = None
    alert: dict[str, Any] | None = None
    timestamp: int | None = None
    dismissal_date: int | None = None
    priority: Literal[5, 10] = 10


async def authorize(request: Request, authorization: str | None = Header(default=None)):
    key = settings.api_key
    if not key:
        return
    if authorization != f"Bearer {key}":
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")


async def store_for(request: Request) -> TokenStore:
    return request.app.state.store


async def apns_for(request: Request) -> APNSClient:
    return request.app.state.apns


def current_timestamp(value: int | None) -> int:
    return value if value is not None else int(time.time())


def token_for(store: TokenStore, user_id: str, token_type: str, environment: str) -> str:
    token = store.get(user_id, token_type, environment)
    if not token:
        raise HTTPException(status_code=404, detail=f"No {token_type} token registered for this user and environment")
    return token


async def send_or_raise(client: APNSClient, token: str, environment: str, payload: dict[str, Any],
                        event: str, timestamp: int | None, priority: int):
    try:
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


@app.post("/api/token/register", dependencies=[Depends(authorize)])
async def register_token(body: RegisterToken, store: TokenStore = Depends(store_for)):
    if not re.fullmatch(r"[0-9a-fA-F]+", body.token):
        raise HTTPException(status_code=422, detail="token must be a hexadecimal APNs token")
    store.register(body.user_id, body.token.lower(), body.token_type, body.environment)
    logger.info("APNs token registered user_id=%s token_type=%s environment=%s", body.user_id,
                body.token_type, body.environment)
    return {"status": "registered", "token_type": body.token_type, "environment": body.environment}


@app.post("/api/live-activity/start", dependencies=[Depends(authorize)])
async def start_activity(body: StartActivity, store: TokenStore = Depends(store_for),
                         client: APNSClient = Depends(apns_for)):
    token = token_for(store, body.user_id, "push_to_start", body.environment)
    aps: dict[str, Any] = {"attributes-type": body.attributes_type, "attributes": body.attributes,
                           "content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    return await send_or_raise(client, token, body.environment, {"aps": aps}, "start",
                               current_timestamp(body.timestamp), body.priority)


@app.post("/api/live-activity/update", dependencies=[Depends(authorize)])
async def update_activity(body: ActivityEvent, store: TokenStore = Depends(store_for),
                          client: APNSClient = Depends(apns_for)):
    if body.content_state is None:
        raise HTTPException(status_code=422, detail="content_state is required for update")
    token = token_for(store, body.user_id, "activity", body.environment)
    aps: dict[str, Any] = {"content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    return await send_or_raise(client, token, body.environment, {"aps": aps}, "update",
                               current_timestamp(body.timestamp), body.priority)


@app.post("/api/live-activity/end", dependencies=[Depends(authorize)])
async def end_activity(body: ActivityEvent, store: TokenStore = Depends(store_for),
                       client: APNSClient = Depends(apns_for)):
    if body.content_state is None:
        raise HTTPException(status_code=422, detail="content_state is required for end")
    token = token_for(store, body.user_id, "activity", body.environment)
    aps: dict[str, Any] = {"content-state": body.content_state}
    if body.alert:
        aps["alert"] = body.alert
    if body.dismissal_date is not None:
        aps["dismissal-date"] = body.dismissal_date
    return await send_or_raise(client, token, body.environment, {"aps": aps}, "end",
                               current_timestamp(body.timestamp), body.priority)
