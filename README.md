# APNs Live Activity Push-to-Start API

Python 3.12, FastAPI and Docker Compose server for registering ActivityKit push tokens and sending Live Activity `start`, `update` and `end` events through APNs HTTP/2 with provider JWT authentication.

## Requirements

- Ubuntu 22.04/24.04 (or another Docker host) with Docker Engine and the Compose plugin.
- Apple Developer team, an APNs authentication key (`.p8`), its Key ID, Team ID, and the app Bundle ID. The app must enable the Live Activities capability and request Push-to-Start authorization.
- A client app that forwards the Push-to-Start token and each activity's update token to this API. APNs tokens identify the app installation; register refreshed tokens again.

## Configure and run

```bash
cp .env.example .env
mkdir -p secrets
cp /path/to/AuthKey_ABCDEFGHIJ.p8 secrets/AuthKey.p8
chmod 600 secrets/AuthKey.p8
```

Edit `.env`: set `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_BUNDLE_ID`, and a long random `API_KEY`. Keep the `.p8` file out of source control. Then start the service:

```bash
docker compose up -d --build
docker compose logs -f apns-api
curl http://localhost:8000/health
```

The API requires `Authorization: Bearer <API_KEY>` when `API_KEY` is non-empty. Configure a reverse proxy with TLS and firewall the application port from public access where possible. SQLite token data persists in the `apns-data` Docker volume. `sandbox` requests use `api.sandbox.push.apple.com`; `production` requests use `api.push.apple.com`. Environments are separate in token storage; the caller must select the environment matching the token issued by iOS.

## Install on Home Assistant OS

HAOS uses Supervisor-managed apps (formerly add-ons), not the standalone Compose deployment. This repository includes a local app build for the NUC's `amd64` architecture and Python 3.12.

1. Install the Home Assistant **Samba share** app or **Terminal & SSH** app if needed.
2. Copy only `config.yaml`, `Dockerfile.amd64`, `run.sh`, `requirements.txt`, and the `app/` folder into `local_apps/apns_live_activity_server`. Do not copy `.env`, `.p8` files, `.venv`, or the Compose Caddy configuration.
3. Copy the Apple key to `app_configs/local_apns_live_activity_server/AuthKey.p8`. This is the app's private configuration directory; do not put the key in a GitHub repository or a public share. The app mounts this directory read-only at `/config`.
4. In Home Assistant, open **Settings → Apps → Install app**, refresh/check for updates, then install **APNs Live Activity Server** under **Local apps**.
5. Open the app's Configuration tab and enter the Team ID, Key ID, Bundle ID, and a long random API key (at least 32 characters). Save, then start the app.
6. Check `http://<HOME_ASSISTANT_LAN_IP>:8000/health`. If port 8000 is already taken, change the host port in the app's network/port settings and use that port in the URL.

The app stores its SQLite database in its persistent `/data` directory. Its API is HTTP on the local network in this setup. For access from outside your home, route a hostname through your existing HTTPS reverse proxy to the add-on's host port; do not expose the API over plain HTTP. The app uses the Home Assistant base Python 3.12 image and is limited to `amd64` devices.

### Expose a home test server with DDNS and HTTPS

The Compose setup includes Caddy as an HTTPS reverse proxy. Set `PUBLIC_DOMAIN` in `.env` to your complete DDNS hostname (for example, `myhost.ddnsfree.com`). Keep the API container private; only Caddy listens on ports 80 and 443. The router must forward inbound TCP 80 and 443 to the host running Docker. Caddy obtains and renews a TLS certificate automatically when the hostname resolves to your public IP and those ports are reachable.

Configure the DDNS updater to keep the hostname pointed at your current public IP, assign the Docker host a stable LAN IP, then forward TCP ports 80 and 443 to it. Check that your router has a public WAN address; if the WAN address is private or in `100.64.0.0/10`, your ISP may use CGNAT and direct port forwarding will not work. In that case use a tunnel or request a public IP from the ISP. Once DNS and forwarding are ready, run `docker compose up -d --build` and check `docker compose logs -f caddy`. Do not forward port 8000 directly.

This is suitable for controlled testing. Do not embed the shared `API_KEY` in an iOS app; production token registration should be authenticated through your app's backend or an app-user authentication scheme.

## API

All JSON APIs require the bearer header when configured. Tokens are stored by `(user_id, token_type, environment)`, so registering a refreshed token replaces that user's token for that environment. Tokens are never written to logs.

### Register a token

```http
POST /api/token/register
Content-Type: application/json
Authorization: Bearer <API_KEY>
```

```json
{
  "user_id": "user-123",
  "token": "0123abcd...",
  "token_type": "push_to_start",
  "environment": "sandbox"
}
```

`token_type` is `push_to_start` or `activity`. Register an activity's update token as `activity` after ActivityKit provides it; use this token for update/end. A single token is stored per user, type and environment. Multi-activity users should extend the storage key with an application activity identifier.

### Start

```json
POST /api/live-activity/start
{
  "user_id": "user-123",
  "environment": "production",
  "attributes_type": "OrderAttributes",
  "attributes": {"orderId": "order-456"},
  "content_state": {"status": "Preparing", "eta": "12:30"},
  "alert": {"title": "Order update", "body": "Your order is being prepared"},
  "priority": 10
}
```

`timestamp` (Unix seconds) is optional and defaults to server time. The server sends event `start` to the registered Push-to-Start token. The client app must later register the resulting ActivityKit update token.

### Update and end

Both endpoints require `user_id`, `environment`, and `content_state`. Optional fields are `alert`, `timestamp` and `priority` (`5` or `10`). End also accepts `dismissal_date` (Unix seconds).

```json
POST /api/live-activity/update
{
  "user_id": "user-123",
  "environment": "production",
  "content_state": {"status": "On the way", "eta": "12:10"}
}
```

Use the same body at `POST /api/live-activity/end` to end the activity; it sends APNs event `end`. The API responds with `{"status":"sent","apns_id":"..."}` after APNs accepts the request. This means accepted by APNs, not confirmed as displayed on device. A missing token returns 404; APNs rejection returns a sanitized error reason and its status, and server-side errors are logged without token or payload contents.

### Health

`GET /health` returns `{"status":"ok"}` and is intentionally unauthenticated for container health checks.

## Payload and APNs details

The server sends `apns-push-type: liveactivity`, topic `<Bundle ID>.push-type.liveactivity`, and an ES256 provider JWT signed with the `.p8` key. JWTs are reused for up to 50 minutes. The ActivityKit event payload is placed under `aps`; `start` includes `attributes-type`, `attributes`, and `content-state`. See [Apple's ActivityKit push notification guide](https://developer.apple.com/documentation/ActivityKit/starting-and-updating-live-activities-with-activitykit-push-notifications) and [APNs request requirements](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns).

## Tests

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install pytest
pytest -q
```

Tests mock APNs and exercise registration, environment isolation, and all three event endpoints. They do not require Apple credentials or make network requests.
