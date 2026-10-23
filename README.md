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

## Install from the Home Assistant app repository

The Home Assistant app is in `apns_live_activity_server/`. Add this Git repository in **Settings → Apps → Install app → ⋮ → Repositories**, then install **APNs Live Activity Server**. The app builds its Python 3.12 container on the HAOS host for `amd64` devices.

After installation, configure the Apple Team ID, Key ID, Bundle ID, API key, and App Attest options. Copy `AuthKey.p8` into the app's `app_configs/<repository-id>_apns_live_activity_server/` folder. The app mounts it read-only at `/config/AuthKey.p8` and stores SQLite data in its persistent `/data` directory.

The Git repository must be reachable by the Home Assistant host. Home Assistant's repository manager clones the Git URL directly, so a private GitHub repository is not accessible unless the host has authenticated Git credentials configured. Keep the Apple `.p8` key and `.env` out of Git.

For App Attest, set the environment to `development` for development-signed builds or `production` for App Store/TestFlight builds. The configured App ID is usually `<Team ID>.<Bundle ID>`; override it only if the app's App ID prefix differs from the Team ID. App Attest clients authenticate with per-installation assertions; API-key authentication remains available for backend and manual calls.

Check `http://<HOME_ASSISTANT_LAN_IP>:8000/health` on the local network. For external access, use an HTTPS reverse proxy to the app's host port; do not expose port 8000 directly.

### Expose a home test server with DDNS and HTTPS

The Compose setup includes Caddy as an HTTPS reverse proxy. Set `PUBLIC_DOMAIN` in `.env` to your complete DDNS hostname (for example, `myhost.ddnsfree.com`). Keep the API container private; only Caddy listens on ports 80 and 443. The router must forward inbound TCP 80 and 443 to the host running Docker. Caddy obtains and renews a TLS certificate automatically when the hostname resolves to your public IP and those ports are reachable.

Configure the DDNS updater to keep the hostname pointed at your current public IP, assign the Docker host a stable LAN IP, then forward TCP ports 80 and 443 to it. Check that your router has a public WAN address; if the WAN address is private or in `100.64.0.0/10`, your ISP may use CGNAT and direct port forwarding will not work. In that case use a tunnel or request a public IP from the ISP. Once DNS and forwarding are ready, run `docker compose up -d --build` and check `docker compose logs -f caddy`. Do not forward port 8000 directly.

This is suitable for controlled testing. Do not embed the shared `API_KEY` in an iOS app; production token registration should be authenticated through your app's backend or an app-user authentication scheme.

## API

Protected JSON APIs accept the bearer API key or, when enabled, a valid App Attest assertion. Tokens are stored by `(identity, token_type, environment)`: API-key callers supply `user_id`, while App Attest callers use a server-assigned installation ID. Registering a refreshed token replaces the token for that identity and environment. APNs tokens and installation IDs are not written to logs.

### Anonymous iOS authentication with App Attest

The Home Assistant app enables App Attest by default. It supports both App Attest assertions for accountless iOS clients and the existing bearer API key for backend/manual use. The iOS app must never embed the shared API key.

- `POST /api/app-attest/challenge` with `{"purpose":"attestation","key_id":"<hex key ID>"}` starts key enrollment. Use purpose `assertion` with the same key ID for each protected API request.
- `POST /api/app-attest/attest` verifies the one-time challenge, Apple certificate chain, key identifier, app ID, App Attest environment, and credential public key. The response includes a server-generated `installation_id`.
- Protected requests carry `X-App-Attest-Key-Id`, `X-App-Attest-Challenge-Id`, and base64 `X-App-Attest-Assertion` headers. The assertion covers the decoded challenge concatenated with the exact UTF-8 JSON body bytes. Challenges expire and can be used once; assertion counters must increase.
- In App Attest mode, omit `user_id`; the server associates the request with the attested installation. Register `push_to_start` and `activity` tokens separately. `sandbox`/`production` still refer to the APNs token environment, not the App Attest development/production environment.

See [the Home Assistant app guide](apns_live_activity_server/DOCS.md) for the request sequence and configuration options.

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

## Multiple apps

One server can serve multiple apps owned by the same Apple Developer team. Set the primary `apns_bundle_id` and list additional IDs in the Home Assistant app's comma-separated `additional_bundle_ids` option. All apps share the configured Team ID, Key ID, and `.p8` provider key. Include the target `bundle_id` in token registration and Live Activity start, update, and end requests for every non-primary app. App Attest challenges use that same Bundle ID; token records and App Attest identities are isolated by app.

## Tests

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install pytest
pytest -q
```

Tests mock APNs and exercise registration, environment isolation, and all three event endpoints. They do not require Apple credentials or make network requests.

## License

The project is licensed under the [MIT License](LICENSE). See
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for notices about Python
dependencies and the Apple App Attestation root certificate.
