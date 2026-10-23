# APNs Live Activity Server

FastAPI service for registering ActivityKit tokens and sending Live Activity events through APNs.

## Configuration

- `apns_team_id`, `apns_key_id`, and `apns_bundle_id`: Apple Developer credentials and app identifier.
- `api_key`: server-to-server bearer credential. Keep it private; do not embed it in an iOS app.
- `app_attest_enabled`: enables anonymous iOS app authentication with Apple App Attest. API-key callers remain supported.
- `app_attest_environment`: `development` for development-signed builds and `production` for App Store/TestFlight builds.
- `app_attest_app_id`: optional App ID prefix and bundle identifier, usually `TeamID.BundleID`. Leave empty to use the configured APNs Team ID and Bundle ID.
- `app_attest_challenge_ttl_seconds`: one-time challenge lifetime, from 60 to 900 seconds.

Place the APNs key file at `/config/AuthKey.p8`. The app stores token and App Attest state in its persistent `/data` directory.

When replacing a local app install with this repository version, stop the local app before starting this one because both default to host port 8000. Copy the `.p8` key into this repository app's own `app_config` folder; app configuration folders are separated by repository and app ID.

## App Attest client flow

1. On first launch, generate an App Attest key on the device and retain its key ID in the iOS Keychain.
2. Request `POST /api/app-attest/challenge` with `{"purpose":"attestation","key_id":"<key-id>"}`.
3. Hash the decoded challenge with SHA-256 and call `DCAppAttestService.attestKey`. Send the base64 attestation object, key ID, and challenge ID to `POST /api/app-attest/attest`.
4. Save the returned `installation_id` locally. No user account is created.
5. Before each protected API request, request a fresh challenge with purpose `assertion` and the registered key ID. Serialize the API request body once as UTF-8 JSON bytes. Compute `clientDataHash = SHA256(decodedChallenge || exactRequestBodyBytes)`, then create an assertion with `DCAppAttestService.generateAssertion`.
6. Send the exact same request body and these headers: `X-App-Attest-Key-Id`, `X-App-Attest-Challenge-Id`, and `X-App-Attest-Assertion` (base64).
7. For `/api/token/register`, omit `user_id`; the server associates the token with the attested `installation_id`. Set `token_type` to `push_to_start` or `activity`, and `environment` to `sandbox` or `production` according to the APNs token.

The server checks Apple's App Attest certificate chain and nonce, app identifier, environment, credential key, assertion signature, request challenge, and increasing counter. Each challenge is single-use and expires. Re-register refreshed tokens with another assertion.

## Dual authentication

Existing API-key clients remain supported: send `Authorization: Bearer <API_KEY>` and a `user_id` in token and Live Activity request bodies. App Attest clients must not include the shared API key and omit `user_id`; the attested installation is their token namespace. Do not enable unauthenticated access on an Internet-facing deployment.

## Network access

The app listens on port 8000. Use a TLS reverse proxy and forward public HTTPS traffic to this app; do not expose port 8000 directly to the Internet.
