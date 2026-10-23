#!/command/with-contenv bashio

export APNS_TEAM_ID="$(bashio::config 'apns_team_id')"
export APNS_KEY_ID="$(bashio::config 'apns_key_id')"
export APNS_BUNDLE_ID="$(bashio::config 'apns_bundle_id')"
export APNS_PRIVATE_KEY_PATH="/config/AuthKey.p8"
export DATABASE_PATH="/data/apns.db"
export API_KEY="$(bashio::config 'api_key')"
export APNS_TIMEOUT_SECONDS="$(bashio::config 'apns_timeout_seconds')"
export LOG_LEVEL="$(bashio::config 'log_level')"

if [ ! -r "$APNS_PRIVATE_KEY_PATH" ]; then
    bashio::log.error "APNs private key missing at /config/AuthKey.p8"
    exit 1
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000

