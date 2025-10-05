#!/bin/bash
set -euo pipefail

# Generate self-signed certs if not present
if [ ! -f "$REGISTRY_NFQ_CERT_PATH" ] || [ ! -f "$REGISTRY_NFQ_KEY_PATH" ]; then
  echo "[entrypoint] Generating self-signed certs for $SERVICE_NAME ..."
  mkdir -p "$(dirname "$REGISTRY_NFQ_CERT_PATH")"
  openssl req -x509 -nodes -days 365 -newkey rsa:4096         -keyout "$REGISTRY_NFQ_KEY_PATH"         -out "$REGISTRY_NFQ_CERT_PATH"         -subj "/CN=$SERVICE_NAME"
  cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_PEM_PATH" || true
  cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_CA_PATH" || true
fi


set -m
# Start FastAPI proxy (TLS optional)
if [ "${APP_TLS,,}" = "true" ]; then
  echo "[entrypoint] Starting FastAPI proxy (HTTPS) on ${LISTEN_HOST}:${LISTEN_PORT}"
  python3 -m uvicorn api.app:app --host "${LISTEN_HOST}" --port "${LISTEN_PORT}"         --ssl-keyfile "$REGISTRY_NFQ_KEY_PATH" --ssl-certfile "$REGISTRY_NFQ_CERT_PATH" &
else
  echo "[entrypoint] Starting FastAPI proxy (HTTP) on ${LISTEN_HOST}:${LISTEN_PORT}"
  python3 -m uvicorn api.app:app --host "${LISTEN_HOST}" --port "${LISTEN_PORT}" &
fi

# Launch nginx + fcgiwrap (health only) in foreground
/usr/local/bin/nginx-fcgiwrap.sh


fg %1