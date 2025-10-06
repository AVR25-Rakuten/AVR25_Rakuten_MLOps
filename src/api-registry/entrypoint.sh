#!/bin/bash
set -euo pipefail



#TODO: implémenter vaultt
# Generate self-signed certs if not present
# if [ ! -f "$REGISTRY_NFQ_CERT_PATH" ] || [ ! -f "$REGISTRY_NFQ_KEY_PATH" ]; then


#   EXTRA_SANS_IP="192.168.200.1"

#   ips=$(ip -o -4 addr list | awk '{print $4}' | cut -d/ -f1)

#   # Variable pour stocker les adresses IP séparées par des virgules
#   ip_list=""

#   # Boucle pour traiter chaque adresse IP
#   for ip in $ips; do
#     if [ -z "$ip_list" ]; then
#       ip_list="$ip"
#     else
#       ip_list="$ip_list,$ip"
#     fi
#   done



#   echo "[entrypoint] Generating self-signed certs for $SERVICE_NAME ..."
#   mkdir -p "$(dirname "$REGISTRY_NFQ_CERT_PATH")"
#   openssl req -x509 -nodes -days 365 -newkey rsa:4096         -keyout "$REGISTRY_NFQ_KEY_PATH"         -out "$REGISTRY_NFQ_CERT_PATH"         -subj "/CN=$SERVICE_NAME"
#   cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_PEM_PATH" || true
#   cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_CA_PATH" || true
# fi



if [ ! -f "$REGISTRY_NFQ_CERT_PATH" ] || [ ! -f "$REGISTRY_NFQ_KEY_PATH" ]; then
  echo "[entrypoint] Generating self-signed certs for $SERVICE_NAME ..."

  mkdir -p "$(dirname "$REGISTRY_NFQ_CERT_PATH")"

  # --- Collecte des IPs locales ---
  ips=$(ip -o -4 addr list | awk '{print $4}' | cut -d/ -f1)
  # Ajoute ton IP fixe manuelle si besoin
  EXTRA_SANS_IP="192.168.200.1"
  ips="$ips $EXTRA_SANS_IP"

  # Génération de la chaîne SAN
  san_list=""
  i=1
  for ip in $ips; do
    san_list="${san_list}IP.$i = $ip"$'\n'
    ((i++))
  done

  # On ajoute aussi les SAN DNS les plus courants (utile si ton proxy est appelé par nom)
  san_list="${san_list}DNS.${i}=localhost"$'\n'
  ((i++))
  san_list="${san_list}DNS.${i}=${SERVICE_NAME}"$'\n'

  # Fichier temporaire de conf OpenSSL
  tmp_conf=$(mktemp)
  cat > "$tmp_conf" <<EOF
[req]
default_bits       = 4096
distinguished_name = req_distinguished_name
x509_extensions    = v3_req
prompt             = no

[req_distinguished_name]
CN = ${SERVICE_NAME}

[v3_req]
subjectAltName = @alt_names

[alt_names]
${san_list}
EOF

  # Génère le certificat autosigné avec les IPs en SAN
  openssl req -x509 -nodes -days 365 \
    -newkey rsa:4096 \
    -keyout "$REGISTRY_NFQ_KEY_PATH" \
    -out "$REGISTRY_NFQ_CERT_PATH" \
    -config "$tmp_conf"

  # Copie dans les emplacements attendus
  cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_PEM_PATH" || true
  cat "$REGISTRY_NFQ_CERT_PATH" > "$REGISTRY_NFQ_CA_PATH" || true

  echo "[entrypoint] Certificate generated with SANs:"
  echo "$san_list"
  rm -f "$tmp_conf"
fi




set -m
# Set log level
LOG_LEVEL=${LOG_LEVEL:-DEBUG}
export LOG_LEVEL

# Start FastAPI proxy (TLS optional)
if [ "${APP_TLS,,}" = "true" ]; then
  echo "[entrypoint] Starting FastAPI proxy (HTTPS) on ${LISTEN_HOST}:${LISTEN_PORT}"
  python3 -m uvicorn api.app:app --host "${LISTEN_HOST}" --port "${LISTEN_PORT}" --ssl-keyfile "$REGISTRY_NFQ_KEY_PATH" --ssl-certfile "$REGISTRY_NFQ_CERT_PATH" &
else
  echo "[entrypoint] Starting FastAPI proxy (HTTP) on ${LISTEN_HOST}:${LISTEN_PORT}"
  python3 -m uvicorn api.app:app --host "${LISTEN_HOST}" --port "${LISTEN_PORT}" &
fi
# Launch nginx + fcgiwrap (health only) in foreground
/usr/local/bin/nginx-fcgiwrap.sh


fg %1