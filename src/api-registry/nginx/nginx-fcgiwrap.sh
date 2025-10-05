#!/bin/bash
set -euo pipefail
SOCK="/var/run/fcgiwrap/fcgiwrap.socket"
USER="www-data"
GROUP="www-data"

mkdir -p "$(dirname "$SOCK")"
chown "$USER:$GROUP" "$(dirname "$SOCK")" || true
rm -f "$SOCK"

# Start fcgiwrap via spawn-fcgi
spawn-fcgi -s "$SOCK" -U "$USER" -G "$GROUP" -M 766 /usr/sbin/fcgiwrap

# Wait socket
for i in {1..50}; do
  [ -S "$SOCK" ] && break
  sleep 0.1
done
[ -S "$SOCK" ] || { echo "fcgiwrap socket not found: $SOCK" >&2; exit 1; }

# Generate nginx conf (health only)
/usr/local/bin/nginx-conf.sh

# Test and run nginx in foreground
nginx -t -c "$NGINX_CONFIG_FILE"
exec nginx -g 'daemon off;' -c "$NGINX_CONFIG_FILE"
