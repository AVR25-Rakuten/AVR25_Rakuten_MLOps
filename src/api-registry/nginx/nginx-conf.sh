#!/bin/bash
cat <<EOF > "$NGINX_CONFIG_FILE"
events { worker_connections 1024; }
http {
  log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
  access_log /dev/stdout main;
  error_log  /dev/stderr info;

  server {
    listen 443 ssl;
    server_name $SERVICE_NAME;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_certificate     $REGISTRY_NFQ_CERT_PATH;
    ssl_certificate_key $REGISTRY_NFQ_KEY_PATH;

    # Health only (via fcgi)
    location /health {
      include fastcgi_params;
      fastcgi_pass unix:/var/run/fcgiwrap/fcgiwrap.socket;
      fastcgi_param SCRIPT_FILENAME $HEALTH_CHECK_FILE;
      fastcgi_param DOCUMENT_ROOT /usr/local/bin;
      fastcgi_param SCRIPT_NAME health-check.sh;
      fastcgi_param QUERY_STRING "";
    }
  }
}
EOF
