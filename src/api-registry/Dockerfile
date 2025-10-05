FROM ubuntu:noble-20250127

ARG DEBIAN_FRONTEND=noninteractive
# Optionnel : changer de miroir APT à la build
#   docker build --build-arg APT_MIRROR=https://azure.archive.ubuntu.com/ubuntu ...
ARG APT_MIRROR=

WORKDIR /app

# ---- Variables d'env (proxy + health) ----
ENV SERVICE_NAME="registry-nfq" \
    APP_TLS="true" \
    LISTEN_HOST="0.0.0.0" \
    LISTEN_PORT="8000" \
    \
    REG_LOCAL_BASE_URL="http://internal-registry:5000" \
    TAMPON_REGISTRY="internal-registry:5000" \
    INSECURE_SRC="false" \
    INSECURE_DEST="true" \
    MAX_CONCURRENT_COPIES="4" \
    \
    # Mode mirroring (rapide par défaut: 1 arch)
    MIRROR_ALL_ARCHS="false" \
    PLATFORM_OS="linux" \
    PLATFORM_ARCH="" \
    PLATFORM_VARIANT="" \
    \
    # Nginx / fcgiwrap (health)
    NGINX_CONFIG_FILE="/etc/nginx/nginx.conf" \
    HEALTH_CHECK_FILE="/usr/local/bin/health-check.sh" \
    \
    # Certificats (partagés uvicorn/nginx)
    REGISTRY_NFQ_KEY_PATH="/etc/ssl/registry-nfq/registry-nfq.key" \
    REGISTRY_NFQ_CERT_PATH="/etc/ssl/registry-nfq/registry-nfq.crt" \
    REGISTRY_NFQ_CA_PATH="/etc/ssl/registry-nfq/registry-nfq.ca" \
    REGISTRY_NFQ_PEM_PATH="/etc/ssl/registry-nfq/registry-nfq.pem"

# ---- Dépendances système (HTTPS + retries + IPv4 + miroir optionnel) ----
RUN set -eux; \
    sed -ri 's#http://(archive|security)\.ubuntu\.com/ubuntu#https://\1.ubuntu.com/ubuntu#g' /etc/apt/sources.list || true; \
    if [ -n "$APT_MIRROR" ]; then \
      sed -ri "s#https://archive\.ubuntu\.com/ubuntu#${APT_MIRROR}#g" /etc/apt/sources.list; \
    fi; \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::ForceIPv4=true update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl jq openssl \
        python3 python3-pip \
        nginx fcgiwrap spawn-fcgi \
        skopeo \
    ; rm -rf /var/lib/apt/lists/*

# ---- Python deps ----
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# ---- Scripts (entrypoint + nginx/fcgi/health) ----
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY nginx/nginx-fcgiwrap.sh /usr/local/bin/nginx-fcgiwrap.sh
COPY nginx/nginx-conf.sh /usr/local/bin/nginx-conf.sh
COPY nginx/health-check.sh /usr/local/bin/health-check.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/nginx-fcgiwrap.sh /usr/local/bin/nginx-conf.sh /usr/local/bin/health-check.sh

# ---- Application ----
COPY api /app/api

# ---- Tests intégrés ----
COPY tests /opt/tests
RUN chmod +x /opt/tests/run-tests.sh && ln -sf /opt/tests/run-tests.sh /usr/local/bin/run-tests

EXPOSE 443 8000
ENTRYPOINT ["entrypoint.sh"]
