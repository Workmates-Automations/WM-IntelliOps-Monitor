#!/bin/sh
# Runs via /docker-entrypoint.d/ before nginx starts.
# Generates a temporary self-signed cert so nginx can start on first boot.
# Certbot will replace it with a real Let's Encrypt cert shortly after.
DOMAIN="monitor.wmintelliops.com"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

if [ ! -f "${CERT_DIR}/fullchain.pem" ]; then
    echo "[init-cert] No cert found — generating temporary self-signed cert for ${DOMAIN}"
    mkdir -p "${CERT_DIR}"
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
        -keyout "${CERT_DIR}/privkey.pem" \
        -out "${CERT_DIR}/fullchain.pem" \
        -subj "/CN=${DOMAIN}" 2>/dev/null
    echo "[init-cert] Temporary cert ready — certbot will replace it"
fi
