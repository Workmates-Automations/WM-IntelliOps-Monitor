#!/bin/bash
# Called by SSM on every push to production.
# Pulls latest code, recreates changed containers, issues/verifies LE cert, reloads nginx.
set -euo pipefail

DEPLOY_DIR="/opt/intelliops-monitor"
DOMAIN="monitor.wmintelliops.com"
CERT_EMAIL="admin@wmintelliops.com"
COMPOSE="docker compose -f ${DEPLOY_DIR}/docker-compose.yml --env-file ${DEPLOY_DIR}/.env"

cd "$DEPLOY_DIR"

echo "=== Deploy started $(date) ==="

# Pull latest code
git fetch origin production
git reset --hard origin/production
chmod +x nginx/init-cert.sh

# Recreate monitor, nginx, certbot with latest config
# --force-recreate picks up new volume mounts (certbot_certs, init-cert.sh)
$COMPOSE up -d --build --force-recreate monitor nginx certbot

# Wait for nginx to accept connections (max 60s)
echo "Waiting for nginx..."
for i in $(seq 1 12); do
  if curl -sfo /dev/null http://localhost; then
    echo "Nginx ready (${i}0s)"
    break
  fi
  sleep 5
done

# Stop renewal daemon to avoid lock-file conflict, run one-off cert issuance
$COMPOSE stop certbot 2>/dev/null || true

$COMPOSE run --rm --entrypoint certbot certbot \
  certonly --webroot -w /var/www/certbot \
  -d "$DOMAIN" \
  --email "$CERT_EMAIL" \
  --agree-tos --no-eff-email \
  --non-interactive 2>&1 \
  && echo "Certificate issued/verified" \
  || echo "NOTE: certbot skipped (cert already valid or DNS not propagated yet)"

# Restart renewal daemon
$COMPOSE start certbot 2>/dev/null || true

# Reload nginx to pick up any new cert
$COMPOSE exec -T nginx nginx -s reload 2>/dev/null || true

echo "=== Deploy complete $(date) ==="
