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

# ── Ensure docker compose v2 plugin is installed ──────────────────────────────
if ! docker compose version &>/dev/null 2>&1; then
  echo "docker compose plugin not found — installing..."
  if command -v dnf &>/dev/null; then
    dnf install -y docker-compose-plugin 2>/dev/null || true
  fi
  # Fallback: manual binary download
  if ! docker compose version &>/dev/null 2>&1; then
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -fsSL "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  fi
  echo "docker compose $(docker compose version)"
fi

# ── Create .env if setup.sh never completed (partial first-boot) ──────────────
if [ ! -f "${DEPLOY_DIR}/.env" ]; then
  echo ".env missing — generating from EC2 metadata..."
  REGION=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "ap-south-1")
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "036160411876")
  cat > "${DEPLOY_DIR}/.env" <<ENVEOF
AWS_REGION=${REGION}
HOME_ACCOUNT_ID=${ACCOUNT_ID}
CROSS_ACCOUNT_ROLE_NAME=CWMSessionRole
OLLAMA_MODEL=llama3.2
MONITOR_LAMBDAS=
MONITOR_DYNAMO_TABLES=IntelliOps-Tickets,IntelliOps-Alarms,IntelliOps-Sessions
INTELLIOPS_STRANDS_JOBS_BUCKET=intelliops-websiterca
DOMAIN=monitor.wmintelliops.com
CERT_EMAIL=admin@wmintelliops.com
ENVEOF
  echo ".env created"
fi

# Pull latest code
git fetch origin production
git reset --hard origin/production
chmod +x nginx/init-cert.sh

# Ensure ollama is running (start only — never recreate, image is 3.8 GB)
$COMPOSE up -d --no-recreate ollama 2>/dev/null || true

# Apply IAM inline policy update so EC2/RDS monitoring permissions stay current
echo "Refreshing IAM inline policy…"
aws iam put-role-policy \
  --role-name "IntelliOps-Monitor-EC2-Role" \
  --policy-name "IntelliOps-Monitor-Policy" \
  --policy-document file://"${DEPLOY_DIR}/iam/ec2-instance-profile-policy.json" 2>/dev/null \
  && echo "IAM policy updated" || echo "NOTE: IAM policy update skipped (may require elevated permissions)"

# Recreate monitor, multiagent, nginx, certbot with latest config.
# --no-deps: skip ollama so we never re-pull its 3.8 GB image.
# --force-recreate: picks up new volume mounts (certbot_certs, init-cert.sh).
$COMPOSE up -d --build --force-recreate --no-deps monitor multiagent nginx certbot

# Wait for nginx to accept connections (max 60s)
echo "Waiting for nginx..."
for i in $(seq 1 12); do
  if curl -sfo /dev/null http://localhost; then
    echo "Nginx ready (${i}0s)"
    break
  fi
  sleep 5
done

# If certbot has never successfully issued a cert, the live/ directory contains
# dummy files created by init-cert.sh (real files, not certbot's symlinks).
# Certbot cannot overwrite real files with its symlink structure, so it fails.
# Delete dummy files only when no renewal config exists (i.e. certbot never ran).
$COMPOSE run --rm --entrypoint /bin/sh certbot -c \
  'DOMAIN=monitor.wmintelliops.com
   if [ ! -f "/etc/letsencrypt/renewal/${DOMAIN}.conf" ]; then
     echo "No renewal config found — removing dummy cert so certbot can create real one"
     rm -rf "/etc/letsencrypt/live/${DOMAIN}" "/etc/letsencrypt/archive/${DOMAIN}"
   fi'

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
