#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/intelliops-userdata.log) 2>&1
echo "=== IntelliOps Monitor bootstrap $(date) ==="
command -v git &>/dev/null || dnf install -y git || apt-get install -y git
git clone -b production \
  https://github.com/Workmates-Automations/WM-IntelliOps-Monitor.git \
  /opt/intelliops-monitor
cd /opt/intelliops-monitor
bash setup.sh
