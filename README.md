# IntelliOps Monitor — EC2 Stack

Standalone monitoring server that watches the IntelliOps platform.
Runs entirely on a single EC2 instance — no Lambda, no portal dependency.

## What's included

| Service | Description |
|---------|-------------|
| **FastAPI server** | Serves Product Monitoring + AI Monitoring APIs + dashboard HTML |
| **Ollama** | Local LLM (llama3.2) for AI-powered monitoring assistant |
| **Nginx** | Reverse proxy on port 80 |

## Dashboard tabs

- **Product Monitoring** — Lambda error rates, API Gateway latency, DynamoDB throttles, active CloudWatch alarms
- **AI Monitoring** — Agent success rates, hallucination detection, latency from S3 events
- **CloudWatch Dashboards** — Browse dashboards across accounts
- **AI Assistant** — Chat with Ollama about monitoring data

## Deployment

### Step 1 — IAM Role (run once, from your local machine)

```bash
cd iam/
bash create-role.sh
```

This creates `IntelliOps-Monitor-EC2-Role` with:
- `sts:AssumeRole` on `CWMSessionRole` (cross-account access)
- CloudWatch / Lambda / DynamoDB read in home account
- S3 read on `intelliops-websiterca/ai-monitoring/*`

### Step 2 — Launch EC2

Recommended specs:
- **Instance type**: `t3.large` (2 vCPU, 8 GB RAM) — minimum for Ollama + API
- **GPU option**: `g4dn.xlarge` for faster inference (attach GPU flag in docker-compose.yml)
- **AMI**: Amazon Linux 2023 or Ubuntu 22.04 LTS
- **Storage**: 30 GB gp3 (Ollama models ~5–8 GB)
- **IAM Instance Profile**: `IntelliOps-Monitor-Profile` (created in Step 1)
- **Security Group**: inbound 80 (HTTP), 22 (SSH) from your IP

### Step 3 — Bootstrap (EC2 User Data or SSH)

**Option A — User Data** (paste into "Advanced → User Data" during launch):
```bash
#!/bin/bash
curl -fsSL https://raw.githubusercontent.com/Workmates-Automations/WM-IntelliOps-Monitor/main/setup.sh | bash
```

**Option B — SSH after launch**:
```bash
# Copy files to EC2
scp -r . ec2-user@<EC2-IP>:/opt/intelliops-monitor/

# SSH in and run
ssh ec2-user@<EC2-IP>
cd /opt/intelliops-monitor
sudo bash setup.sh
```

### Step 4 — Access

After setup completes (≈5–10 min including model pull):
```
http://<EC2-PUBLIC-IP>        # Dashboard
http://<EC2-PUBLIC-IP>/docs   # API docs
http://<EC2-PUBLIC-IP>/health # Health check
```

## Configuration (.env)

Edit `/opt/intelliops-monitor/.env` on the EC2:

```env
AWS_REGION=ap-south-1
HOME_ACCOUNT_ID=036160411876
CROSS_ACCOUNT_ROLE_NAME=CWMSessionRole

OLLAMA_MODEL=llama3.2

# Comma-separated Lambda names to monitor
MONITOR_LAMBDAS=IntelliOps-Main-Lambda,IntelliOps-Worker-Lambda

# DynamoDB tables
MONITOR_DYNAMO_TABLES=IntelliOps-Tickets,IntelliOps-Alarms,IntelliOps-Sessions

# S3 bucket for AI monitoring events
INTELLIOPS_STRANDS_JOBS_BUCKET=intelliops-websiterca
```

After editing, restart: `docker compose restart monitor`

## Cross-account setup

Uses the same `CWMSessionRole` pattern as the portal's Nexus page.
The EC2 instance profile has `sts:AssumeRole` permission on `CWMSessionRole` in all accounts.

To add a new target account, ensure `CWMSessionRole` exists in that account with a trust policy allowing the Monitor EC2's account to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::036160411876:role/IntelliOps-Monitor-EC2-Role" },
    "Action": "sts:AssumeRole"
  }]
}
```

## Useful commands

```bash
# View logs
docker compose logs -f

# Restart everything
docker compose restart

# Pull a different Ollama model
docker exec intelliops-ollama ollama pull mistral

# Check Ollama models
docker exec intelliops-ollama ollama list
```
