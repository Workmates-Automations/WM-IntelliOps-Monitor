#!/bin/bash
# Creates the EC2 IAM role + instance profile for IntelliOps Monitor
# Idempotent — safe to run multiple times (checks existence before creating)
set -euo pipefail

ROLE_NAME="IntelliOps-Monitor-EC2-Role"
POLICY_NAME="IntelliOps-Monitor-Policy"
PROFILE_NAME="IntelliOps-Monitor-Profile"

# IAM is a global service — never pass --region to iam commands

# ── Role ──────────────────────────────────────────────────────────────────────
if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
  echo "Role already exists: $ROLE_NAME"
else
  echo "Creating IAM role: $ROLE_NAME"
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document file://trust-policy.json \
    --description "EC2 role for IntelliOps Monitor — cross-account CloudWatch read access"
fi

# ── Inline policy (always overwrite so updates are applied) ───────────────────
echo "Putting inline policy: $POLICY_NAME"
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$POLICY_NAME" \
  --policy-document file://ec2-instance-profile-policy.json

# ── SSM managed policy (required for SSM Run Command deployments) ─────────────
echo "Attaching AmazonSSMManagedInstanceCore…"
aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" 2>/dev/null \
  || echo "SSM policy already attached"

# ── Instance profile ──────────────────────────────────────────────────────────
if aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" &>/dev/null; then
  echo "Instance profile already exists: $PROFILE_NAME"
else
  echo "Creating instance profile: $PROFILE_NAME"
  aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME"
fi

# ── Bind role to profile ──────────────────────────────────────────────────────
EXISTING_ROLE=$(aws iam get-instance-profile \
  --instance-profile-name "$PROFILE_NAME" \
  --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null || echo "None")

if [[ "$EXISTING_ROLE" == "$ROLE_NAME" ]]; then
  echo "Role already bound to profile"
else
  echo "Adding role to instance profile…"
  aws iam add-role-to-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --role-name "$ROLE_NAME"
fi

PROFILE_ARN=$(aws iam get-instance-profile \
  --instance-profile-name "$PROFILE_NAME" \
  --query 'InstanceProfile.Arn' --output text)

echo ""
echo "IAM setup complete"
echo "  Instance Profile ARN: $PROFILE_ARN"
