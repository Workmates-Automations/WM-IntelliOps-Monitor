#!/bin/bash
# Creates the EC2 IAM role + instance profile for IntelliOps Monitor
# Run once from your local machine (requires AWS CLI with admin permissions)
set -euo pipefail

ROLE_NAME="IntelliOps-Monitor-EC2-Role"
POLICY_NAME="IntelliOps-Monitor-Policy"
PROFILE_NAME="IntelliOps-Monitor-Profile"
REGION="${AWS_REGION:-ap-south-1}"

echo "Creating IAM role: $ROLE_NAME"
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file://trust-policy.json \
  --description "EC2 role for IntelliOps Monitor — cross-account CloudWatch read access" \
  --region "$REGION" 2>/dev/null || echo "Role already exists"

echo "Attaching inline policy…"
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$POLICY_NAME" \
  --policy-document file://ec2-instance-profile-policy.json

echo "Creating instance profile…"
aws iam create-instance-profile \
  --instance-profile-name "$PROFILE_NAME" 2>/dev/null || echo "Profile already exists"

echo "Adding role to instance profile…"
aws iam add-role-to-instance-profile \
  --instance-profile-name "$PROFILE_NAME" \
  --role-name "$ROLE_NAME" 2>/dev/null || echo "Role already in profile"

PROFILE_ARN=$(aws iam get-instance-profile \
  --instance-profile-name "$PROFILE_NAME" \
  --query 'InstanceProfile.Arn' --output text)

echo ""
echo "✅ IAM setup complete"
echo "   Instance Profile ARN: $PROFILE_ARN"
echo ""
echo "When launching EC2, attach this instance profile."
echo "The EC2 will then be able to:"
echo "  • AssumeRole CWMSessionRole in any account"
echo "  • Read CloudWatch, Lambda, DynamoDB metrics directly in home account"
echo "  • Read AI monitoring events from S3 bucket intelliops-websiterca"
