# Qualys Fargate Scanner

Event-driven container vulnerability scanning for AWS ECS/Fargate workloads. Automatically triggers Qualys Container Security scans when task definitions are registered or services deployed.

## Features

- **Event-Driven**: CloudTrail + EventBridge triggers scans on ECS deployments
- **Multi-Account**: Service/target architecture for AWS Organizations
- **Multi-Region**: Forward events from any region to a central processor
- **Encrypted**: KMS encryption for all data at rest
- **CIS Compliant**: Follows AWS security best practices
- **Observable**: X-Ray tracing, CloudWatch logging, SNS notifications

## Architecture

The solution uses two CloudFormation templates:

- **Service Account** (`service-account.yaml`): Central processing infrastructure
- **Target Account** (`target-account.yaml`): Event capture and forwarding

For single-account deployments, both templates deploy to the same account.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Target Account(s)                         │
│                                                                  │
│  ECS API Call ──> CloudTrail ──> EventBridge ──────────────────┼──┐
│                                                                  │  │
└──────────────────────────────────────────────────────────────────┘  │
                                                                      │
┌─────────────────────────────────────────────────────────────────┐  │
│                        Service Account                           │  │
│                                                                  │  │
│  Central EventBridge Bus <─────────────────────────────────────┼──┘
│           │                                                      │
│           └──> Step Functions Workflow                           │
│                      │                                           │
│                      ├── Parse Event                             │
│                      ├── Check Cache (DynamoDB)                  │
│                      ├── Get/Create Registry                     │
│                      ├── Submit Scan                             │
│                      ├── Poll for Completion                     │
│                      ├── Get Results                             │
│                      └── Notify (SNS)                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. [Qualys Registry Sensor](https://github.com/nelssec/qualys-registry-sensor-cft) deployed
2. Qualys API token with Container Security permissions
3. AWS CLI configured with CloudFormation permissions

## Quick Start

### Single Account

```bash
export QUALYS_API_TOKEN="your-token"

# Using existing IAM role (recommended)
make deploy QUALYS_POD=US2 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-ecr-role

# Create new IAM role automatically
make deploy QUALYS_POD=US2 CREATE_ROLE=true
```

### Multi-Region (Same Account)

```bash
# Deploy to primary region
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-ecr-role

# Add target stacks in additional regions
make deploy-region REGION=us-west-2,eu-west-1 EXISTING_ROLE_NAME=qualys-ecr-role
```

### Multi-Account

```bash
# 1. Deploy service account (in security/central account)
make deploy-service QUALYS_POD=US2 OrganizationId=o-xxxxxxxxxx EXISTING_ROLE_NAME=qualys-ecr-role

# Note the outputs: ServiceAccountId and CentralEventBusArn

# 2a. Deploy target to a single account
make deploy-target \
  ServiceAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:us-east-1:111111111111:event-bus/qualys-fargate-scanner-service-bus \
  EXISTING_ROLE_NAME=qualys-ecr-role

# 2b. OR deploy targets via StackSet (organization-wide)
make deploy-target-stackset \
  OrganizationId=o-xxxxxxxxxx \
  OrgUnitIds=ou-xxxx-xxxxxxxx \
  ServiceAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:us-east-1:111111111111:event-bus/qualys-fargate-scanner-service-bus \
  EXISTING_ROLE_NAME=qualys-ecr-role
```

## IAM Role Requirements

The Qualys Registry Sensor requires an IAM role to pull images from ECR.

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::QUALYS_ACCOUNT_ID:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "QUALYS_EXTERNAL_ID" } }
  }]
}
```

**Permissions:** `AmazonEC2ContainerRegistryReadOnly` managed policy

Get your Qualys account info:
```bash
make get-qualys-info QUALYS_POD=US2
```

## Security

### Encryption at Rest

| Resource | Encryption |
|----------|------------|
| S3 (CloudTrail logs) | KMS with bucket keys |
| S3 (Access logs) | AES-256 |
| DynamoDB (scan cache) | KMS |
| SNS (notifications) | KMS |
| Secrets Manager (credentials) | KMS |
| CloudTrail | KMS with log file validation |
| CloudWatch Logs | KMS |

### CIS Benchmark Compliance

| Control | Implementation |
|---------|----------------|
| S3 public access | Blocked on all buckets |
| S3 HTTPS enforcement | Deny insecure transport policy |
| S3 versioning | Enabled on CloudTrail bucket |
| S3 access logging | Enabled with dedicated bucket |
| KMS key rotation | Automatic annual rotation |
| CloudTrail validation | Log file integrity validation |
| DynamoDB recovery | Point-in-time recovery enabled |
| DynamoDB protection | Deletion protection enabled |

### IAM Least Privilege

| Permission | Resource Scope |
|------------|---------------|
| `secretsmanager:GetSecretValue` | Specific secret ARN |
| `dynamodb:GetItem`, `PutItem` | Specific table ARN |
| `sns:Publish` | Specific topic ARN |
| `kms:Decrypt`, `GenerateDataKey` | Specific KMS key ARN |
| `lambda:InvokeFunction` | Specific Lambda ARN |
| `states:StartExecution` | Specific state machine ARN |
| `events:PutEvents` | Specific event bus ARN |

### Additional Security Controls

- External ID required for Qualys cross-account access (confused deputy protection)
- CloudWatch Logs encrypted with KMS
- All resources tagged for governance
- X-Ray tracing for observability

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `QUALYS_POD` | Qualys platform (US1-4, EU1-2, IN1, CA1, AE1, UK1, AU1) | `US2` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `STACK_NAME` | CloudFormation stack name prefix | `qualys-fargate-scanner` |
| `CREATE_ROLE` | Create new IAM role for Qualys | `false` |
| `EXISTING_ROLE_ARN` | Existing role ARN (single-account) | |
| `EXISTING_ROLE_NAME` | Existing role name (multi-account/region) | |

## Commands

```bash
make help                     # Show all commands

# Single Account
make deploy                   # Deploy service + target to same account
make deploy-region REGION=    # Add targets in additional regions
make update                   # Update Lambda code
make destroy                  # Delete all stacks

# Multi-Account
make deploy-service           # Deploy service account
make deploy-target            # Deploy target account
make deploy-target-stackset   # Deploy targets via StackSet

# Operations
make logs                     # Tail Lambda logs
make status                   # Show stack outputs
make get-qualys-info          # Show Qualys account info
make list-registries          # List Qualys registries
```

## Trigger Events

| ECS API Call | Trigger |
|--------------|---------|
| `RegisterTaskDefinition` | New task definition revision |
| `RunTask` | Standalone task launched |
| `CreateService` | New service created |
| `UpdateService` | Service deployment updated |

## Workflow

1. **Parse Event** - Extract ECR image URIs from task definition
2. **Check Cache** - Skip if scanned within 7 days (images are immutable)
3. **Get Registry** - Find or create Qualys registry connector
4. **Submit Scan** - Trigger on-demand vulnerability scan
5. **Poll Status** - Wait for scan completion (configurable interval/attempts)
6. **Get Results** - Retrieve vulnerability summary
7. **Notify** - Send SNS alert for critical/high findings

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Workflow not triggering | Verify CloudTrail is logging ECS events |
| Registry creation failed | Verify IAM role trust policy includes Qualys account |
| Scan timeout | Increase `MaxPollAttempts` parameter |
| API 401/403 errors | Regenerate Qualys token, update secret |
| Cross-account events not arriving | Verify EventBus policy allows target account |

## Cost Estimate

| Component | Monthly Cost |
|-----------|-------------|
| Step Functions | ~$0.025 / 1000 executions |
| Lambda | ~$0.20 / 1000 scans |
| DynamoDB | ~$0.25 / million requests |
| CloudTrail | ~$0.10 / 100k events |
| KMS | ~$1.00 / key + $0.03 / 10k requests |

Approximately **$15-30/month** for 1000 deployments per day.

## License

MIT
