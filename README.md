# Qualys Fargate Scanner

Event-driven container vulnerability scanning for AWS ECS/Fargate workloads. Automatically triggers Qualys Container Security scans when task definitions are registered or services deployed.

## Features

- **Event-Driven**: CloudTrail + EventBridge triggers scans on ECS deployments
- **Multi-Account**: Hub-spoke architecture for AWS Organizations
- **Multi-Region**: Forward events from any region to a central processor
- **Encrypted**: KMS encryption for all data at rest (S3, DynamoDB, SNS, Secrets Manager, CloudTrail)
- **Secure**: IAM least privilege, external ID validation, optional VPC deployment
- **Observable**: X-Ray tracing, CloudWatch logging, SNS notifications

## Architecture

```
ECS API Call ──> CloudTrail ──> EventBridge ──> Step Functions
                                                     │
                                                     ├── Parse Event
                                                     ├── Check Cache (DynamoDB)
                                                     ├── Get/Create Registry
                                                     ├── Submit Scan
                                                     ├── Poll for Completion
                                                     ├── Get Results
                                                     └── Notify (SNS)
```

## Prerequisites

1. [Qualys Registry Sensor](https://github.com/nelssec/qualys-registry-sensor-cft) deployed
2. Qualys API token with Container Security permissions
3. AWS CLI configured with CloudFormation permissions

## Quick Start

### Single Account

```bash
export QUALYS_API_TOKEN="your-token"

# Using existing IAM role
make deploy QUALYS_POD=US2 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-ecr-role

# Create new IAM role automatically
make deploy QUALYS_POD=US2 CREATE_ROLE=true
```

### Multi-Region

```bash
# Deploy primary region
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1 EXISTING_ROLE_ARN=...

# Add regional spokes (events forwarded to primary)
make deploy-region REGION=us-west-2,eu-west-1
```

### Multi-Account (Hub-Spoke)

```bash
# Deploy hub in security account
make deploy-hub QUALYS_POD=US2 OrganizationId=o-xxxxxxxxxx EXISTING_ROLE_NAME=qualys-ecr-role

# Deploy spokes via StackSet
make deploy-spoke-stackset \
  OrganizationId=o-xxxxxxxxxx \
  OrgUnitIds=ou-xxxx-xxxxxxxx \
  SecurityAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:us-east-1:111111111111:event-bus/qualys-fargate-hub-central-bus \
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

### Encryption
- **S3**: KMS encryption with bucket keys, versioning, access logging
- **DynamoDB**: KMS encryption, point-in-time recovery, deletion protection
- **SNS**: KMS encryption for notifications
- **Secrets Manager**: KMS encryption for Qualys credentials
- **CloudTrail**: KMS encryption with log file validation

### IAM
- Lambda roles use least privilege with resource-scoped permissions
- Qualys access protected by external ID (confused deputy protection)
- Optional VPC deployment for network isolation

### Compliance
- S3 public access blocked on all buckets
- HTTPS enforced via bucket policy
- CloudTrail log integrity validation enabled
- All resources tagged for governance

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `QUALYS_POD` | Qualys platform (US1, US2, US3, US4, EU1, EU2, IN1, CA1, AE1, UK1, AU1) | `US2` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `STACK_NAME` | CloudFormation stack name | `qualys-fargate-scanner` |
| `CREATE_ROLE` | Create new IAM role for Qualys | `false` |
| `EXISTING_ROLE_ARN` | Existing role ARN (single-account) | |
| `EXISTING_ROLE_NAME` | Existing role name (hub-spoke) | |
| `NOTIFICATION_EMAIL` | Email for scan alerts | |

## Commands

```bash
make help                    # Show all commands
make deploy                  # Deploy single-account stack
make deploy-region REGION=   # Deploy regional spokes
make deploy-hub              # Deploy hub stack
make deploy-spoke            # Deploy spoke stack
make deploy-spoke-stackset   # Deploy spokes via StackSet
make update                  # Update Lambda code
make destroy                 # Delete stack
make logs                    # Tail Lambda logs
make status                  # Show stack outputs
make get-qualys-info         # Show Qualys account info
make list-registries         # List Qualys registries
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
| Cross-account events not arriving | Verify EventBus policy allows spoke account |

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
