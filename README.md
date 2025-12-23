# Qualys Fargate Scanner

Event-driven container image scanning for AWS Fargate. Triggers Qualys vulnerability scans when ECS task definitions are registered or services deployed.

## Architecture

```
ECS API (RegisterTaskDefinition / RunTask / CreateService / UpdateService)
    |
    v
CloudTrail --> EventBridge --> Step Functions
                                    |
                                    +--> Parse Event
                                    +--> Check Cache
                                    +--> Get/Create Registry
                                    +--> Submit Scan
                                    +--> Poll for Completion
                                    +--> Get Results
                                    +--> Send Notification (SNS)
```

## Prerequisites

1. Qualys Registry Sensor deployed in ECS ([qualys-registry-sensor-cft](https://github.com/nelssec/qualys-registry-sensor-cft))
2. Qualys API token with Container Security permissions
3. AWS CLI with CloudFormation permissions

## IAM Role

The Qualys Registry Sensor requires an IAM role to pull images from ECR.

### Using an Existing Role

The role must have:

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::QUALYS_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "QUALYS_EXTERNAL_ID"
        }
      }
    }
  ]
}
```

**Permissions:**
- `AmazonEC2ContainerRegistryReadOnly` managed policy

To get your Qualys account ID and external ID:
```bash
export QUALYS_API_TOKEN="your-token"
make get-qualys-info QUALYS_POD=US2
```

### Creating a New Role

Set `CREATE_ROLE=true` during deployment. The stack will fetch the Qualys account ID and external ID from the API and create the role automatically.

## Deployment

### Single Account

```bash
export QUALYS_API_TOKEN="your-token"

# With existing role
make deploy QUALYS_POD=US2 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-role

# Create new role
make deploy QUALYS_POD=US2 CREATE_ROLE=true
```

### Multi-Region

```bash
# Primary region
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1 EXISTING_ROLE_ARN=...

# Additional regions forward events to primary
make deploy-region REGION=us-west-2,eu-west-1
```

### Multi-Account (Hub-Spoke)

```bash
export QUALYS_API_TOKEN="your-token"

# Deploy hub in security account
make deploy-hub QUALYS_POD=US2 OrganizationId=o-xxxxxxxxxx EXISTING_ROLE_NAME=qualys-role

# Deploy spokes via StackSet
make deploy-spoke-stackset \
  OrganizationId=o-xxxxxxxxxx \
  OrgUnitIds=ou-xxxx-xxxxxxxx \
  SecurityAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:us-east-1:111111111111:event-bus/qualys-fargate-scanner-hub-central-bus \
  EXISTING_ROLE_NAME=qualys-role
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `QUALYS_POD` | Qualys platform | `US2` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `STACK_NAME` | CloudFormation stack name | `qualys-fargate-scanner` |
| `CREATE_ROLE` | Create new IAM role | `false` |
| `EXISTING_ROLE_ARN` | Existing role ARN (single-account) | |
| `EXISTING_ROLE_NAME` | Existing role name (hub-spoke) | |

## Commands

```bash
make help                    # Show all commands
make deploy                  # Deploy single-account stack
make deploy-region REGION=   # Add regional spokes
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

| ECS API Call | Description |
|--------------|-------------|
| `RegisterTaskDefinition` | New task definition revision |
| `RunTask` | Standalone task launched |
| `CreateService` | New service created |
| `UpdateService` | Service deployment updated |

## Workflow

1. Parse event and extract ECR image URIs
2. Check DynamoDB cache (7-day TTL, images are immutable)
3. Get or create Qualys registry connector
4. Submit on-demand scan
5. Poll for completion (60s intervals, 30 max attempts)
6. Retrieve vulnerability results
7. Send SNS notification if critical or high findings

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Workflow not triggering | Verify CloudTrail logs ECS events, check EventBridge rules |
| Registry creation failed | Verify IAM role exists and trusts Qualys account |
| Scan timeout | Increase `MaxPollAttempts` parameter |
| API errors (401/403) | Regenerate Qualys token, update Secrets Manager |

## Cost

| Component | Estimate |
|-----------|----------|
| Step Functions | $0.025 / 1000 executions |
| Lambda | $0.20 / 1000 scans |
| DynamoDB | $0.25 / million requests |
| CloudTrail | $0.10 / 100k events |

Approximately $15-25/month for 1000 deployments per day.

## License

MIT
