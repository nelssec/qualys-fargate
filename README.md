# Qualys Fargate Scanner

Event-driven container image scanning for AWS Fargate. Automatically triggers Qualys vulnerability scans when task definitions are registered or services are deployed.

## Architecture

```
ECS API Call (RegisterTaskDefinition / RunTask / CreateService / UpdateService)
     │
     ▼
CloudTrail ──► EventBridge ──► Step Functions Workflow
                                     │
                                     ├─► Parse Event (extract ECR images)
                                     ├─► Check Cache (skip if recently scanned)
                                     ├─► Get/Create Registry (Qualys API)
                                     ├─► Submit Scan (Qualys API)
                                     ├─► Wait & Poll (60s intervals)
                                     ├─► Get Results (Qualys API)
                                     └─► Send Notification (SNS)
```

## Prerequisites

1. **Qualys Registry Sensor** deployed in ECS (hard prerequisite)
   - Deploy using: [qualys-registry-sensor-cft](https://github.com/nelssec/qualys-registry-sensor-cft)
2. **Qualys API Token** with Container Security permissions
3. **AWS CLI** configured with appropriate permissions

## Deployment Options

### Option 1: Single Account (Single Region)

Deploy scanner to one AWS account and region:

```bash
# Set authentication (choose one)
export QUALYS_API_TOKEN="your-bearer-token"
# OR
export QUALYS_USERNAME="your-username"
export QUALYS_PASSWORD="your-password"

# Deploy (auto-fetches Qualys base account info)
make deploy QUALYS_POD=US2
```

### Option 2: Single Account (Multi-Region)

Deploy to primary region, then add additional regions:

```bash
# 1. Deploy primary stack to us-east-1
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1

# 2. Add other regions (comma-separated, events forward to primary)
make deploy-region REGION=us-west-2,eu-west-1,ap-southeast-1
```

Each regional spoke forwards ECS events to the primary region's workflow. Cost is minimal (~$1/million events).

### Option 3: Multi-Account (Hub-Spoke)

Deploy central scanner in security account, forward events from member accounts:

```bash
# Set authentication
export QUALYS_API_TOKEN="your-bearer-token"

# 1. Deploy hub in security account
make deploy-hub QUALYS_POD=US2 OrganizationId=o-xxxxxxxxxx

# 2. Deploy spokes to member accounts via StackSet
make deploy-spoke-stackset \
  QUALYS_POD=US2 \
  OrganizationId=o-xxxxxxxxxx \
  OrgUnitIds=ou-xxxx-xxxxxxxx \
  SecurityAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:us-east-1:111111111111:event-bus/qualys-fargate-scanner-hub-central-bus
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `QUALYS_API_TOKEN` | Bearer token from Qualys portal | One of these |
| `QUALYS_USERNAME` | Qualys username (generates JWT) | One of these |
| `QUALYS_PASSWORD` | Qualys password | With username |

### Make Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `QUALYS_POD` | Qualys platform (check your subscription) | `US2` |
| `AWS_REGION` | AWS region for deployment | `us-east-1` |
| `STACK_NAME` | CloudFormation stack name | `qualys-fargate-scanner` |
| `NotificationEmail` | Email for SNS notifications | (optional) |

## Make Targets

```bash
make help                 # Show all commands

# Single Account
make deploy               # Deploy to primary region
make deploy-region REGION=us-west-2,eu-west-1  # Add regions
make update               # Update Lambda code only
make destroy              # Delete primary stack
make destroy-region REGION=...  # Delete regional spoke(s)

# Multi-Account (Hub-Spoke)
make deploy-hub           # Deploy hub to security account
make deploy-spoke         # Deploy spoke to single member account
make deploy-spoke-stackset # Deploy spokes via StackSet (org-wide)

# Operations
make logs                 # Tail Lambda logs
make workflow             # Open Step Functions console
make status               # Show stack outputs
make test                 # Start workflow with test event

# Qualys
make get-qualys-info      # Show Qualys base account info
make list-registries      # List Qualys registry connectors
```

## Directory Structure

```
qualys-fargate/
├── cloudformation/
│   ├── single-account.yaml      # Primary deployment (single account)
│   ├── regional-spoke.yaml      # Multi-region support (same account)
│   ├── centralized-hub.yaml     # Hub (multi-account, security account)
│   └── centralized-spoke.yaml   # Spoke (multi-account, member accounts)
├── lambdas/
│   ├── handlers.py              # Dispatch-based Lambda handlers
│   ├── qualys_api.py            # Qualys Container Security API client
│   └── requirements.txt         # Python dependencies
├── docs/
│   └── blog-technical-architecture.md
├── Makefile
└── README.md
```

## How It Works

### Trigger Events

| ECS API Call | When It Fires |
|--------------|---------------|
| `RegisterTaskDefinition` | New task definition revision created |
| `RunTask` | Standalone task launched |
| `CreateService` | New ECS service created |
| `UpdateService` | Service deployment updated |

### Step Functions Workflow

```
ParseEvent ──► HasImages? ──► CheckCache ──► IsCached? ──► GetRegistry
                   │              │              │              │
                   ▼              │              ▼              ▼
               NoImages          │          SkipScan      SubmitScan
               (Succeed)         │          (Succeed)          │
                                 │                             ▼
                                 │                      WaitForScan ◄──┐
                                 │                             │       │
                                 │                             ▼       │
                                 │                       CheckStatus   │
                                 │                             │       │
                                 │                      EvaluateStatus─┘
                                 │                             │
                                 │                        GetResults
                                 │                             │
                                 └────────────────────► SendNotification
```

### Registry Auto-Creation

When processing an event from a new account/region:

1. Workflow generates registry name: `ecr-{account}-{region}`
2. Checks if registry exists in Qualys
3. If not found, creates it using IAM role ARN
4. Qualys Registry Sensor can now pull from that ECR

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `GET /csapi/v1.3/registry/aws-base` | Get Qualys AWS account ID and external ID |
| `GET /csapi/v1.3/registry` | Find registry by URI or name |
| `POST /csapi/v1.3/registry` | Create ECR registry (IAM role auth) |
| `POST /csapi/v1.3/registry/{uuid}/schedule` | Submit on-demand scan |
| `GET /csapi/v1.3/images/{imageId}` | Check scan status |
| `GET /csapi/v1.3/images/{imageId}/vuln` | Get vulnerability details |

## Troubleshooting

### Workflow Not Triggering
```bash
# Verify CloudTrail is logging ECS events
aws cloudtrail describe-trails

# Check EventBridge rules are enabled
make status
```

### Registry Creation Failed
```bash
# List existing registries
make list-registries

# Check IAM role exists
aws iam get-role --role-name qualys-ecr-scan-role
```

### Scan Timeout
- Large images take longer to scan
- Increase `MaxPollAttempts` parameter (default: 30 = 30 minutes)

### API Errors (401/403)
- Regenerate Qualys API token
- Update secret in Secrets Manager

## Security

- **IAM role authentication**: ECR access via cross-account role assumption
- **Qualys token in Secrets Manager**: Never logged or exposed
- **Least privilege IAM**: Lambda has minimal permissions
- **External ID protection**: Prevents confused deputy attacks
- **DynamoDB caching**: Prevents scan flooding (24h TTL)
- **Input validation**: Repository names and digests validated

## Cost Estimate

| Component | Cost Driver | Estimate |
|-----------|-------------|----------|
| Step Functions | State transitions | ~$0.025/1000 executions |
| Lambda | API call handlers | ~$0.20/1000 scans |
| DynamoDB | Read/write units | ~$0.25/million requests |
| CloudTrail | Management events | ~$0.10/100k events |
| SNS | Notifications | ~$0.50/million |

For 1000 deployments/day: ~$15-25/month (excludes Qualys licensing)

## License

MIT
