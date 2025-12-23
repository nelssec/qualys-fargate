# Event-Driven Container Scanning for AWS Fargate

Automated vulnerability scanning for containerized workloads using Qualys Container Security, AWS Step Functions, and event-driven architecture.

## Overview

This solution automatically triggers vulnerability scans when ECS task definitions are registered or services deployed. It integrates with Qualys Container Security to scan ECR images and sends notifications for critical findings.

**Key capabilities:**
- Zero-touch scanning triggered by deployment events
- Multi-account support via hub-spoke architecture
- Multi-region event forwarding
- 7-day scan caching (container images are immutable)
- KMS encryption for all data at rest

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AWS Account                                    │
│  ┌──────────┐    ┌───────────┐    ┌─────────────┐    ┌───────────────┐ │
│  │ ECS API  │───>│CloudTrail │───>│ EventBridge │───>│Step Functions │ │
│  └──────────┘    └───────────┘    └─────────────┘    └───────┬───────┘ │
│                        │                                      │         │
│                        v                                      v         │
│                  ┌──────────┐                           ┌──────────┐   │
│                  │    S3    │                           │  Lambda  │   │
│                  │(encrypted)│                          └────┬─────┘   │
│                  └──────────┘                                │         │
│                                                              v         │
│  ┌──────────┐    ┌───────────┐    ┌─────────────┐    ┌───────────────┐ │
│  │DynamoDB  │<───│  Secrets  │<───│     KMS     │    │     SNS       │ │
│  │ (cache)  │    │  Manager  │    │             │    │(notifications)│ │
│  └──────────┘    └───────────┘    └─────────────┘    └───────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                       │
                                       v
┌─────────────────────────────────────────────────────────────────────────┐
│                         Qualys Platform                                  │
│  ┌──────────────────┐         ┌──────────────────────┐                  │
│  │ Container        │         │   Registry Sensor    │                  │
│  │ Security API     │<───────>│   (assumes IAM role) │                  │
│  └──────────────────┘         └──────────┬───────────┘                  │
└──────────────────────────────────────────┼──────────────────────────────┘
                                           │
                                           v
┌─────────────────────────────────────────────────────────────────────────┐
│                              AWS ECR                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Container Images                               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Event Detection

CloudTrail captures ECS management API calls and delivers them to EventBridge:

```yaml
EventSelectors:
  - ReadWriteType: WriteOnly
    IncludeManagementEvents: true
```

EventBridge rules match specific ECS events:

| Event | Description |
|-------|-------------|
| `RegisterTaskDefinition` | New task definition revision created |
| `RunTask` | Standalone task launched |
| `CreateService` | New ECS service created |
| `UpdateService` | Service deployment updated |

EventBridge input transformer extracts relevant fields and passes them to Step Functions:

```json
{
  "trigger_type": "RegisterTaskDefinition",
  "task_definition_arn": "arn:aws:ecs:...",
  "containers": [...],
  "account_id": "123456789012",
  "region": "us-east-1"
}
```

## Step Functions Workflow

```
                    ┌─────────────┐
                    │ ParseEvent  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  HasImages  │
                    └──────┬──────┘
                     no /  │  \ yes
                   ┌──────┘    └──────┐
                   │                   │
            ┌──────▼──────┐    ┌──────▼──────┐
            │  NoImages   │    │ CheckCache  │
            │  (succeed)  │    └──────┬──────┘
            └─────────────┘           │
                              ┌───────▼───────┐
                              │   IsCached    │
                              └───────┬───────┘
                             yes /    │    \ no
                           ┌────┘     │     └────┐
                           │          │          │
                    ┌──────▼──────┐   │   ┌──────▼──────┐
                    │  SkipScan   │   │   │ GetRegistry │
                    │  (succeed)  │   │   └──────┬──────┘
                    └─────────────┘   │          │
                                      │   ┌──────▼──────┐
                                      │   │ SubmitScan  │
                                      │   └──────┬──────┘
                                      │          │
                                      │   ┌──────▼──────┐
                                      │   │ WaitForScan │◄────┐
                                      │   └──────┬──────┘     │
                                      │          │            │
                                      │   ┌──────▼──────┐     │
                                      │   │ CheckStatus │     │
                                      │   └──────┬──────┘     │
                                      │          │            │
                                      │   ┌──────▼───────┐    │
                                      │   │EvaluateStatus│────┘
                                      │   └──────┬───────┘ incomplete
                                      │    done/ │ \timeout
                                      │   ┌─────┘   └─────┐
                                      │   │               │
                               ┌──────▼───▼──┐    ┌───────▼───────┐
                               │  GetResults │    │  ScanTimeout  │
                               └──────┬──────┘    └───────┬───────┘
                                      │                   │
                                      └─────────┬─────────┘
                                                │
                                      ┌─────────▼─────────┐
                                      │ SendNotification  │
                                      └───────────────────┘
```

### Parse Event

Extracts ECR image URIs from task definition containers:

```python
ECR_PATTERN = r'^(\d+)\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([^:@]+)(?::([^@]+))?(?:@(sha256:[a-f0-9]+))?$'

def parse_ecr_image(image_uri):
    match = re.match(ECR_PATTERN, image_uri)
    if not match:
        return None
    account, region, repo, tag, digest = match.groups()
    return {
        'account_id': account,
        'region': region,
        'repository': repo,
        'tag': tag or 'latest',
        'digest': digest
    }
```

### Cache Check

DynamoDB stores scan results with 7-day TTL. Container images are immutable by digest, so repeated scans of the same image are skipped:

```python
cache_key = data.get('digest') or f"{data['repository']}:{data['tag']}"
response = table.get_item(Key={'imageDigest': cache_key})
if 'Item' in response and response['Item']['ttl'] > now:
    return {'cached': True}
```

### Registry Management

Creates Qualys ECR registry connector if one doesn't exist:

```python
def get_or_create_registry(creds, registry_name, account_id, region, role_arn):
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    uuid = get_registry_uuid(creds, registry_uri)
    if uuid:
        return {'registry_uuid': uuid, 'created': False}

    result = create_ecr_registry(creds, registry_name, account_id, region, role_arn)
    return {'registry_uuid': result['registry_uuid'], 'created': True}
```

### Scan Submission

Submits on-demand scan via Qualys Container Security API:

```python
payload = {
    "filters": [{"repoTags": [{"repo": repo_name, "tag": tag_filter}]}],
    "name": f"ECR-{repo_name}-{timestamp}",
    "onDemand": True,
    "forceScan": True,
    "registryType": "AWS"
}

response = requests.post(
    f"{gateway_url}/csapi/v1.3/registry/{registry_uuid}/schedule",
    json=payload,
    headers=headers
)
```

### Polling

Step Functions handles polling with configurable interval and max attempts:

```yaml
WaitForScan:
  Type: Wait
  SecondsPath: $.wait_seconds
  Next: CheckStatus

EvaluateStatus:
  Type: Choice
  Choices:
    - Variable: $.scan_complete
      BooleanEquals: true
      Next: GetResults
    - Variable: $.poll_count
      NumericGreaterThanEqualsPath: $.max_polls
      Next: ScanTimeout
  Default: IncrementPoll
```

### Notifications

SNS notifications are sent only for critical or high severity findings:

```python
summary = data.get('scan_result', {}).get('summary', {})
if summary.get('critical', 0) == 0 and summary.get('high', 0) == 0:
    return {'notified': False}

sns.publish(
    TopicArn=SNS_TOPIC_ARN,
    Subject=f"Scan: {repository} - {critical}C/{high}H",
    Message=json.dumps(result)
)
```

## IAM Configuration

### Qualys ECR Access Role

The Qualys Registry Sensor assumes an IAM role to pull images from ECR:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::QUALYS_ACCOUNT_ID:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "EXTERNAL_ID" } }
  }]
}
```

The external ID prevents confused deputy attacks. Retrieve it from Qualys:

```bash
curl -s "https://gateway.qg2.apps.qualys.com/csapi/v1.3/registry/aws-base" \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Lambda Execution Role

Follows least privilege with resource-scoped permissions:

| Permission | Resource |
|------------|----------|
| `secretsmanager:GetSecretValue` | Specific secret ARN |
| `dynamodb:GetItem`, `PutItem` | Specific table ARN |
| `sns:Publish` | Specific topic ARN |
| `ecs:DescribeTaskDefinition` | Account task definitions |
| `kms:Decrypt`, `GenerateDataKey` | Specific KMS key ARN |
| `xray:PutTraceSegments` | X-Ray tracing |

## Multi-Account Architecture

Hub-spoke pattern for AWS Organizations:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Account (Hub)                            │
│  ┌────────────────┐    ┌───────────────┐    ┌────────────────────────┐  │
│  │ Central        │    │ Step          │    │ Lambda                 │  │
│  │ EventBridge Bus│───>│ Functions     │───>│ (scans all accounts)   │  │
│  └───────▲────────┘    └───────────────┘    └────────────────────────┘  │
│          │                                                               │
└──────────┼───────────────────────────────────────────────────────────────┘
           │
    ┌──────┴──────┬──────────────┐
    │             │              │
┌───▼───┐    ┌───▼───┐    ┌─────▼─────┐
│Account│    │Account│    │  Account  │
│   A   │    │   B   │    │     C     │
│       │    │       │    │           │
│ ┌───┐ │    │ ┌───┐ │    │   ┌───┐   │
│ │EB │─┼────┼─│EB │─┼────┼───│EB │   │
│ └───┘ │    │ └───┘ │    │   └───┘   │
│ ┌───┐ │    │ ┌───┐ │    │   ┌───┐   │
│ │IAM│ │    │ │IAM│ │    │   │IAM│   │
│ │Role│ │    │ │Role│ │    │   │Role│   │
│ └───┘ │    │ └───┘ │    │   └───┘   │
└───────┘    └───────┘    └───────────┘
```

Spoke accounts:
- Forward ECS events to central EventBridge bus
- Maintain IAM roles for Qualys ECR access
- CloudTrail logs ECS management events

Hub account:
- Receives events from all spokes
- Runs Step Functions workflow
- Stores scan cache (DynamoDB)
- Manages Qualys API credentials

## Multi-Region Architecture

Regional spokes forward events to the primary region:

```
┌─────────────────────────┐    ┌─────────────────────────┐
│   Region: us-west-2     │    │   Region: eu-west-1     │
│   ┌─────────────────┐   │    │   ┌─────────────────┐   │
│   │  EventBridge    │───┼────┼──>│  EventBridge    │   │
│   │  (forward rule) │   │    │   │  (forward rule) │   │
│   └─────────────────┘   │    │   └────────┬────────┘   │
└─────────────┬───────────┘    └────────────┼────────────┘
              │                              │
              └──────────────┬───────────────┘
                             │
                             v
              ┌──────────────────────────────┐
              │   Region: us-east-1 (Primary)│
              │   ┌────────────────────────┐ │
              │   │    Step Functions      │ │
              │   │    Lambda              │ │
              │   │    DynamoDB            │ │
              │   └────────────────────────┘ │
              └──────────────────────────────┘
```

## Security Controls

### Encryption at Rest

| Resource | Encryption |
|----------|------------|
| S3 (CloudTrail logs) | KMS with bucket keys |
| DynamoDB (cache) | KMS |
| SNS (notifications) | KMS |
| Secrets Manager | KMS |
| CloudTrail | KMS with log validation |

### Network Security

- Optional VPC deployment for Lambda
- S3 bucket policy enforces HTTPS
- Public access blocked on all S3 buckets

### IAM Security

- External ID protects against confused deputy attacks
- Lambda roles use resource-scoped permissions
- Principle of least privilege throughout

## API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/csapi/v1.3/registry/aws-base` | GET | Get Qualys account ID and external ID |
| `/csapi/v1.3/registry` | GET | Find registry by URI or name |
| `/csapi/v1.3/registry` | POST | Create ECR registry connector |
| `/csapi/v1.3/registry/{uuid}/schedule` | POST | Submit on-demand scan |
| `/csapi/v1.3/images/{imageId}` | GET | Check scan status |
| `/csapi/v1.3/images/{imageId}/vuln` | GET | Get vulnerability details |

## Cost Estimate

| Component | Cost |
|-----------|------|
| Step Functions | $0.025 / 1000 executions |
| Lambda | $0.20 / 1000 scans |
| DynamoDB | $0.25 / million requests |
| CloudTrail | $0.10 / 100k events |
| KMS | $1.00 / key/month |
| Cross-region events | $1.00 / million |

**Estimate:** $15-30/month for 1000 deployments per day.

## Deployment

### Single Account

```bash
export QUALYS_API_TOKEN="your-token"
make deploy QUALYS_POD=US2 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-role
```

### Multi-Account

```bash
# Hub (security account)
make deploy-hub QUALYS_POD=US2 OrganizationId=o-xxx EXISTING_ROLE_NAME=qualys-role

# Spokes (member accounts via StackSet)
make deploy-spoke-stackset \
  OrganizationId=o-xxx \
  OrgUnitIds=ou-xxx \
  SecurityAccountId=111111111111 \
  CentralEventBusArn=arn:aws:events:... \
  EXISTING_ROLE_NAME=qualys-role
```

### Multi-Region

```bash
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1 EXISTING_ROLE_ARN=...
make deploy-region REGION=us-west-2,eu-west-1
```
