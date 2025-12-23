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

```mermaid
flowchart TB
    subgraph trigger["Event Detection"]
        ECS[ECS API Call]
        CT[CloudTrail]
        EB[EventBridge]
    end

    subgraph workflow["Step Functions"]
        PARSE[Parse Event]
        CACHE[Check Cache]
        REG[Get/Create Registry]
        SCAN[Submit Scan]
        POLL[Poll Status]
        RESULTS[Get Results]
        NOTIFY[Send Notification]
    end

    subgraph storage["Encrypted Storage"]
        DDB[(DynamoDB)]
        S3[(S3)]
        SM[Secrets Manager]
        KMS[KMS]
    end

    subgraph qualys["Qualys"]
        API[Container Security API]
        SENSOR[Registry Sensor]
    end

    subgraph aws["AWS"]
        ECR[ECR]
        ROLE[IAM Role]
    end

    ECS --> CT --> EB --> PARSE
    PARSE --> CACHE --> REG --> SCAN --> POLL --> RESULTS --> NOTIFY
    CACHE <--> DDB
    CT --> S3
    REG --> SM
    DDB & S3 & SM --> KMS
    REG --> API
    SCAN --> API
    RESULTS --> API
    API --> SENSOR --> ROLE --> ECR
```

ECS API calls are logged by CloudTrail and matched by EventBridge rules. EventBridge triggers a Step Functions workflow that extracts ECR images from the event, checks a DynamoDB cache, and calls the Qualys API to submit scans. The Qualys Registry Sensor assumes an IAM role to pull images from ECR.

## Security

### Encryption at Rest

All data is encrypted using customer-managed KMS keys:

| Resource | Encryption |
|----------|------------|
| S3 (CloudTrail logs) | KMS with bucket keys, versioning enabled |
| DynamoDB (scan cache) | KMS with point-in-time recovery |
| SNS (notifications) | KMS |
| Secrets Manager (API credentials) | KMS |
| CloudTrail | KMS with log file validation |

### IAM Least Privilege

Lambda execution roles use resource-scoped permissions:

| Permission | Resource Scope |
|------------|---------------|
| `secretsmanager:GetSecretValue` | Specific secret ARN |
| `dynamodb:GetItem`, `PutItem` | Specific table ARN |
| `sns:Publish` | Specific topic ARN |
| `ecs:DescribeTaskDefinition` | Account task definitions |
| `kms:Decrypt`, `GenerateDataKey` | Specific KMS key ARN |

### Network Security

- Optional VPC deployment for Lambda isolation
- S3 bucket policies enforce HTTPS (deny insecure transport)
- Public access blocked on all S3 buckets
- External ID protects against confused deputy attacks

## IAM Role Configuration

The Qualys Registry Sensor requires an IAM role to access ECR.

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

### Authentication Flow

```mermaid
sequenceDiagram
    participant Sensor as Registry Sensor
    participant Role as IAM Role
    participant ECR as ECR

    Sensor->>Role: AssumeRole with external ID
    Role-->>Sensor: Temporary credentials
    Sensor->>ECR: Pull image
    ECR-->>Sensor: Image layers
```

Retrieve the Qualys account ID and external ID:
```bash
curl -s "https://gateway.qg2.apps.qualys.com/csapi/v1.3/registry/aws-base" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Deployment

### Single Account

```bash
export QUALYS_API_TOKEN="your-token"

# Using existing role
make deploy QUALYS_POD=US2 EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-role

# Creating new role
make deploy QUALYS_POD=US2 CREATE_ROLE=true
```

### Multi-Region

Regional spokes forward events to the primary region:

```mermaid
flowchart TB
    subgraph primary["Primary Region"]
        SF[Step Functions]
        LAMBDA[Lambda]
        DDB[DynamoDB]
        KMS1[KMS]
    end

    subgraph spoke1["Region 2"]
        EB1[EventBridge]
        CT1[CloudTrail]
        KMS2[KMS]
    end

    subgraph spoke2["Region 3"]
        EB2[EventBridge]
        CT2[CloudTrail]
        KMS3[KMS]
    end

    EB1 --> SF
    EB2 --> SF
    SF --> LAMBDA --> DDB
    DDB --> KMS1
```

```bash
make deploy QUALYS_POD=US2 AWS_REGION=us-east-1 EXISTING_ROLE_ARN=...
make deploy-region REGION=us-west-2,eu-west-1
```

### Multi-Account (Hub-Spoke)

Hub-spoke pattern for AWS Organizations:

```mermaid
flowchart TB
    subgraph hub["Security Account (Hub)"]
        BUS[EventBridge Bus]
        SF[Step Functions]
        LAMBDA[Lambda]
        DDB[(DynamoDB)]
        SM[Secrets Manager]
    end

    subgraph spoke1["Member Account A"]
        EB1[EventBridge]
        CT1[CloudTrail]
        ROLE1[IAM Role]
    end

    subgraph spoke2["Member Account B"]
        EB2[EventBridge]
        CT2[CloudTrail]
        ROLE2[IAM Role]
    end

    EB1 --> BUS
    EB2 --> BUS
    BUS --> SF --> LAMBDA
    LAMBDA --> DDB
    LAMBDA --> SM
```

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

## Event Detection

CloudTrail captures ECS management events with log file validation:

```yaml
EventSelectors:
  - ReadWriteType: WriteOnly
    IncludeManagementEvents: true
EnableLogFileValidation: true
KMSKeyId: !Ref EncryptionKey
```

EventBridge matches the following events:

| Event | Description |
|-------|-------------|
| `RegisterTaskDefinition` | New task definition revision |
| `RunTask` | Standalone task launched |
| `CreateService` | New service created |
| `UpdateService` | Service deployment updated |

## Workflow

```mermaid
stateDiagram-v2
    [*] --> ParseEvent
    ParseEvent --> HasImages
    HasImages --> NoImages: no ECR images
    HasImages --> CheckCache: has images
    NoImages --> [*]

    CheckCache --> IsCached
    IsCached --> SkipScan: cached
    IsCached --> GetRegistry: not cached
    SkipScan --> [*]

    GetRegistry --> SubmitScan
    SubmitScan --> WaitForScan
    WaitForScan --> CheckStatus
    CheckStatus --> EvaluateStatus
    EvaluateStatus --> WaitForScan: incomplete
    EvaluateStatus --> GetResults: complete
    EvaluateStatus --> ScanTimeout: max polls

    GetResults --> SendNotification
    ScanTimeout --> SendNotification
    SendNotification --> [*]
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

DynamoDB stores scan results with 7-day TTL. Container images are immutable by digest:

```python
cache_key = data.get('digest') or f"{data['repository']}:{data['tag']}"
response = table.get_item(Key={'imageDigest': cache_key})
if 'Item' in response and response['Item']['ttl'] > now:
    return {'cached': True}
```

### Registry Management

Creates Qualys ECR registry connector if not found:

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

Step Functions polls with configurable interval (default 60s) and max attempts (default 30):

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

### Notification

SNS notifications (encrypted) sent for critical or high severity findings:

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

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Workflow not triggering | Verify CloudTrail logs ECS events |
| Registry creation failed | Verify IAM role trust policy includes Qualys account |
| Scan timeout | Increase `MaxPollAttempts` parameter |
| API 401/403 errors | Regenerate Qualys token, update secret |
| Cross-account events not arriving | Verify EventBus policy allows spoke account |
