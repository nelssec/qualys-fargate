#!/bin/bash
set -e

# End-to-End Test Deployment Script
# Deploys vulnerable test app with runtime monitoring and database storage

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}End-to-End Security Testing Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Configuration
AWS_REGION=${AWS_REGION:-us-east-1}
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CLUSTER_NAME=${CLUSTER_NAME:-fargate-security-test}
SUBNET_ID=${SUBNET_ID:-}
SECURITY_GROUP_ID=${SECURITY_GROUP_ID:-}
QUALYS_POD=${QUALYS_POD:-US2}
QUALYS_ACCESS_TOKEN=${QUALYS_ACCESS_TOKEN:-}

# Validate prerequisites
echo -e "${BLUE}Step 1: Validating prerequisites...${NC}"

if [ -z "$SUBNET_ID" ]; then
    echo -e "${RED}Error: SUBNET_ID environment variable not set${NC}"
    echo "Usage: SUBNET_ID=subnet-xxx SECURITY_GROUP_ID=sg-xxx ./scripts/deploy-end-to-end-test.sh"
    exit 1
fi

if [ -z "$SECURITY_GROUP_ID" ]; then
    echo -e "${RED}Error: SECURITY_GROUP_ID environment variable not set${NC}"
    exit 1
fi

if [ -z "$QUALYS_ACCESS_TOKEN" ]; then
    echo -e "${YELLOW}Warning: QUALYS_ACCESS_TOKEN not set. Runtime events will not be sent to Qualys CRS${NC}"
fi

echo -e "${GREEN}Prerequisites validated${NC}"
echo ""

# Deploy DynamoDB events table
echo -e "${BLUE}Step 2: Deploying DynamoDB events table...${NC}"
aws cloudformation deploy \
    --template-file cloudformation/events-database.yaml \
    --stack-name fargate-security-events-db \
    --parameter-overrides \
        TableName=fargate-runtime-security-events \
    --region ${AWS_REGION}

EVENTS_TABLE_NAME=$(aws cloudformation describe-stacks \
    --stack-name fargate-security-events-db \
    --query 'Stacks[0].Outputs[?OutputKey==`TableName`].OutputValue' \
    --output text \
    --region ${AWS_REGION})

echo -e "${GREEN}Events table deployed: ${EVENTS_TABLE_NAME}${NC}"
echo ""

# Build and push vulnerable test app
echo -e "${BLUE}Step 3: Building vulnerable test application...${NC}"
cd test-app

# Create ECR repository if it doesn't exist
aws ecr describe-repositories --repository-names vulnerable-test-app --region ${AWS_REGION} 2>/dev/null || \
    aws ecr create-repository \
        --repository-name vulnerable-test-app \
        --image-scanning-configuration scanOnPush=true \
        --region ${AWS_REGION}

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build and push
docker build -t vulnerable-test-app:latest .
docker tag vulnerable-test-app:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/vulnerable-test-app:latest
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/vulnerable-test-app:latest

echo -e "${GREEN}Vulnerable test app pushed to ECR${NC}"
echo -e "${YELLOW}Note: This will trigger the image scanner if deployed${NC}"
cd ..
echo ""

# Build and push runtime sidecar
echo -e "${BLUE}Step 4: Building runtime security sidecar...${NC}"
make build-runtime-sidecar
make push-runtime-sidecar
echo -e "${GREEN}Runtime sidecar deployed${NC}"
echo ""

# Create ECS cluster if it doesn't exist
echo -e "${BLUE}Step 5: Creating ECS cluster...${NC}"
aws ecs describe-clusters --clusters ${CLUSTER_NAME} --region ${AWS_REGION} 2>/dev/null | \
    grep -q "ACTIVE" || \
    aws ecs create-cluster --cluster-name ${CLUSTER_NAME} --region ${AWS_REGION}

echo -e "${GREEN}ECS cluster ready: ${CLUSTER_NAME}${NC}"
echo ""

# Create CloudWatch log groups
echo -e "${BLUE}Step 6: Creating CloudWatch log groups...${NC}"
aws logs create-log-group --log-group-name /ecs/vulnerable-test-app --region ${AWS_REGION} 2>/dev/null || true
aws logs create-log-group --log-group-name /ecs/fargate-runtime-security --region ${AWS_REGION} 2>/dev/null || true
echo -e "${GREEN}Log groups created${NC}"
echo ""

# Create task execution role if needed
echo -e "${BLUE}Step 7: Configuring IAM roles...${NC}"
EXEC_ROLE_ARN=$(aws iam get-role --role-name ecsTaskExecutionRole --query 'Role.Arn' --output text 2>/dev/null || echo "")
if [ -z "$EXEC_ROLE_ARN" ]; then
    echo -e "${YELLOW}ecsTaskExecutionRole not found, please create it manually${NC}"
    exit 1
fi

# Create task role with DynamoDB permissions
TASK_ROLE_NAME="fargateSecurityTestTaskRole"
aws iam get-role --role-name ${TASK_ROLE_NAME} --region ${AWS_REGION} 2>/dev/null || \
    aws iam create-role \
        --role-name ${TASK_ROLE_NAME} \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }' \
        --region ${AWS_REGION}

# Attach policies to task role
aws iam put-role-policy \
    --role-name ${TASK_ROLE_NAME} \
    --policy-name DynamoDBEventsAccess \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:BatchWriteItem",
                    "dynamodb:Query",
                    "dynamodb:Scan"
                ],
                "Resource": "arn:aws:dynamodb:'${AWS_REGION}':'${AWS_ACCOUNT_ID}':table/'${EVENTS_TABLE_NAME}'"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:Query"
                ],
                "Resource": "arn:aws:dynamodb:'${AWS_REGION}':'${AWS_ACCOUNT_ID}':table/'${EVENTS_TABLE_NAME}'/index/*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutMetricData"
                ],
                "Resource": "*"
            }
        ]
    }'

TASK_ROLE_ARN=$(aws iam get-role --role-name ${TASK_ROLE_NAME} --query 'Role.Arn' --output text)
echo -e "${GREEN}IAM roles configured${NC}"
echo ""

# Register task definition
echo -e "${BLUE}Step 8: Registering ECS task definition...${NC}"
cat > /tmp/test-task-definition.json <<EOF
{
  "family": "vulnerable-test-app-with-security",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "${EXEC_ROLE_ARN}",
  "taskRoleArn": "${TASK_ROLE_ARN}",
  "platformVersion": "1.4.0",
  "containerDefinitions": [
    {
      "name": "vulnerable-app",
      "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/vulnerable-test-app:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/vulnerable-test-app",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "app"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
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
          "value": "60"
        },
        {
          "name": "LOG_GROUP_NAME",
          "value": "/ecs/fargate-runtime-security"
        },
        {
          "name": "EVENTS_TABLE_NAME",
          "value": "${EVENTS_TABLE_NAME}"
        },
        {
          "name": "QUALYS_POD",
          "value": "${QUALYS_POD}"
        },
        {
          "name": "QUALYS_ACCESS_TOKEN",
          "value": "${QUALYS_ACCESS_TOKEN}"
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
          "containerName": "vulnerable-app",
          "condition": "START"
        }
      ]
    }
  ]
}
EOF

aws ecs register-task-definition \
    --cli-input-json file:///tmp/test-task-definition.json \
    --region ${AWS_REGION}

echo -e "${GREEN}Task definition registered${NC}"
echo ""

# Run the task
echo -e "${BLUE}Step 9: Launching Fargate task...${NC}"
TASK_ARN=$(aws ecs run-task \
    --cluster ${CLUSTER_NAME} \
    --task-definition vulnerable-test-app-with-security \
    --launch-type FARGATE \
    --platform-version 1.4.0 \
    --network-configuration "awsvpcConfiguration={
        subnets=[${SUBNET_ID}],
        securityGroups=[${SECURITY_GROUP_ID}],
        assignPublicIp=ENABLED
    }" \
    --region ${AWS_REGION} \
    --query 'tasks[0].taskArn' \
    --output text)

echo -e "${GREEN}Task launched: ${TASK_ARN}${NC}"
echo ""

# Wait for task to start
echo -e "${BLUE}Step 10: Waiting for task to start...${NC}"
aws ecs wait tasks-running \
    --cluster ${CLUSTER_NAME} \
    --tasks ${TASK_ARN} \
    --region ${AWS_REGION}

# Get task public IP
TASK_IP=$(aws ecs describe-tasks \
    --cluster ${CLUSTER_NAME} \
    --tasks ${TASK_ARN} \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' \
    --output text \
    --region ${AWS_REGION} | xargs -I {} aws ec2 describe-network-interfaces \
    --network-interface-ids {} \
    --query 'NetworkInterfaces[0].Association.PublicIp' \
    --output text \
    --region ${AWS_REGION})

echo -e "${GREEN}Task is running${NC}"
echo -e "${GREEN}Public IP: ${TASK_IP}${NC}"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Task ARN: ${TASK_ARN}"
echo -e "Task IP: http://${TASK_IP}:8080"
echo -e "Events Table: ${EVENTS_TABLE_NAME}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Trigger security events:"
echo -e "   curl http://${TASK_IP}:8080/trigger-all"
echo -e ""
echo -e "2. View runtime security logs:"
echo -e "   aws logs tail /ecs/fargate-runtime-security --follow"
echo -e ""
echo -e "3. Query events from DynamoDB:"
echo -e "   python3 scripts/query-events.py --hours 1"
echo -e ""
echo -e "4. View image scan results:"
echo -e "   aws logs tail /aws/lambda/qualys-fargate-scanner-image-scanner --follow"
echo ""
