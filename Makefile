# Qualys Fargate Security Scanner - Deployment Automation
# Builds and deploys ECR image scanner and runtime sidecar

# Configuration
STACK_NAME ?= qualys-fargate-scanner
AWS_REGION ?= us-east-1
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)
QUALYS_POD ?= US2
QUALYS_TOKEN ?= $(shell aws secretsmanager get-secret-value --secret-id qualys-token --query SecretString --output text 2>/dev/null || echo "")

# ECR Configuration
SIDECAR_IMAGE_NAME = fargate-runtime-sidecar
SIDECAR_IMAGE_TAG ?= latest
SIDECAR_ECR_REPO = $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com/$(SIDECAR_IMAGE_NAME)

# Lambda Configuration
LAMBDA_CODE_DIR = image-scanner-lambda
LAMBDA_ZIP = lambda_function.zip

# QScanner Layer
QSCANNER_URL = https://qualysguard.qg2.apps.qualys.com/CloudAgent/Tools/qscanner/qscanner_latest.tar.gz

# Colors for output
BLUE = \033[0;34m
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help
help:
	@echo "$(BLUE)Qualys Fargate Security Scanner - Make Targets$(NC)"
	@echo ""
	@echo "$(GREEN)Image Scanner (Lambda):$(NC)"
	@echo "  make deploy-image-scanner    - Deploy ECR image scanner Lambda"
	@echo "  make package-lambda          - Package Lambda function"
	@echo "  make build-qscanner-layer    - Download and package QScanner layer"
	@echo "  make update-lambda           - Update existing Lambda function code"
	@echo ""
	@echo "$(GREEN)Runtime Sidecar (Container):$(NC)"
	@echo "  make build-runtime-sidecar   - Build runtime sidecar Docker image"
	@echo "  make push-runtime-sidecar    - Push sidecar image to ECR"
	@echo "  make create-ecr-repo         - Create ECR repository for sidecar"
	@echo ""
	@echo "$(GREEN)Full Deployment:$(NC)"
	@echo "  make deploy-all              - Deploy everything (scanner + sidecar)"
	@echo "  make clean                   - Clean build artifacts"
	@echo ""
	@echo "$(GREEN)Configuration:$(NC)"
	@echo "  STACK_NAME=$(STACK_NAME)"
	@echo "  AWS_REGION=$(AWS_REGION)"
	@echo "  AWS_ACCOUNT_ID=$(AWS_ACCOUNT_ID)"
	@echo "  QUALYS_POD=$(QUALYS_POD)"

# ==================== Image Scanner Deployment ====================

.PHONY: deploy-image-scanner
deploy-image-scanner: package-lambda build-qscanner-layer
	@echo "$(BLUE)Deploying ECR Image Scanner...$(NC)"
	@if [ -z "$(QUALYS_TOKEN)" ]; then \
		echo "$(RED)Error: QUALYS_TOKEN not set. Set it via environment or AWS Secrets Manager.$(NC)"; \
		exit 1; \
	fi

	# Create S3 bucket for Lambda code
	@aws s3 mb s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID) --region $(AWS_REGION) 2>/dev/null || true

	# Upload Lambda code and layer
	@aws s3 cp build/$(LAMBDA_ZIP) s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID)/scanner-lambda/$(LAMBDA_ZIP)
	@aws s3 cp build/qscanner-layer.zip s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID)/lambda-layer/qscanner-layer.zip

	# Deploy CloudFormation stack
	@aws cloudformation deploy \
		--template-file cloudformation/image-scanner.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysAccessToken=$(QUALYS_TOKEN) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)

	@echo "$(GREEN)Image Scanner deployed successfully$(NC)"

.PHONY: package-lambda
package-lambda:
	@echo "$(BLUE)Packaging Lambda function...$(NC)"
	@mkdir -p build
	@cd $(LAMBDA_CODE_DIR) && \
		pip install -r requirements.txt -t package/ && \
		cd package && zip -r9 ../../build/$(LAMBDA_ZIP) . && \
		cd .. && zip -g ../build/$(LAMBDA_ZIP) lambda_function.py
	@echo "$(GREEN)Lambda packaged: build/$(LAMBDA_ZIP)$(NC)"

.PHONY: build-qscanner-layer
build-qscanner-layer:
	@echo "$(BLUE)Building QScanner Lambda layer...$(NC)"
	@mkdir -p build/layer/bin

	# Download QScanner (this URL may need to be updated based on your Qualys subscription)
	# For now, we'll create a placeholder
	@echo "$(YELLOW)Note: QScanner binary must be obtained from Qualys$(NC)"
	@echo "$(YELLOW)Place qscanner binary in build/layer/bin/qscanner$(NC)"
	@echo "$(YELLOW)Creating placeholder layer structure...$(NC)"

	@mkdir -p build/layer/bin
	@touch build/layer/bin/qscanner
	@chmod +x build/layer/bin/qscanner

	@cd build/layer && zip -r9 ../qscanner-layer.zip .
	@echo "$(GREEN)QScanner layer created: build/qscanner-layer.zip$(NC)"

.PHONY: update-lambda
update-lambda: package-lambda
	@echo "$(BLUE)Updating Lambda function code...$(NC)"
	@aws lambda update-function-code \
		--function-name $(STACK_NAME)-image-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION)
	@echo "$(GREEN)Lambda function updated$(NC)"

# ==================== Runtime Sidecar Deployment ====================

.PHONY: create-ecr-repo
create-ecr-repo:
	@echo "$(BLUE)Creating ECR repository for runtime sidecar...$(NC)"
	@aws ecr describe-repositories \
		--repository-names $(SIDECAR_IMAGE_NAME) \
		--region $(AWS_REGION) >/dev/null 2>&1 || \
	aws ecr create-repository \
		--repository-name $(SIDECAR_IMAGE_NAME) \
		--image-scanning-configuration scanOnPush=true \
		--encryption-configuration encryptionType=AES256 \
		--region $(AWS_REGION)
	@echo "$(GREEN)ECR repository ready: $(SIDECAR_IMAGE_NAME)$(NC)"

.PHONY: build-runtime-sidecar
build-runtime-sidecar:
	@echo "$(BLUE)Building runtime sidecar Docker image...$(NC)"
	@docker build -t $(SIDECAR_IMAGE_NAME):$(SIDECAR_IMAGE_TAG) \
		-f runtime-sidecar/Dockerfile \
		runtime-sidecar/
	@echo "$(GREEN)Sidecar image built: $(SIDECAR_IMAGE_NAME):$(SIDECAR_IMAGE_TAG)$(NC)"

.PHONY: push-runtime-sidecar
push-runtime-sidecar: create-ecr-repo build-runtime-sidecar
	@echo "$(BLUE)Pushing runtime sidecar to ECR...$(NC)"

	# Login to ECR
	@aws ecr get-login-password --region $(AWS_REGION) | \
		docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com

	# Tag and push
	@docker tag $(SIDECAR_IMAGE_NAME):$(SIDECAR_IMAGE_TAG) $(SIDECAR_ECR_REPO):$(SIDECAR_IMAGE_TAG)
	@docker push $(SIDECAR_ECR_REPO):$(SIDECAR_IMAGE_TAG)

	@echo "$(GREEN)Sidecar pushed to: $(SIDECAR_ECR_REPO):$(SIDECAR_IMAGE_TAG)$(NC)"

# ==================== Full Deployment ====================

.PHONY: deploy-all
deploy-all: deploy-image-scanner push-runtime-sidecar
	@echo "$(GREEN)Full deployment complete$(NC)"
	@echo ""
	@echo "$(BLUE)Next steps:$(NC)"
	@echo "1. Update your ECS task definitions to include the runtime sidecar"
	@echo "   See: examples/task-definition-with-sidecar.json"
	@echo "2. Ensure Fargate platform version is 1.4.0 or later"
	@echo "3. Monitor CloudWatch Logs at /ecs/fargate-runtime-security"
	@echo "4. Subscribe to SNS topic for security alerts"

# ==================== Utilities ====================

.PHONY: test-lambda-local
test-lambda-local:
	@echo "$(BLUE)Testing Lambda function locally...$(NC)"
	@cd $(LAMBDA_CODE_DIR) && \
		python3 -c "import lambda_function; import json; \
		event = {'detail': {'eventName': 'PutImage', 'requestParameters': {'repositoryName': 'test'}, 'responseElements': {'image': {'imageId': {'imageDigest': 'sha256:test'}}}}}; \
		print(json.dumps(lambda_function.lambda_handler(event, {}), indent=2))"

.PHONY: logs-lambda
logs-lambda:
	@echo "$(BLUE)Fetching Lambda logs...$(NC)"
	@aws logs tail /aws/lambda/$(STACK_NAME)-image-scanner --follow --region $(AWS_REGION)

.PHONY: logs-sidecar
logs-sidecar:
	@echo "$(BLUE)Fetching sidecar logs...$(NC)"
	@aws logs tail /ecs/fargate-runtime-security --follow --region $(AWS_REGION)

.PHONY: clean
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf build/
	@rm -rf $(LAMBDA_CODE_DIR)/package/
	@echo "$(GREEN)Clean complete$(NC)"

.PHONY: destroy
destroy:
	@echo "$(RED)Warning: This will delete all resources!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		aws cloudformation delete-stack --stack-name $(STACK_NAME) --region $(AWS_REGION); \
		echo "$(YELLOW)Stack deletion initiated. This may take a few minutes.$(NC)"; \
	fi

# ==================== Validation ====================

.PHONY: validate
validate:
	@echo "$(BLUE)Validating CloudFormation template...$(NC)"
	@aws cloudformation validate-template \
		--template-body file://cloudformation/image-scanner.yaml \
		--region $(AWS_REGION) >/dev/null
	@echo "$(GREEN)Template is valid$(NC)"

.PHONY: check-requirements
check-requirements:
	@echo "$(BLUE)Checking requirements...$(NC)"
	@command -v aws >/dev/null 2>&1 || { echo "$(RED)AWS CLI not installed$(NC)"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Docker not installed$(NC)"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)Python 3 not installed$(NC)"; exit 1; }
	@echo "$(GREEN)All requirements satisfied$(NC)"
