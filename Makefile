# Qualys ECR Image Scanner - Deployment Automation
# Builds and deploys Lambda-based ECR image scanning using Qualys QScanner

# Configuration
STACK_NAME ?= qualys-ecr-scanner
AWS_REGION ?= us-east-1
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)
QUALYS_POD ?= US2
QUALYS_ACCESS_TOKEN ?= $(shell aws secretsmanager get-secret-value --secret-id qualys-token --query SecretString --output text 2>/dev/null || echo "")

# Lambda Configuration
LAMBDA_CODE_DIR = image-scanner-lambda
LAMBDA_ZIP = lambda_function.zip

# Colors for output
BLUE = \033[0;34m
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help
help:
	@echo "$(BLUE)Qualys ECR Image Scanner - Make Targets$(NC)"
	@echo ""
	@echo "$(GREEN)Deployment:$(NC)"
	@echo "  make deploy              - Deploy ECR image scanner Lambda stack"
	@echo "  make update              - Update Lambda function code only"
	@echo "  make destroy             - Delete the CloudFormation stack"
	@echo ""
	@echo "$(GREEN)Build:$(NC)"
	@echo "  make package             - Package Lambda function"
	@echo "  make build-layer         - Build QScanner Lambda layer"
	@echo "  make clean               - Clean build artifacts"
	@echo ""
	@echo "$(GREEN)Operations:$(NC)"
	@echo "  make logs                - Tail Lambda function logs"
	@echo "  make validate            - Validate CloudFormation template"
	@echo "  make verify              - Verify Qualys integration"
	@echo "  make status              - Show stack status and outputs"
	@echo ""
	@echo "$(GREEN)Configuration:$(NC)"
	@echo "  STACK_NAME=$(STACK_NAME)"
	@echo "  AWS_REGION=$(AWS_REGION)"
	@echo "  AWS_ACCOUNT_ID=$(AWS_ACCOUNT_ID)"
	@echo "  QUALYS_POD=$(QUALYS_POD)"

# ==================== Deployment ====================

.PHONY: deploy
deploy: package build-layer
	@echo "$(BLUE)Deploying ECR Image Scanner...$(NC)"
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "$(RED)Error: QUALYS_ACCESS_TOKEN not set.$(NC)"; \
		echo "Set via environment variable or store in AWS Secrets Manager as 'qualys-token'"; \
		exit 1; \
	fi

	# Create S3 bucket for Lambda code (ignore if exists)
	@aws s3 mb s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID) --region $(AWS_REGION) 2>/dev/null || true

	# Upload Lambda code and layer
	@echo "$(BLUE)Uploading Lambda artifacts to S3...$(NC)"
	@aws s3 cp build/$(LAMBDA_ZIP) s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID)/scanner-lambda/$(LAMBDA_ZIP)
	@aws s3 cp build/qscanner-layer.zip s3://$(STACK_NAME)-lambda-code-$(AWS_ACCOUNT_ID)/lambda-layer/qscanner-layer.zip

	# Deploy CloudFormation stack
	@echo "$(BLUE)Deploying CloudFormation stack...$(NC)"
	@aws cloudformation deploy \
		--template-file cloudformation/image-scanner.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysAccessToken=$(QUALYS_ACCESS_TOKEN) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)

	@echo ""
	@echo "$(GREEN)Deployment successful!$(NC)"
	@echo ""
	@$(MAKE) status --no-print-directory

.PHONY: update
update: package
	@echo "$(BLUE)Updating Lambda function code...$(NC)"
	@aws lambda update-function-code \
		--function-name $(STACK_NAME)-image-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION)
	@echo "$(GREEN)Lambda function updated$(NC)"

.PHONY: destroy
destroy:
	@echo "$(RED)Warning: This will delete the image scanner stack and all associated resources!$(NC)"
	@echo "Note: S3 buckets with DeletionPolicy: Retain will be preserved."
	@read -p "Are you sure you want to delete $(STACK_NAME)? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		aws cloudformation delete-stack --stack-name $(STACK_NAME) --region $(AWS_REGION); \
		echo "$(YELLOW)Stack deletion initiated. Run 'make status' to monitor progress.$(NC)"; \
	fi

# ==================== Build ====================

.PHONY: package
package:
	@echo "$(BLUE)Packaging Lambda function...$(NC)"
	@mkdir -p build
	@rm -rf $(LAMBDA_CODE_DIR)/package
	@cd $(LAMBDA_CODE_DIR) && \
		pip install -r requirements.txt -t package/ --quiet && \
		cd package && zip -r9 ../../build/$(LAMBDA_ZIP) . -x "*.pyc" -x "__pycache__/*" && \
		cd .. && zip -g ../build/$(LAMBDA_ZIP) lambda_function.py
	@echo "$(GREEN)Lambda packaged: build/$(LAMBDA_ZIP)$(NC)"

.PHONY: build-layer
build-layer:
	@echo "$(BLUE)Building QScanner Lambda layer...$(NC)"
	@mkdir -p build/layer/bin

	@echo "$(YELLOW)Note: QScanner binary must be obtained from your Qualys subscription.$(NC)"
	@echo "$(YELLOW)Download QScanner from your Qualys portal and place it in build/layer/bin/qscanner$(NC)"
	@echo ""

	@if [ ! -f build/layer/bin/qscanner ] || [ ! -s build/layer/bin/qscanner ]; then \
		echo "$(YELLOW)Creating placeholder layer (replace with actual QScanner binary)...$(NC)"; \
		touch build/layer/bin/qscanner; \
		chmod +x build/layer/bin/qscanner; \
	fi

	@cd build/layer && zip -r9 ../qscanner-layer.zip .
	@echo "$(GREEN)QScanner layer created: build/qscanner-layer.zip$(NC)"

.PHONY: clean
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf build/
	@rm -rf $(LAMBDA_CODE_DIR)/package/
	@echo "$(GREEN)Clean complete$(NC)"

# ==================== Operations ====================

.PHONY: logs
logs:
	@echo "$(BLUE)Tailing Lambda function logs (Ctrl+C to stop)...$(NC)"
	@aws logs tail /aws/lambda/$(STACK_NAME)-image-scanner --follow --region $(AWS_REGION)

.PHONY: validate
validate:
	@echo "$(BLUE)Validating CloudFormation template...$(NC)"
	@aws cloudformation validate-template \
		--template-body file://cloudformation/image-scanner.yaml \
		--region $(AWS_REGION) >/dev/null
	@echo "$(GREEN)Template is valid$(NC)"

.PHONY: verify
verify:
	@echo "$(BLUE)Verifying Qualys integration...$(NC)"
	@./scripts/verify-qualys-integration.sh

.PHONY: status
status:
	@echo "$(BLUE)Stack Status:$(NC)"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--query 'Stacks[0].StackStatus' \
		--output text \
		--region $(AWS_REGION) 2>/dev/null || echo "Stack not found"
	@echo ""
	@echo "$(BLUE)Stack Outputs:$(NC)"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
		--output table \
		--region $(AWS_REGION) 2>/dev/null || echo "No outputs available"

.PHONY: check-requirements
check-requirements:
	@echo "$(BLUE)Checking requirements...$(NC)"
	@command -v aws >/dev/null 2>&1 || { echo "$(RED)AWS CLI not installed$(NC)"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)Python 3 not installed$(NC)"; exit 1; }
	@command -v zip >/dev/null 2>&1 || { echo "$(RED)zip not installed$(NC)"; exit 1; }
	@echo "$(GREEN)All requirements satisfied$(NC)"
