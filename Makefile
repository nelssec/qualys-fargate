# Qualys Fargate Scanner
#
# Deployment Options:
#   - Single Account: make deploy (deploys both service + target to same account)
#   - Multi-Account:  make deploy-service (hub) + make deploy-target (spokes)
#
# Authentication:
#   Option 1: Bearer token (recommended)
#     export QUALYS_API_TOKEN="your-subscription-token"
#
#   Option 2: Username/password (generates 4-hour JWT)
#     export QUALYS_USERNAME="your-username"
#     export QUALYS_PASSWORD="your-password"

STACK_NAME ?= qualys-fargate-scanner
AWS_REGION ?= us-east-1

# IAM Role Configuration
# Set CREATE_ROLE=true to create a new IAM role for Qualys ECR access
# Set EXISTING_ROLE_ARN to use an existing IAM role (single-account)
# Set EXISTING_ROLE_NAME to use an existing IAM role (multi-account)
CREATE_ROLE ?= false
EXISTING_ROLE_ARN ?=
EXISTING_ROLE_NAME ?=

# POD to Gateway URL mapping
QUALYS_POD ?= US2
QUALYS_GATEWAY_URL_US1 = https://gateway.qg1.apps.qualys.com
QUALYS_GATEWAY_URL_US2 = https://gateway.qg2.apps.qualys.com
QUALYS_GATEWAY_URL_US3 = https://gateway.qg3.apps.qualys.com
QUALYS_GATEWAY_URL_US4 = https://gateway.qg4.apps.qualys.com
QUALYS_GATEWAY_URL_EU1 = https://gateway.qg1.apps.qualys.eu
QUALYS_GATEWAY_URL_EU2 = https://gateway.qg2.apps.qualys.eu
QUALYS_GATEWAY_URL_IN1 = https://gateway.qg1.apps.qualys.in
QUALYS_GATEWAY_URL_CA1 = https://gateway.qg1.apps.qualys.ca
QUALYS_GATEWAY_URL_AE1 = https://gateway.qg1.apps.qualys.ae
QUALYS_GATEWAY_URL_UK1 = https://gateway.qg1.apps.qualys.co.uk
QUALYS_GATEWAY_URL_AU1 = https://gateway.qg1.apps.qualys.com.au

# Select gateway based on POD
QUALYS_GATEWAY_URL = $(QUALYS_GATEWAY_URL_$(QUALYS_POD))

LAMBDA_DIR = lambdas
LAMBDA_ZIP = scanner.zip

.PHONY: help
help:
	@echo "Qualys Fargate Scanner"
	@echo ""
	@echo "Authentication (set one of these):"
	@echo "  export QUALYS_API_TOKEN=...           Bearer token from Qualys portal"
	@echo "  export QUALYS_USERNAME=... PASSWORD=... Username/password (generates JWT)"
	@echo ""
	@echo "IAM Role Options:"
	@echo "  EXISTING_ROLE_ARN=arn:aws:iam::...    Use existing IAM role (single-account)"
	@echo "  EXISTING_ROLE_NAME=role-name          Use existing IAM role name (multi-account)"
	@echo "  CREATE_ROLE=true                      Create new IAM role (uses Qualys API)"
	@echo ""
	@echo "Single Account Deployment:"
	@echo "  make deploy EXISTING_ROLE_ARN=...     Deploy with existing role (recommended)"
	@echo "  make deploy CREATE_ROLE=true          Deploy and create new role"
	@echo "  make deploy-region REGION=us-west-2   Add additional regions"
	@echo "  make update                           Update Lambda code only"
	@echo "  make destroy                          Delete all stacks"
	@echo ""
	@echo "Multi-Account Deployment:"
	@echo "  make deploy-service                   Deploy service account (hub)"
	@echo "  make deploy-target                    Deploy target account (spoke)"
	@echo "  make deploy-target-stackset           Deploy targets via StackSet (org-wide)"
	@echo ""
	@echo "Operations:"
	@echo "  make logs                             Tail Lambda logs"
	@echo "  make workflow                         Open Step Functions console"
	@echo "  make status                           Show stack outputs"
	@echo ""
	@echo "Qualys Info:"
	@echo "  make get-qualys-info                  Show Qualys base account info"
	@echo "  make list-registries                  List Qualys registry connectors"

# ==================== Authentication Helpers ====================

# Get or generate token
define get_token
$(if $(QUALYS_API_TOKEN),$(QUALYS_API_TOKEN),$(shell \
	if [ -n "$(QUALYS_USERNAME)" ] && [ -n "$(QUALYS_PASSWORD)" ]; then \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true" \
			2>/dev/null; \
	fi))
endef

# Fetch base account info from Qualys API
define fetch_qualys_base
$(shell curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
	-H "Authorization: Bearer $(1)" \
	-H "Accept: application/json" 2>/dev/null)
endef

VALID_PODS := US1 US2 US3 US4 EU1 EU2 IN1 CA1 AE1 UK1 AU1

.PHONY: check-auth
check-auth:
	@if [ -z "$(QUALYS_API_TOKEN)" ] && [ -z "$(QUALYS_USERNAME)" ]; then \
		echo "Error: Set QUALYS_API_TOKEN or QUALYS_USERNAME/QUALYS_PASSWORD"; \
		exit 1; \
	fi
	@if [ -z "$(QUALYS_GATEWAY_URL)" ]; then \
		echo "Error: Invalid QUALYS_POD '$(QUALYS_POD)'. Check your Qualys subscription for your POD."; \
		exit 1; \
	fi

.PHONY: get-qualys-info
get-qualys-info: check-auth
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	echo "Fetching Qualys base account info from $(QUALYS_POD)..."; \
	curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Accept: application/json" | jq '{"QualysBaseAccountId": .accountId, "QualysExternalId": .externalId, "POD": "$(QUALYS_POD)"}'

# ==================== Single Account Deployment ====================

.PHONY: deploy
deploy: check-auth package
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	echo "Deploying service account stack..."; \
	aws cloudformation deploy \
		--template-file cloudformation/service-account.yaml \
		--stack-name $(STACK_NAME)-service \
		--parameter-overrides \
			QualysGatewayUrl=$(QUALYS_GATEWAY_URL) \
			QualysApiToken=$$TOKEN \
			TargetAccountIds=$$ACCOUNT_ID \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Updating Lambda code..."; \
	aws lambda update-function-code \
		--function-name $(STACK_NAME)-service-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION) > /dev/null; \
	CENTRAL_BUS_ARN=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-service \
		--query 'Stacks[0].Outputs[?OutputKey==`CentralEventBusArn`].OutputValue' \
		--output text --region $(AWS_REGION)); \
	echo ""; \
	echo "Deploying target account stack..."; \
	if [ "$(CREATE_ROLE)" = "true" ]; then \
		QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
			-H "Authorization: Bearer $$TOKEN" \
			-H "Accept: application/json"); \
		BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
		EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
		if [ -z "$$BASE_ACCOUNT_ID" ] || [ "$$BASE_ACCOUNT_ID" = "null" ]; then \
			echo "Error: Failed to fetch Qualys base account info. Check your credentials."; \
			exit 1; \
		fi; \
		echo "Creating new IAM role for Qualys ECR access..."; \
		aws cloudformation deploy \
			--template-file cloudformation/target-account.yaml \
			--stack-name $(STACK_NAME)-target \
			--parameter-overrides \
				ServiceAccountId=$$ACCOUNT_ID \
				CentralEventBusArn=$$CENTRAL_BUS_ARN \
				CreateRole=true \
				QualysBaseAccountId=$$BASE_ACCOUNT_ID \
				QualysExternalId=$$EXTERNAL_ID \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	else \
		if [ -z "$(EXISTING_ROLE_ARN)" ]; then \
			echo "Error: Set EXISTING_ROLE_ARN or use CREATE_ROLE=true"; \
			echo "  Example: make deploy EXISTING_ROLE_ARN=arn:aws:iam::123456789012:role/qualys-ecr-role"; \
			exit 1; \
		fi; \
		ROLE_NAME=$$(echo "$(EXISTING_ROLE_ARN)" | sed 's/.*:role\///'); \
		aws cloudformation deploy \
			--template-file cloudformation/target-account.yaml \
			--stack-name $(STACK_NAME)-target \
			--parameter-overrides \
				ServiceAccountId=$$ACCOUNT_ID \
				CentralEventBusArn=$$CENTRAL_BUS_ARN \
				CreateRole=false \
				ExistingRoleName=$$ROLE_NAME \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	fi; \
	echo ""; \
	echo "Done. Run 'make status' to see outputs."

.PHONY: update
update: package
	@aws lambda update-function-code \
		--function-name $(STACK_NAME)-service-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION)
	@echo "Lambda updated"

.PHONY: destroy
destroy:
	@echo "Deleting target stack..."
	@aws cloudformation delete-stack --stack-name $(STACK_NAME)-target --region $(AWS_REGION) 2>/dev/null || true
	@echo "Deleting service stack..."
	@aws cloudformation delete-stack --stack-name $(STACK_NAME)-service --region $(AWS_REGION) 2>/dev/null || true
	@echo "Stack deletion initiated"

# ==================== Multi-Region (Same Account) ====================

.PHONY: deploy-region
deploy-region: check-auth
	@if [ -z "$(REGION)" ]; then echo "Error: Set REGION (e.g., make deploy-region REGION=us-west-2,eu-west-1)"; exit 1; fi
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	CENTRAL_BUS_ARN=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-service \
		--query 'Stacks[0].Outputs[?OutputKey==`CentralEventBusArn`].OutputValue' \
		--output text --region $(AWS_REGION)); \
	if [ -z "$$CENTRAL_BUS_ARN" ]; then \
		echo "Error: Service stack not found. Deploy with 'make deploy' first."; \
		exit 1; \
	fi; \
	for region in $$(echo "$(REGION)" | tr ',' ' '); do \
		if [ "$$region" = "$(AWS_REGION)" ]; then \
			echo "Skipping $$region (same as primary region)"; \
			continue; \
		fi; \
		echo "Deploying target stack to $$region..."; \
		if [ "$(CREATE_ROLE)" = "true" ]; then \
			TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
				curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
					-H "Content-Type: application/x-www-form-urlencoded" \
					-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
			fi); \
			QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
				-H "Authorization: Bearer $$TOKEN" \
				-H "Accept: application/json"); \
			BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
			EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
			aws cloudformation deploy \
				--template-file cloudformation/target-account.yaml \
				--stack-name $(STACK_NAME)-target-$$region \
				--parameter-overrides \
					ServiceAccountId=$$ACCOUNT_ID \
					CentralEventBusArn=$$CENTRAL_BUS_ARN \
					CreateRole=true \
					QualysBaseAccountId=$$BASE_ACCOUNT_ID \
					QualysExternalId=$$EXTERNAL_ID \
				--capabilities CAPABILITY_NAMED_IAM \
				--region $$region; \
		else \
			if [ -z "$(EXISTING_ROLE_NAME)" ]; then \
				echo "Error: Set EXISTING_ROLE_NAME or use CREATE_ROLE=true"; \
				exit 1; \
			fi; \
			aws cloudformation deploy \
				--template-file cloudformation/target-account.yaml \
				--stack-name $(STACK_NAME)-target-$$region \
				--parameter-overrides \
					ServiceAccountId=$$ACCOUNT_ID \
					CentralEventBusArn=$$CENTRAL_BUS_ARN \
					CreateRole=false \
					ExistingRoleName=$(EXISTING_ROLE_NAME) \
				--capabilities CAPABILITY_NAMED_IAM \
				--region $$region; \
		fi; \
		echo "Target stack deployed to $$region."; \
	done
	@echo "Done. ECS events from specified regions will forward to $(AWS_REGION)."

.PHONY: destroy-region
destroy-region:
	@if [ -z "$(REGION)" ]; then echo "Error: Set REGION"; exit 1; fi
	@for region in $$(echo "$(REGION)" | tr ',' ' '); do \
		echo "Deleting target stack in $$region..."; \
		aws cloudformation delete-stack --stack-name $(STACK_NAME)-target-$$region --region $$region; \
	done
	@echo "Regional stack deletion initiated"

# ==================== Multi-Account Deployment ====================

.PHONY: deploy-service
deploy-service: check-auth package
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	ECR_ROLE="$(if $(EXISTING_ROLE_NAME),$(EXISTING_ROLE_NAME),qualys-fargate-scan-role)"; \
	echo "Deploying service account stack..."; \
	echo "ECR Role Name: $$ECR_ROLE"; \
	aws cloudformation deploy \
		--template-file cloudformation/service-account.yaml \
		--stack-name $(STACK_NAME)-service \
		--parameter-overrides \
			QualysGatewayUrl=$(QUALYS_GATEWAY_URL) \
			QualysApiToken=$$TOKEN \
			OrganizationId=$(OrganizationId) \
			ECRRoleName=$$ECR_ROLE \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Updating Lambda code..."; \
	aws lambda update-function-code \
		--function-name $(STACK_NAME)-service-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION) > /dev/null; \
	echo "Done. Service account deployed."; \
	echo ""; \
	echo "Central EventBridge Bus ARN:"; \
	aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-service \
		--query 'Stacks[0].Outputs[?OutputKey==`CentralEventBusArn`].OutputValue' \
		--output text --region $(AWS_REGION); \
	echo ""; \
	echo "Service Account ID:"; \
	aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-service \
		--query 'Stacks[0].Outputs[?OutputKey==`ServiceAccountId`].OutputValue' \
		--output text --region $(AWS_REGION)

.PHONY: deploy-target
deploy-target: check-auth
	@if [ -z "$(ServiceAccountId)" ]; then echo "Set ServiceAccountId"; exit 1; fi
	@if [ -z "$(CentralEventBusArn)" ]; then echo "Set CentralEventBusArn"; exit 1; fi
	@if [ "$(CREATE_ROLE)" = "true" ]; then \
		echo "Fetching Qualys base account info..."; \
		TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
			curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
				-H "Content-Type: application/x-www-form-urlencoded" \
				-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
		fi); \
		QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
			-H "Authorization: Bearer $$TOKEN" \
			-H "Accept: application/json"); \
		BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
		EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
		if [ -z "$$BASE_ACCOUNT_ID" ] || [ "$$BASE_ACCOUNT_ID" = "null" ]; then \
			echo "Error: Failed to fetch Qualys base account info. Check your credentials."; \
			exit 1; \
		fi; \
		echo "Deploying target stack (creating new IAM role)..."; \
		aws cloudformation deploy \
			--template-file cloudformation/target-account.yaml \
			--stack-name $(STACK_NAME)-target \
			--parameter-overrides \
				ServiceAccountId=$(ServiceAccountId) \
				CentralEventBusArn=$(CentralEventBusArn) \
				CreateRole=true \
				QualysBaseAccountId=$$BASE_ACCOUNT_ID \
				QualysExternalId=$$EXTERNAL_ID \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	else \
		if [ -z "$(EXISTING_ROLE_NAME)" ]; then \
			echo "Error: Set EXISTING_ROLE_NAME or use CREATE_ROLE=true"; \
			echo "  Example: make deploy-target EXISTING_ROLE_NAME=qualys-ecr-role ..."; \
			exit 1; \
		fi; \
		echo "Deploying target stack (using existing IAM role)..."; \
		aws cloudformation deploy \
			--template-file cloudformation/target-account.yaml \
			--stack-name $(STACK_NAME)-target \
			--parameter-overrides \
				ServiceAccountId=$(ServiceAccountId) \
				CentralEventBusArn=$(CentralEventBusArn) \
				CreateRole=false \
				ExistingRoleName=$(EXISTING_ROLE_NAME) \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	fi; \
	echo "Target stack deployed."

.PHONY: deploy-target-stackset
deploy-target-stackset: check-auth
	@if [ -z "$(OrganizationId)" ]; then echo "Set OrganizationId"; exit 1; fi
	@if [ -z "$(OrgUnitIds)" ]; then echo "Set OrgUnitIds (comma-separated)"; exit 1; fi
	@if [ -z "$(ServiceAccountId)" ]; then echo "Set ServiceAccountId"; exit 1; fi
	@if [ -z "$(CentralEventBusArn)" ]; then echo "Set CentralEventBusArn"; exit 1; fi
	@if [ "$(CREATE_ROLE)" = "true" ]; then \
		echo "Fetching Qualys base account info..."; \
		TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
			curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
				-H "Content-Type: application/x-www-form-urlencoded" \
				-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
		fi); \
		QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
			-H "Authorization: Bearer $$TOKEN" \
			-H "Accept: application/json"); \
		BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
		EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
		if [ -z "$$BASE_ACCOUNT_ID" ] || [ "$$BASE_ACCOUNT_ID" = "null" ]; then \
			echo "Error: Failed to fetch Qualys base account info. Check your credentials."; \
			exit 1; \
		fi; \
		echo "Creating/updating StackSet for target accounts (creating new IAM roles)..."; \
		aws cloudformation create-stack-set \
			--stack-set-name $(STACK_NAME)-target \
			--template-body file://cloudformation/target-account.yaml \
			--parameters \
				ParameterKey=ServiceAccountId,ParameterValue=$(ServiceAccountId) \
				ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
				ParameterKey=CreateRole,ParameterValue=true \
				ParameterKey=QualysBaseAccountId,ParameterValue=$$BASE_ACCOUNT_ID \
				ParameterKey=QualysExternalId,ParameterValue=$$EXTERNAL_ID \
			--capabilities CAPABILITY_NAMED_IAM \
			--permission-model SERVICE_MANAGED \
			--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
			--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-target \
			--template-body file://cloudformation/target-account.yaml \
			--parameters \
				ParameterKey=ServiceAccountId,ParameterValue=$(ServiceAccountId) \
				ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
				ParameterKey=CreateRole,ParameterValue=true \
				ParameterKey=QualysBaseAccountId,ParameterValue=$$BASE_ACCOUNT_ID \
				ParameterKey=QualysExternalId,ParameterValue=$$EXTERNAL_ID \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	else \
		if [ -z "$(EXISTING_ROLE_NAME)" ]; then \
			echo "Error: Set EXISTING_ROLE_NAME or use CREATE_ROLE=true"; \
			echo "  Example: make deploy-target-stackset EXISTING_ROLE_NAME=qualys-ecr-role ..."; \
			exit 1; \
		fi; \
		echo "Creating/updating StackSet for target accounts (using existing IAM roles)..."; \
		aws cloudformation create-stack-set \
			--stack-set-name $(STACK_NAME)-target \
			--template-body file://cloudformation/target-account.yaml \
			--parameters \
				ParameterKey=ServiceAccountId,ParameterValue=$(ServiceAccountId) \
				ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
				ParameterKey=CreateRole,ParameterValue=false \
				ParameterKey=ExistingRoleName,ParameterValue=$(EXISTING_ROLE_NAME) \
			--capabilities CAPABILITY_NAMED_IAM \
			--permission-model SERVICE_MANAGED \
			--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
			--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-target \
			--template-body file://cloudformation/target-account.yaml \
			--parameters \
				ParameterKey=ServiceAccountId,ParameterValue=$(ServiceAccountId) \
				ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
				ParameterKey=CreateRole,ParameterValue=false \
				ParameterKey=ExistingRoleName,ParameterValue=$(EXISTING_ROLE_NAME) \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION); \
	fi; \
	echo "Deploying to organization units..."; \
	aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-target \
		--deployment-targets OrganizationalUnitIds=$(OrgUnitIds) \
		--regions $(AWS_REGION) \
		--operation-preferences MaxConcurrentPercentage=100 \
		--region $(AWS_REGION); \
	echo "StackSet deployment initiated."

# ==================== Build ====================

.PHONY: package
package:
	@mkdir -p build
	@rm -rf $(LAMBDA_DIR)/package
	@cd $(LAMBDA_DIR) && \
		pip3 install -r requirements.txt -t package/ --quiet && \
		cd package && zip -r9 ../../build/$(LAMBDA_ZIP) . -x "*.pyc" -x "__pycache__/*" && \
		cd .. && zip -g ../build/$(LAMBDA_ZIP) *.py
	@echo "Built: build/$(LAMBDA_ZIP)"

.PHONY: clean
clean:
	@rm -rf build/ $(LAMBDA_DIR)/package/

# ==================== Operations ====================

.PHONY: logs
logs:
	@aws logs tail /aws/lambda/$(STACK_NAME)-service-scanner --follow --region $(AWS_REGION)

.PHONY: workflow
workflow:
	@echo "Opening Step Functions console..."
	@open "https://$(AWS_REGION).console.aws.amazon.com/states/home?region=$(AWS_REGION)#/statemachines"

.PHONY: status
status:
	@echo "Service Account Stack:"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-service \
		--query 'Stacks[0].Outputs' \
		--output table \
		--region $(AWS_REGION) 2>/dev/null || echo "  (not deployed)"
	@echo ""
	@echo "Target Account Stack:"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-target \
		--query 'Stacks[0].Outputs' \
		--output table \
		--region $(AWS_REGION) 2>/dev/null || echo "  (not deployed)"

# ==================== Qualys Operations ====================

.PHONY: list-registries
list-registries: check-auth
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry?pageNumber=1&pageSize=50" \
		-H "Authorization: Bearer $$TOKEN" | jq '.data[]|{name:.registryName,uuid:.registryUuid,uri:.registryUri}'
