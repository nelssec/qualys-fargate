# Qualys Fargate Scanner
#
# Deployment Options:
#   - Single Account: make deploy
#   - Hub-Spoke (Centralized): make deploy-hub + make deploy-spoke-stackset
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
	@echo "Single Account:"
	@echo "  make deploy QUALYS_POD=US2            Deploy to primary region"
	@echo "  make deploy-region REGION=us-west-2,eu-west-1  Add regions"
	@echo "  make update                           Update Lambda code only"
	@echo "  make destroy                          Delete primary stack"
	@echo "  make destroy-region REGION=...        Delete regional spoke(s)"
	@echo ""
	@echo "Multi-Account (Hub-Spoke):"
	@echo "  make deploy-hub QUALYS_POD=US2        Deploy hub to security account"
	@echo "  make deploy-spoke                     Deploy spoke to member account"
	@echo "  make deploy-spoke-stackset            Deploy spokes via StackSet (org-wide)"
	@echo ""
	@echo "Operations:"
	@echo "  make logs                             Tail Lambda logs"
	@echo "  make workflow                         Open Step Functions console"
	@echo "  make status                           Show stack outputs"
	@echo "  make test                             Start workflow with test event"
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
	@echo "Fetching Qualys base account info..."
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
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
	echo "Qualys Base Account: $$BASE_ACCOUNT_ID"; \
	echo "Deploying single-account stack..."; \
	aws cloudformation deploy \
		--template-file cloudformation/single-account.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides \
			QualysGatewayUrl=$(QUALYS_GATEWAY_URL) \
			QualysApiToken=$$TOKEN \
			QualysBaseAccountId=$$BASE_ACCOUNT_ID \
			QualysExternalId=$$EXTERNAL_ID \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Updating Lambda code..."; \
	aws lambda update-function-code \
		--function-name $(STACK_NAME)-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION) > /dev/null; \
	echo "Done. Run 'make status' to see outputs."

.PHONY: update
update: package
	@aws lambda update-function-code \
		--function-name $(STACK_NAME)-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION)
	@echo "Lambda updated"

.PHONY: destroy
destroy:
	@aws cloudformation delete-stack --stack-name $(STACK_NAME) --region $(AWS_REGION)
	@echo "Stack deletion initiated"

# ==================== Multi-Region (Same Account) ====================

.PHONY: deploy-region
deploy-region:
	@if [ -z "$(REGION)" ]; then echo "Error: Set REGION (e.g., make deploy-region REGION=us-west-2,eu-west-1)"; exit 1; fi
	@for region in $$(echo "$(REGION)" | tr ',' ' '); do \
		if [ "$$region" = "$(AWS_REGION)" ]; then \
			echo "Skipping $$region (same as primary region)"; \
			continue; \
		fi; \
		echo "Deploying regional spoke to $$region..."; \
		aws cloudformation deploy \
			--template-file cloudformation/regional-spoke.yaml \
			--stack-name $(STACK_NAME)-$$region \
			--parameter-overrides \
				PrimaryRegion=$(AWS_REGION) \
				PrimaryStackName=$(STACK_NAME) \
				CreateCloudTrail=true \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $$region; \
		echo "Regional spoke deployed to $$region."; \
	done
	@echo "Done. ECS events from specified regions will forward to $(AWS_REGION)."

.PHONY: destroy-region
destroy-region:
	@if [ -z "$(REGION)" ]; then echo "Error: Set REGION"; exit 1; fi
	@for region in $$(echo "$(REGION)" | tr ',' ' '); do \
		echo "Deleting regional spoke in $$region..."; \
		aws cloudformation delete-stack --stack-name $(STACK_NAME)-$$region --region $$region; \
	done
	@echo "Regional spoke deletion initiated"

# ==================== Hub-Spoke (Multi-Account) ====================

.PHONY: deploy-hub
deploy-hub: check-auth package
	@echo "Fetching Qualys base account info..."
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	echo "Deploying hub stack to security account..."; \
	aws cloudformation deploy \
		--template-file cloudformation/centralized-hub.yaml \
		--stack-name $(STACK_NAME)-hub \
		--parameter-overrides \
			QualysGatewayUrl=$(QUALYS_GATEWAY_URL) \
			QualysApiToken=$$TOKEN \
			OrganizationId=$(OrganizationId) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Updating Lambda code..."; \
	aws lambda update-function-code \
		--function-name $(STACK_NAME)-hub-scanner \
		--zip-file fileb://build/$(LAMBDA_ZIP) \
		--region $(AWS_REGION) > /dev/null; \
	echo "Done. Hub deployed."; \
	echo ""; \
	echo "Central EventBridge Bus ARN:"; \
	aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query 'Stacks[0].Outputs[?OutputKey==`CentralEventBusArn`].OutputValue' \
		--output text --region $(AWS_REGION)

.PHONY: deploy-spoke
deploy-spoke: check-auth
	@if [ -z "$(SecurityAccountId)" ]; then echo "Set SecurityAccountId"; exit 1; fi
	@if [ -z "$(CentralEventBusArn)" ]; then echo "Set CentralEventBusArn"; exit 1; fi
	@echo "Fetching Qualys base account info..."
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Accept: application/json"); \
	BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
	EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
	echo "Deploying spoke stack..."; \
	aws cloudformation deploy \
		--template-file cloudformation/centralized-spoke.yaml \
		--stack-name $(STACK_NAME)-spoke \
		--parameter-overrides \
			SecurityAccountId=$(SecurityAccountId) \
			CentralEventBusArn=$(CentralEventBusArn) \
			QualysBaseAccountId=$$BASE_ACCOUNT_ID \
			QualysExternalId=$$EXTERNAL_ID \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Spoke deployed."

.PHONY: deploy-spoke-stackset
deploy-spoke-stackset: check-auth
	@if [ -z "$(OrganizationId)" ]; then echo "Set OrganizationId"; exit 1; fi
	@if [ -z "$(OrgUnitIds)" ]; then echo "Set OrgUnitIds (comma-separated)"; exit 1; fi
	@if [ -z "$(SecurityAccountId)" ]; then echo "Set SecurityAccountId"; exit 1; fi
	@if [ -z "$(CentralEventBusArn)" ]; then echo "Set CentralEventBusArn"; exit 1; fi
	@echo "Fetching Qualys base account info..."
	@TOKEN=$$(if [ -n "$(QUALYS_API_TOKEN)" ]; then echo "$(QUALYS_API_TOKEN)"; else \
		curl -s -X POST "$(QUALYS_GATEWAY_URL)/auth" \
			-H "Content-Type: application/x-www-form-urlencoded" \
			-d "username=$(QUALYS_USERNAME)&password=$(QUALYS_PASSWORD)&token=true"; \
	fi); \
	QUALYS_INFO=$$(curl -s "$(QUALYS_GATEWAY_URL)/csapi/v1.3/registry/aws-base" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Accept: application/json"); \
	BASE_ACCOUNT_ID=$$(echo "$$QUALYS_INFO" | jq -r '.accountId'); \
	EXTERNAL_ID=$$(echo "$$QUALYS_INFO" | jq -r '.externalId'); \
	echo "Creating/updating StackSet for spoke accounts..."; \
	aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-spoke \
		--template-body file://cloudformation/centralized-spoke.yaml \
		--parameters \
			ParameterKey=SecurityAccountId,ParameterValue=$(SecurityAccountId) \
			ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
			ParameterKey=QualysBaseAccountId,ParameterValue=$$BASE_ACCOUNT_ID \
			ParameterKey=QualysExternalId,ParameterValue=$$EXTERNAL_ID \
		--capabilities CAPABILITY_NAMED_IAM \
		--permission-model SERVICE_MANAGED \
		--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
		--region $(AWS_REGION) 2>/dev/null || \
	aws cloudformation update-stack-set \
		--stack-set-name $(STACK_NAME)-spoke \
		--template-body file://cloudformation/centralized-spoke.yaml \
		--parameters \
			ParameterKey=SecurityAccountId,ParameterValue=$(SecurityAccountId) \
			ParameterKey=CentralEventBusArn,ParameterValue=$(CentralEventBusArn) \
			ParameterKey=QualysBaseAccountId,ParameterValue=$$BASE_ACCOUNT_ID \
			ParameterKey=QualysExternalId,ParameterValue=$$EXTERNAL_ID \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION); \
	echo "Deploying to organization units..."; \
	aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke \
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
	@aws logs tail /aws/lambda/$(STACK_NAME)-scanner --follow --region $(AWS_REGION)

.PHONY: workflow
workflow:
	@echo "Opening Step Functions console..."
	@open "https://$(AWS_REGION).console.aws.amazon.com/states/home?region=$(AWS_REGION)#/statemachines"

.PHONY: status
status:
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--query 'Stacks[0].Outputs' \
		--output table \
		--region $(AWS_REGION) 2>/dev/null || echo "Stack not found"

.PHONY: test
test:
	@echo "Starting test workflow execution..."
	@WORKFLOW_ARN=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--query 'Stacks[0].Outputs[?OutputKey==`WorkflowArn`].OutputValue' \
		--output text --region $(AWS_REGION)); \
	aws stepfunctions start-execution \
		--state-machine-arn $$WORKFLOW_ARN \
		--input '{"trigger_type":"task_definition","repository":"test-repo","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","tag":"test","account_id":"123456789012","region":"us-east-1","max_polls":3,"wait_seconds":10}' \
		--region $(AWS_REGION)

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
