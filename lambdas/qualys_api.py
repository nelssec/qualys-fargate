"""
Qualys Container Security API Client

IAM role-based authentication for AWS ECR registry scanning.
No static credentials required - uses cross-account role assumption.
"""

import json
import time
import urllib.parse
import boto3
import requests
import logging
from datetime import datetime

logger = logging.getLogger()

API_TIMEOUT = 30


def get_qualys_credentials(secret_arn: str) -> dict:
    """Retrieve Qualys API token from Secrets Manager."""
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(response['SecretString'])

    return {
        'token': secret['qualys_token'],
        'gateway_url': secret.get('qualys_gateway_url', 'https://gateway.qg2.apps.qualys.com')
    }


def get_headers(token: str) -> dict:
    """Build headers for Qualys API requests."""
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


def get_qualys_aws_base(creds: dict) -> dict:
    """
    Get Qualys base account ID and external ID for IAM role trust policy.

    API: GET /csapi/v1.3/registry/aws-base

    Returns: {'base_account_id': '...', 'external_id': '...'}
    """
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws-base"
    headers = get_headers(creds['token'])

    response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
    response.raise_for_status()

    data = response.json()
    return {
        'base_account_id': data['accountId'],
        'external_id': str(data['externalId'])
    }


def update_iam_role_trust_policy(role_name: str, qualys_account_id: str, external_id: str) -> bool:
    """
    Update IAM role trust policy with current Qualys external ID.

    The external ID from Qualys can change, so we update it each time before
    creating connectors/registries.
    """
    iam = boto3.client('iam')

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{qualys_account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": str(external_id)}}
            }
        ]
    }

    try:
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )
        logger.info(f"Updated IAM role {role_name} trust policy with external ID")
        return True
    except Exception as e:
        logger.error(f"Failed to update IAM role trust policy: {e}")
        return False


def create_aws_connector(creds: dict, role_arn: str, external_id: str,
                         connector_name: str = None) -> dict:
    """
    Create AWS connector in Qualys.

    API: POST /csapi/v1.3/registry/aws/connector

    The connector must be created before creating ECR registries.
    """
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws/connector"
    headers = get_headers(creds['token'])

    if not connector_name:
        connector_name = f"ECR-Connector-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    payload = {
        "arn": role_arn,
        "description": "Auto-created connector for ECR scanning",
        "externalId": str(external_id),
        "name": connector_name,
        "accountType": "Global"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=API_TIMEOUT)

    if response.status_code == 200:
        logger.info(f"Created AWS connector: {connector_name}")
        return {
            'created': True,
            'connector_name': connector_name,
            'connector_arn': role_arn
        }
    else:
        return {
            'created': False,
            'error': response.text[:200],
            'status_code': response.status_code
        }


def get_aws_connector(creds: dict, connector_name: str = None, role_arn: str = None) -> dict:
    """
    Get AWS connector details.

    API: GET /csapi/v1.3/registry/aws/connectors
    """
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws/connectors"
    headers = get_headers(creds['token'])

    response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

    if response.status_code != 200:
        return None

    connectors = response.json()

    for connector in connectors:
        if connector_name and connector.get('name') == connector_name:
            return connector
        if role_arn and connector.get('arn') == role_arn:
            return connector

    return None


def get_current_account_id() -> str:
    """Get the AWS account ID where this Lambda is running."""
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']


def ensure_aws_connector(creds: dict, role_arn: str, role_name: str) -> dict:
    """
    Ensure AWS connector exists, creating one if needed.

    This function:
    1. Gets current external ID from Qualys
    2. Updates the IAM role trust policy (only if same account - for hub-spoke,
       spoke accounts manage their own IAM roles)
    3. Creates or finds an existing connector
    """
    # Get current external ID
    base_info = get_qualys_aws_base(creds)
    qualys_account_id = base_info['base_account_id']
    external_id = base_info['external_id']

    logger.info(f"Qualys base account: {qualys_account_id}, external ID: {external_id}")

    # Extract account ID from role ARN (arn:aws:iam::ACCOUNT_ID:role/name)
    role_account_id = role_arn.split(':')[4] if role_arn else None
    current_account_id = get_current_account_id()

    # Only update IAM trust policy if the role is in the same account
    # For hub-spoke, spoke accounts manage their own IAM roles during deployment
    if role_account_id == current_account_id:
        update_iam_role_trust_policy(role_name, qualys_account_id, external_id)
        # Wait for IAM changes to propagate (required for Qualys to assume role)
        logger.info("Waiting 30s for IAM trust policy to propagate...")
        time.sleep(30)
    else:
        logger.info(f"Cross-account scenario: role in {role_account_id}, Lambda in {current_account_id}. "
                    "Skipping IAM update - spoke accounts manage their own IAM roles.")

    # Check if connector already exists for this role
    existing = get_aws_connector(creds, role_arn=role_arn)
    if existing:
        logger.info(f"Found existing connector: {existing.get('name')}")
        return {
            'connector_name': existing.get('name'),
            'connector_arn': existing.get('arn'),
            'created': False
        }

    # Create new connector
    connector_name = f"ecr-connector-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    result = create_aws_connector(creds, role_arn, external_id, connector_name)

    if result.get('created'):
        return result
    else:
        return {
            'connector_name': None,
            'error': result.get('error')
        }


def get_registry_uuid(creds: dict, registry_uri: str) -> str:
    """Get registry UUID by ECR URI."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry"
    headers = get_headers(creds['token'])
    filter_query = urllib.parse.quote(f'registryUri:"{registry_uri}"')
    params = {'filter': filter_query, 'pageNumber': 1, 'pageSize': 50}

    response = requests.get(url, headers=headers, params=params, timeout=API_TIMEOUT)

    if response.status_code == 204:
        return None

    response.raise_for_status()
    data = response.json()

    if 'data' in data and data['data']:
        return data['data'][0].get('registryUuid')

    return None


def get_registry_by_name(creds: dict, registry_name: str) -> str:
    """Get registry UUID by name."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry"
    headers = get_headers(creds['token'])
    params = {'pageNumber': 1, 'pageSize': 100}

    response = requests.get(url, headers=headers, params=params, timeout=API_TIMEOUT)
    response.raise_for_status()

    data = response.json()
    for registry in data.get('data', []):
        if registry_name == registry.get('registryName'):
            return registry.get('registryUuid')

    return None


def create_ecr_registry(creds: dict, registry_name: str, account_id: str,
                        region: str, role_arn: str) -> dict:
    """Create ECR registry in Qualys using IAM role authentication."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry"
    headers = get_headers(creds['token'])
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    payload = {
        "aws": {
            "accountId": account_id,
            "arn": role_arn,
            "region": region,
            "accountType": "Global"
        },
        "credentialType": "AWS",
        "registryType": "AWS",
        "registryUri": registry_uri,
        "registryName": registry_name
    }

    response = requests.post(url, json=payload, headers=headers, timeout=API_TIMEOUT)

    if response.status_code == 200:
        try:
            data = response.json()
            registry_uuid = data.get('registryUuid')
            if not registry_uuid:
                registry_uuid = get_registry_uuid(creds, registry_uri)
            return {
                'created': True,
                'registry_uuid': registry_uuid,
                'registry_name': registry_name
            }
        except Exception:
            registry_uuid = get_registry_uuid(creds, registry_uri)
            return {
                'created': True,
                'registry_uuid': registry_uuid,
                'registry_name': registry_name
            }
    else:
        return {
            'created': False,
            'error': response.text[:200],
            'status_code': response.status_code
        }


def get_or_create_registry(creds: dict, registry_name: str, account_id: str,
                           region: str, role_arn: str = None,
                           role_name: str = None) -> dict:
    """
    Get registry UUID, or create if it doesn't exist.

    This function:
    1. Checks if registry already exists
    2. If not, ensures an AWS connector exists (updating IAM trust policy)
    3. Creates the registry using the connector
    """
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    # Check if registry already exists
    uuid = get_registry_uuid(creds, registry_uri)
    if uuid:
        logger.info(f"Found existing registry: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True}

    uuid = get_registry_by_name(creds, registry_name)
    if uuid:
        logger.info(f"Found existing registry by name: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True}

    if not role_arn:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': 'Registry not found and no IAM role ARN provided for auto-creation'
        }

    # Ensure connector exists (this also updates IAM trust policy with current external ID)
    if role_name:
        logger.info(f"Ensuring AWS connector for role: {role_name}")
        connector_result = ensure_aws_connector(creds, role_arn, role_name)

        if connector_result.get('error'):
            logger.warning(f"Connector creation issue: {connector_result.get('error')}")
            # Continue anyway - connector might already exist with different name

    # Create the registry
    logger.info(f"Creating registry: {registry_name}")
    result = create_ecr_registry(creds, registry_name, account_id, region, role_arn)

    if result.get('created'):
        return {
            'registry_uuid': result['registry_uuid'],
            'created': True,
            'exists': True
        }
    else:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': result.get('error')
        }


def submit_on_demand_scan(creds: dict, registry_uuid: str,
                          repo_name: str, image_tag: str) -> dict:
    """Submit on-demand scan request to Qualys."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/{registry_uuid}/schedule"
    headers = get_headers(creds['token'])
    tag_filter = image_tag if image_tag != 'latest' else '.*'

    payload = {
        "filters": [{
            "repoTags": [{
                "repo": repo_name,
                "tag": tag_filter
            }],
            "days": None
        }],
        "name": f"ECR-{repo_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "onDemand": True,
        "schedule": "00:00",
        "forceScan": True,
        "registryType": "AWS"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=API_TIMEOUT)

    return {
        'status_code': response.status_code,
        'schedule_id': response.json().get('scheduleId') if response.ok else None,
        'schedule_name': payload['name']
    }


def get_image_scan_status(creds: dict, image_id: str) -> dict:
    """Check scan status for an image."""
    encoded_id = urllib.parse.quote(image_id, safe='')

    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}"
    headers = get_headers(creds['token'])

    response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

    if response.status_code == 404:
        return {'status': 'pending', 'found': False}

    if response.status_code != 200:
        return {'status': 'error', 'found': False, 'error': response.text[:100]}

    data = response.json()

    return {
        'status': 'complete' if data.get('scanStatus') == 'SUCCESS' else 'scanning',
        'found': True,
        'scan_status': data.get('scanStatus'),
        'vulnerabilities': data.get('vulnerabilities', {})
    }


def get_image_vulnerabilities(creds: dict, image_id: str) -> dict:
    """Get vulnerability details for an image."""
    encoded_id = urllib.parse.quote(image_id, safe='')

    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}/vuln"
    headers = get_headers(creds['token'])
    params = {'pageNumber': 1, 'pageSize': 100}

    response = requests.get(url, headers=headers, params=params, timeout=API_TIMEOUT)

    if response.status_code != 200:
        return {
            'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'vulnerabilities': [],
            'error': response.text[:100]
        }

    data = response.json()
    vulns = data.get('data', [])

    summary = {
        'total': len(vulns),
        'critical': sum(1 for v in vulns if v.get('severity') == 5),
        'high': sum(1 for v in vulns if v.get('severity') == 4),
        'medium': sum(1 for v in vulns if v.get('severity') == 3),
        'low': sum(1 for v in vulns if v.get('severity') in [1, 2])
    }

    return {
        'summary': summary,
        'vulnerabilities': vulns[:20]  # Return top 20 for notification
    }
