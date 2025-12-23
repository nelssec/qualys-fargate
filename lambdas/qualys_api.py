"""Qualys Container Security API Client"""

import os
import json
import urllib.parse
import boto3
import requests
import logging
from datetime import datetime

logger = logging.getLogger()

API_TIMEOUT = int(os.environ.get('API_TIMEOUT_SECONDS', '30'))
IAM_PROPAGATION_WAIT_SECONDS = int(os.environ.get('IAM_PROPAGATION_WAIT_SECONDS', '30'))
SENSITIVE_PATTERNS = ['token', 'key', 'secret', 'password', 'credential', 'auth']


def _sanitize_error(error_text: str, max_length: int = 100) -> str:
    if not error_text:
        return "Unknown error"

    logger.error(f"Full API error: {error_text[:500]}")

    error_lower = error_text.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in error_lower:
            return "API error (details logged to CloudWatch)"

    sanitized = error_text[:max_length]
    if len(error_text) > max_length:
        sanitized += "..."

    return sanitized


def get_qualys_credentials(secret_arn: str) -> dict:
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(response['SecretString'])
    return {
        'token': secret['qualys_token'],
        'gateway_url': secret.get('qualys_gateway_url', 'https://gateway.qg2.apps.qualys.com')
    }


def get_headers(token: str) -> dict:
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


def get_qualys_aws_base(creds: dict) -> dict:
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
            'error': _sanitize_error(response.text),
            'status_code': response.status_code
        }


def get_aws_connector(creds: dict, connector_name: str = None, role_arn: str = None) -> dict:
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
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']


def ensure_aws_connector(creds: dict, role_arn: str, role_name: str) -> dict:
    base_info = get_qualys_aws_base(creds)
    qualys_account_id = base_info['base_account_id']
    external_id = base_info['external_id']

    logger.info(f"Qualys base account: {qualys_account_id[:8]}..., external ID configured")

    role_account_id = role_arn.split(':')[4] if role_arn else None
    current_account_id = get_current_account_id()
    iam_updated = False

    if role_account_id == current_account_id:
        iam_updated = update_iam_role_trust_policy(role_name, qualys_account_id, external_id)
        if iam_updated:
            logger.info(f"IAM trust policy updated - propagation wait of {IAM_PROPAGATION_WAIT_SECONDS}s required")
    else:
        logger.info("Cross-account scenario detected. Skipping IAM update.")

    existing = get_aws_connector(creds, role_arn=role_arn)
    if existing:
        logger.info(f"Found existing connector: {existing.get('name')}")
        return {
            'connector_name': existing.get('name'),
            'connector_arn': existing.get('arn'),
            'created': False,
            'iam_updated': iam_updated,
            'iam_wait_seconds': IAM_PROPAGATION_WAIT_SECONDS if iam_updated else 0
        }

    connector_name = f"ecr-connector-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    result = create_aws_connector(creds, role_arn, external_id, connector_name)

    if result.get('created'):
        result['iam_updated'] = iam_updated
        result['iam_wait_seconds'] = IAM_PROPAGATION_WAIT_SECONDS if iam_updated else 0
        return result
    else:
        return {
            'connector_name': None,
            'error': _sanitize_error(result.get('error', 'Unknown connector error')),
            'iam_updated': iam_updated,
            'iam_wait_seconds': IAM_PROPAGATION_WAIT_SECONDS if iam_updated else 0
        }


def get_registry_uuid(creds: dict, registry_uri: str) -> str:
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
            'error': _sanitize_error(response.text),
            'status_code': response.status_code
        }


def get_or_create_registry(creds: dict, registry_name: str, account_id: str,
                           region: str, role_arn: str = None,
                           role_name: str = None) -> dict:
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"
    iam_wait_seconds = 0

    uuid = get_registry_uuid(creds, registry_uri)
    if uuid:
        logger.info(f"Found existing registry: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True, 'iam_wait_seconds': 0}

    uuid = get_registry_by_name(creds, registry_name)
    if uuid:
        logger.info(f"Found existing registry by name: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True, 'iam_wait_seconds': 0}

    if not role_arn:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': 'Registry not found and no IAM role ARN provided',
            'iam_wait_seconds': 0
        }

    if role_name:
        logger.info(f"Ensuring AWS connector for role: {role_name}")
        connector_result = ensure_aws_connector(creds, role_arn, role_name)
        iam_wait_seconds = connector_result.get('iam_wait_seconds', 0)

        if connector_result.get('error'):
            logger.warning(f"Connector creation issue: {connector_result.get('error')}")

    logger.info(f"Creating registry: {registry_name}")
    result = create_ecr_registry(creds, registry_name, account_id, region, role_arn)

    if result.get('created'):
        return {
            'registry_uuid': result['registry_uuid'],
            'created': True,
            'exists': True,
            'iam_wait_seconds': iam_wait_seconds
        }
    else:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': _sanitize_error(result.get('error', 'Unknown registry error')),
            'iam_wait_seconds': iam_wait_seconds
        }


def submit_on_demand_scan(creds: dict, registry_uuid: str,
                          repo_name: str, image_tag: str) -> dict:
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
    encoded_id = urllib.parse.quote(image_id, safe='')

    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}"
    headers = get_headers(creds['token'])

    response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

    if response.status_code == 404:
        return {'status': 'pending', 'found': False}

    if response.status_code != 200:
        return {'status': 'error', 'found': False, 'error': _sanitize_error(response.text)}

    data = response.json()

    return {
        'status': 'complete' if data.get('scanStatus') == 'SUCCESS' else 'scanning',
        'found': True,
        'scan_status': data.get('scanStatus'),
        'vulnerabilities': data.get('vulnerabilities', {})
    }


def get_image_vulnerabilities(creds: dict, image_id: str) -> dict:
    encoded_id = urllib.parse.quote(image_id, safe='')

    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}/vuln"
    headers = get_headers(creds['token'])
    params = {'pageNumber': 1, 'pageSize': 100}

    response = requests.get(url, headers=headers, params=params, timeout=API_TIMEOUT)

    if response.status_code != 200:
        return {
            'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'vulnerabilities': [],
            'error': _sanitize_error(response.text)
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
        'vulnerabilities': vulns[:20]
    }
