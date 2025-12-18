"""
Qualys Container Security API Client

IAM role-based authentication for AWS ECR registry scanning.
No static credentials required - uses cross-account role assumption.
"""

import json
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
        'external_id': data['externalId']
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
                           region: str, role_arn: str = None) -> dict:
    """Get registry UUID, or create if it doesn't exist. Uses IAM role auth."""
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

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
