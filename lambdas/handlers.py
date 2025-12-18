"""
Step Function Lambda Handlers

Dispatch-based handler for Step Functions workflow.
Handles ECS/Fargate task definition and deployment events.
Uses IAM role-based authentication for ECR access (no static credentials).
"""

import os
import re
import json
import boto3
import logging
from datetime import datetime, timedelta
from qualys_api import (
    get_qualys_credentials,
    get_or_create_registry,
    submit_on_demand_scan,
    get_image_scan_status,
    get_image_vulnerabilities
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

QUALYS_SECRET_ARN = os.environ.get('QUALYS_SECRET_ARN')
CACHE_TABLE_NAME = os.environ.get('CACHE_TABLE_NAME')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ECR_ROLE_NAME = os.environ.get('ECR_ROLE_NAME', 'qualys-ecr-scan-role')

ECR_IMAGE_PATTERN = re.compile(
    r'^(\d+)\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([^:@]+)(?::([^@]+))?(?:@(sha256:[a-f0-9]+))?$'
)


def dispatch(event, context):
    """
    Main dispatcher - routes to appropriate handler based on action.

    Step Functions calls this with:
    {
        "action": "parse_event|check_cache|get_registry|submit_scan|...",
        "input": { ... event data ... }
    }
    """
    action = event.get('action', 'unknown')
    data = event.get('input', event)

    logger.info(f"Action: {action}, Trigger: {data.get('trigger_type', 'unknown')}")

    handlers = {
        'parse_event': handle_parse_event,
        'check_cache': handle_check_cache,
        'get_registry': handle_get_registry,
        'submit_scan': handle_submit_scan,
        'check_status': handle_check_status,
        'get_results': handle_get_results,
        'notify': handle_notify,
        'notify_failure': handle_notify_failure
    }

    handler = handlers.get(action)
    if not handler:
        raise ValueError(f"Unknown action: {action}")

    return handler(data)


def parse_ecr_image(image_uri):
    """
    Parse ECR image URI into components.

    Returns: {account, region, repository, tag, digest} or None if not ECR
    """
    match = ECR_IMAGE_PATTERN.match(image_uri)
    if not match:
        return None

    account, region, repo, tag, digest = match.groups()
    return {
        'account_id': account,
        'region': region,
        'repository': repo,
        'tag': tag or 'latest',
        'digest': digest,
        'image_uri': image_uri
    }


def extract_images_from_containers(containers):
    """Extract ECR images from container definitions."""
    images = []
    for container in containers:
        image_uri = container.get('image', '')
        parsed = parse_ecr_image(image_uri)
        if parsed:
            parsed['container_name'] = container.get('name', 'unknown')
            images.append(parsed)
        else:
            logger.info(f"Skipping non-ECR image: {image_uri[:50]}...")
    return images


def get_task_definition_images(task_def_arn, region):
    """Fetch task definition and extract ECR images."""
    ecs = boto3.client('ecs', region_name=region)

    response = ecs.describe_task_definition(taskDefinition=task_def_arn)
    task_def = response.get('taskDefinition', {})
    containers = task_def.get('containerDefinitions', [])

    return extract_images_from_containers(containers)


def get_ecr_role_arn(account_id: str) -> str:
    """Get the IAM role ARN for ECR access in the specified account."""
    return f"arn:aws:iam::{account_id}:role/{ECR_ROLE_NAME}"


def handle_parse_event(data):
    """
    Parse ECS event and extract ECR images to scan.

    Handles:
    - task_definition: RegisterTaskDefinition event
    - run_task: RunTask event
    - service: CreateService/UpdateService event
    """
    trigger_type = data.get('trigger_type')
    account_id = data.get('account_id')
    region = data.get('region', 'us-east-1')

    images = []

    if trigger_type == 'task_definition':
        # Containers are directly in the event
        containers = data.get('containers', [])
        if isinstance(containers, str):
            containers = json.loads(containers)
        images = extract_images_from_containers(containers)
        logger.info(f"TaskDef event: found {len(images)} ECR images")

    elif trigger_type in ['run_task', 'service']:
        # Need to fetch task definition to get images
        task_def_arn = data.get('task_definition_arn')
        if task_def_arn:
            images = get_task_definition_images(task_def_arn, region)
            logger.info(f"{trigger_type} event: found {len(images)} ECR images in {task_def_arn}")

    if not images:
        logger.info("No ECR images found in event")
        return {
            **data,
            'images': [],
            'has_images': False
        }

    # Return first image for processing (workflow handles one at a time)
    # For multiple images, the workflow should be triggered multiple times
    image = images[0]

    return {
        'trigger_type': trigger_type,
        'task_definition_arn': data.get('task_definition_arn'),
        'cluster': data.get('cluster'),
        'service_name': data.get('service_name'),
        'account_id': image.get('account_id', account_id),
        'region': image.get('region', region),
        'repository': image['repository'],
        'tag': image['tag'],
        'digest': image.get('digest'),
        'image_uri': image['image_uri'],
        'container_name': image.get('container_name'),
        'all_images': images,
        'has_images': True,
        'max_polls': data.get('max_polls', 30),
        'wait_seconds': data.get('wait_seconds', 60)
    }


def handle_check_cache(data):
    """Check if image was recently scanned."""
    # Use digest if available, otherwise use repo:tag as cache key
    cache_key = data.get('digest') or f"{data.get('repository')}:{data.get('tag', 'latest')}"

    if not CACHE_TABLE_NAME:
        return {**data, 'cached': False}

    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(CACHE_TABLE_NAME)
        response = table.get_item(Key={'imageDigest': cache_key})

        if 'Item' in response:
            ttl = response['Item'].get('ttl', 0)
            if ttl > int(datetime.now().timestamp()):
                logger.info(f"Cache hit for {data.get('repository')}")
                return {**data, 'cached': True, 'cached_result': response['Item'].get('result')}

        return {**data, 'cached': False}
    except Exception as e:
        logger.warning(f"Cache check failed: {e}")
        return {**data, 'cached': False}


def handle_get_registry(data):
    """Get Qualys registry UUID, or create if not found."""
    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    account_id = data.get('account_id')
    region = data.get('region', 'us-east-1')
    registry_name = f"ecr-{account_id}-{region}"
    role_arn = get_ecr_role_arn(account_id)

    result = get_or_create_registry(
        creds,
        registry_name,
        account_id,
        region,
        role_arn
    )

    if not result.get('registry_uuid'):
        raise Exception(f"Registry for {account_id}/{region} not found: {result.get('error')}")

    if result.get('created'):
        logger.info(f"Created new registry: {registry_name}")
    else:
        logger.info(f"Found existing registry: {result['registry_uuid'][:8]}...")

    return {
        **data,
        'registry_uuid': result['registry_uuid'],
        'registry_name': registry_name,
        'registry_created': result.get('created', False)
    }


def handle_submit_scan(data):
    """Submit on-demand scan to Qualys."""
    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    result = submit_on_demand_scan(
        creds,
        data['registry_uuid'],
        data['repository'],
        data.get('tag', 'latest')
    )

    if result['status_code'] not in [200, 201, 202]:
        raise Exception(f"Scan submit failed: HTTP {result['status_code']}")

    logger.info(f"Scan submitted for {data['repository']}:{data.get('tag', 'latest')}")
    return {
        **data,
        'scan_submitted': True,
        'schedule_name': result['schedule_name'],
        'poll_count': 0
    }


def handle_check_status(data):
    """Check if scan is complete."""
    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    # Build image identifier for Qualys
    image_id = data.get('digest') or f"{data['repository']}:{data.get('tag', 'latest')}"
    status = get_image_scan_status(creds, image_id)

    poll_count = data.get('poll_count', 0) + 1
    logger.info(f"Poll #{poll_count}: status={status['status']}")

    return {
        **data,
        'scan_complete': status['status'] == 'complete',
        'scan_found': status.get('found', False),
        'poll_count': poll_count
    }


def handle_get_results(data):
    """Get scan results and cache them."""
    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    image_id = data.get('digest') or f"{data['repository']}:{data.get('tag', 'latest')}"
    results = get_image_vulnerabilities(creds, image_id)

    scan_result = {
        'summary': results['summary'],
        'scanned_at': datetime.now().isoformat(),
        'vulnerabilities': results['vulnerabilities'][:10],
        'trigger_type': data.get('trigger_type'),
        'task_definition': data.get('task_definition_arn'),
        'service': data.get('service_name')
    }

    # Cache result
    cache_key = data.get('digest') or f"{data['repository']}:{data.get('tag', 'latest')}"
    if CACHE_TABLE_NAME:
        try:
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(CACHE_TABLE_NAME)
            table.put_item(Item={
                'imageDigest': cache_key,
                'repository': data['repository'],
                'tag': data.get('tag'),
                'result': scan_result,
                'ttl': int((datetime.now() + timedelta(hours=24)).timestamp())
            })
        except Exception as e:
            logger.warning(f"Cache write failed: {e}")

    logger.info(f"Results for {data['repository']}: {results['summary']}")
    return {**data, 'scan_result': scan_result}


def handle_notify(data):
    """Send notification with results."""
    if not SNS_TOPIC_ARN:
        return {**data, 'notified': False}

    summary = data.get('scan_result', {}).get('summary', {})

    # Only notify for critical/high
    if summary.get('critical', 0) == 0 and summary.get('high', 0) == 0:
        logger.info("No critical/high vulns - skipping notification")
        return {**data, 'notified': False}

    sns = boto3.client('sns')

    message = {
        'trigger': data.get('trigger_type'),
        'repository': data['repository'],
        'tag': data.get('tag'),
        'task_definition': data.get('task_definition_arn'),
        'service': data.get('service_name'),
        'cluster': data.get('cluster'),
        'vulnerabilities': summary,
        'scanned_at': data.get('scan_result', {}).get('scanned_at')
    }

    subject = f"Fargate Scan: {data['repository']} - {summary.get('critical', 0)}C/{summary.get('high', 0)}H"

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=json.dumps(message, indent=2)
    )

    logger.info("Notification sent")
    return {**data, 'notified': True}


def handle_notify_failure(data):
    """Send failure notification."""
    if not SNS_TOPIC_ARN:
        return {**data, 'notified': False}

    sns = boto3.client('sns')

    message = {
        'trigger': data.get('trigger_type'),
        'repository': data.get('repository'),
        'task_definition': data.get('task_definition_arn'),
        'error': data.get('error', 'Unknown error'),
        'status': 'failed'
    }

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Scan Failed: {data.get('repository', 'unknown')}"[:100],
        Message=json.dumps(message, indent=2)
    )

    return {**data, 'notified': True, 'status': 'failed'}
