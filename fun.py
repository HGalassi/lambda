import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define AppConfig write actions
APPCONFIG_WRITE_ACTIONS = [
    "appconfig:CreateApplication",
    "appconfig:UpdateApplication",
    "appconfig:DeleteApplication",
    "appconfig:CreateEnvironment",
    "appconfig:UpdateEnvironment",
    "appconfig:DeleteEnvironment",
    "appconfig:CreateConfigurationProfile",
    "appconfig:UpdateConfigurationProfile",
    "appconfig:DeleteConfigurationProfile",
    "appconfig:CreateHostedConfigurationVersion",
    "appconfig:StartDeployment",
    "appconfig:StopDeployment"
]

def list_attached_policies(iam_client, role_name):
    policies = []
    paginator = iam_client.get_paginator('list_attached_role_policies')
    for page in paginator.paginate(RoleName=role_name):
        policies.extend(page['AttachedPolicies'])
    return policies

def get_policy_document(iam_client, policy_arn):
    version_id = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)['PolicyVersion']['Document']
    return policy_document

def detach_policy(iam_client, role_name, policy_arn):
    iam_client.detach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

def is_appconfig_write_policy(policy_document):
    for statement in policy_document.get('Statement', []):
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if any(action in APPCONFIG_WRITE_ACTIONS for action in actions):
            return True
    return False

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    role_name = event.get('role_name')

    if not role_name:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'role_name is required'})
        }

    try:
        policies = list_attached_policies(iam_client, role_name)
        for policy in policies:
            policy_document = get_policy_document(iam_client, policy['PolicyArn'])
            if is_appconfig_write_policy(policy_document):
                detach_policy(iam_client, role_name, policy['PolicyArn'])
                logger.info(f"Detached AppConfig write policy {policy['PolicyArn']} from role {role_name}")

        return {
            'statusCode': 200,
            'body': json.dumps({'message': f"Checked {len(policies)} policies for role {role_name}"})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }