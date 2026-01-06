"""AWS policy document enforcement Lambda function.

Monitors and deletes AWS policy documents that don't match required conditions.
"""
import json
import logging
import os
import boto3

events = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

C_OPERATOR = os.environ.get("OPERATOR")
C_KEY = os.environ.get("KEY")
C_VALUE = os.environ.get("VALUE")


def lambda_handler(event=None, _context=None):
    """Main Lambda handler for policy enforcement events."""
    source = event['detail']['eventSource']
    event_name = event['detail']['eventName']
    if event_name == "PutBucketPolicy" and source == "s3.amazonaws.com":
        s3_main(event['detail'])
        return
    if event_name in "CreatePolicyVersion" and source == "iam.amazonaws.com":
        if "errorCode" in event['detail']:
            code = event['detail']['errorCode']
            message = event['detail']['errorMessage']
            logger.warning(f"Policy not updated - {code} {message}")
            return
        iam_main(event['detail'], event_name)
        return
    # Handle inline policies
    logger.warning("Policy not updated - %s %s", code, message)


def s3_main(event):
    """Handle S3 bucket policy events."""
    try:
        bucket_policy = event['requestParameters']['bucketPolicy']
        bucket_name = event['requestParameters']['bucketName']
    except Exception as e:
        logger.error("Failed to parse event, %s", e)
        return
    delete = is_invalid(bucket_policy['Statement'])
    if delete is False:
        logger.info("Bucket policy for %s is valid - no action required", bucket_name)
        return
    logger.info("Bucket policy for %s is invalid - policy will be deleted", bucket_name)
    s3 = boto3.client('s3')
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
        logger.info("Bucket policy deleted")
    except Exception as e:
        logger.error("Failed to delete bucket policy, %s", e)


def iam_main(event, event_name):
    """Handle IAM policy events."""
    try:
        policy = json.loads(event['requestParameters']['policyDocument'])
        if "policyArn" in event['requestParameters']:
            arn = event['requestParameters']['policyArn']
            version_id = event['responseElements']['policyVersion']['versionId']
        else:
            arn = event['responseElements']['policy']['arn']
        policy_name = arn.split('/')[1]
    except Exception as e:
        logger.error("Failed to parse event, %s", e)
        return
    delete = is_invalid(policy.get("Statement", []))
    if delete is False:
        logger.info("Policy %s is valid - no action required", policy_name)
        return
    logger.info("Policy %s is invalid - policy will be deleted", policy_name)
    iam = boto3.client('iam')
    try:
        if event_name == "CreatePolicyVersion":
            old_version = f"v{int(version_id[1:]) - 1}"
            iam.set_default_policy_version(
                PolicyArn=arn,
                VersionId=old_version
            )
            logger.info("PolicyVersion %s set to default", old_version)
            iam.delete_policy_version(
                PolicyArn=arn,
                VersionId=version_id
            )
            logger.info("PolicyVersion %s deleted", version_id)
        else:
            iam.delete_policy(PolicyArn=arn)
            logger.info("Policy deleted")
    except Exception as e:
        logger.error("Failed to delete Policy/PolicyVersion, %s", e)


def is_invalid(statements):
    """Return True if policy does not satisfy condition, otherwise False."""
    for statement in statements:
        if statement['Effect'] == "Deny":
            continue
                    if "AWS" not in statement.get('Principal', {}):
                        continue
                    aws_principals = statement['Principal']['AWS']
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    non_cloudfront_principals = [
                        p for p in aws_principals
                        if not p.startswith("arn:aws:iam::cloudfront:user")
                    ]
                    if not non_cloudfront_principals:
                        continue
                    if "Condition" not in statement or C_OPERATOR not in statement['Condition'] or C_KEY not in statement['Condition'][C_OPERATOR]:
            return True
        key_values = statement['Condition'][C_OPERATOR][C_KEY]
                if isinstance(key_values, str) and key_values != C_VALUE:
            return True
        if isinstance(key_values, list) and C_VALUE not in key_values:
            return True
        if not isinstance(key_values, (str, list)):
            return True
    return False
