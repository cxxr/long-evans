# Long-evans AWS Test Backdoor

This is a test script which can be run to see if your monitoring catches
someone uploading an AWS Lambda backdoor. It also includes a delete function
which removes itself.

The included AWS Lambda backdoor does nothing as it is just a test, but a more
interesting one could be written easily.

This is to be used for research and penetration testing purposes only. Do not
use this to commit any crime.

# Usage

Example usage:

    $ python long-evans.py --region us-west-2 --disable-logging

To remove, specify the same arguments as you did when you created, but add
`--delete`.

## Help

    usage: long-evans.py [-h] [--region REGION] [--disable-logging]
                        [--re-enable-logging] [--source SOURCE]
                        [--runtime RUNTIME] [--handler HANDLER]
                        [--role-name ROLE_NAME] [--function-name FUNCTION_NAME]
                        [--rule-name RULE_NAME] [--delete]

    Long-Evans AWS Remote Access Tool

    optional arguments:
    -h, --help            show this help message and exit
    --region REGION       Which region to set the default client to. Default:
                            us-west-2
    --disable-logging     Disables CloudTrail logging
    --re-enable-logging   Re-enables CloudTrail logging after disabling
    --source SOURCE       Which python file to use as the lambda
    --runtime RUNTIME     Python runtime to use, either python2.7 or python3.6
    --handler HANDLER     Which function in the Python file to call in AWS
                            Lambda
    --role-name ROLE_NAME
                            The name of the admin role to create
    --function-name FUNCTION_NAME
                            The name of the lambda function to create
    --rule-name RULE_NAME
                            The name of the CloudWatch Events rule to create
    --delete              Tries to undo long-evans in this account

    Github: https://github.com/cxxr/long-evans
