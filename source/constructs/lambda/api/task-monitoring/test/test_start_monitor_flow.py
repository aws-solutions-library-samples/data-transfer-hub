# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws

@pytest.fixture
def sfn_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        client = boto3.client('stepfunctions', region_name=region)

        # Set up mock Step Functions server and create a state machine
        state_machine_name = 'test-state-machine'
        response = client.create_state_machine(
            name=state_machine_name,
            definition='{"StartAt": "HelloWorld", "States": {"HelloWorld": {"Type": "Task", "Resource": "arn:aws:lambda:us-east-1:123456789012:function:HelloWorld", "End": true}}}',
            roleArn='arn:aws:iam::123456789012:role/service-role/MyRole'
        )
        os.environ["MONITOR_SFN_ARN"] = response['stateMachineArn']
        yield

def test_lambda_function(sfn_client):
    import start_monitor_flow

    # Create a service linked role in a brand new account
    result = start_monitor_flow.lambda_handler(
        {
            "id": {
                "S": "0ff94440-331e-4678-a53c-768c6720db55"
            }
        },
        None,
    )
    # Expect Execute successfully.
    assert result == "OK"
