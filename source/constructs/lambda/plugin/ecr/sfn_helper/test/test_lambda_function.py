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
        os.environ["STATE_MACHINE_ARN"] = response['stateMachineArn']
        yield


def test_lambda_function_04(sfn_client):
    import lambda_function

    lambda_function.lambda_handler(
        {},
        None,
    )