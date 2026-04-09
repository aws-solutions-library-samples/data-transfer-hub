# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws


@pytest.fixture
def auto_scaling_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        launch_template_name = os.environ.get("LAUNCH_TEMPLATE_NAME")
        asg_name = os.environ.get("ASG_NAME")
        client = boto3.client("autoscaling", region_name=region)
        client.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            DesiredCapacity=0,
            MinSize=0,
            MaxSize=1,
            LaunchTemplate={
                "LaunchTemplateName": launch_template_name,
                "Version": "$Latest",
            },
            AvailabilityZones=["us-east-1a"],
        )
        yield


@pytest.fixture
def auto_scaling_client_2():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        launch_template_name = os.environ.get("LAUNCH_TEMPLATE_NAME")
        asg_name = os.environ.get("ASG_NAME")
        client = boto3.client("autoscaling", region_name=region)
        client.create_auto_scaling_group(
            AutoScalingGroupName="no_exist",
            DesiredCapacity=0,
            MinSize=0,
            MaxSize=1,
            LaunchTemplate={
                "LaunchTemplateName": launch_template_name,
                "Version": "$Latest",
            },
            AvailabilityZones=["us-east-1a"],
        )
        yield


@pytest.fixture
def ec2_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        launch_template_name = os.environ.get("LAUNCH_TEMPLATE_NAME")
        client = boto3.client("ec2", region_name=region)
        client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            LaunchTemplateData={"ImageId": "ami-12c6146b", "InstanceType": "t2.medium"},
        )
        yield


def test_lambda_function(ec2_client, auto_scaling_client):
    import lambda_function

    # Create a service linked role in a brand new account
    result = lambda_function.lambda_handler(None, None)
    print(result)
    # Expect Execute successfully.
    assert result == 'OK'


def test_lambda_function_2(ec2_client, auto_scaling_client_2):
    import lambda_function

    with pytest.raises(Exception):
        result = lambda_function.lambda_handler(None, None)
        print(result)
        # Expect Execute successfully.
        assert result == 'OK'
