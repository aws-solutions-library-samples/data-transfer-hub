# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_dynamodb, mock_autoscaling, mock_ec2, mock_cloudformation

task_info_1 = {
    "id": "0ff94440-331e-4678-a53c-768c6720db55",
    "createdAt": "2022-07-23T14:49:11.524Z",
    "description": "",
    "executionArn": "arn:aws:states:ap-southeast-1:123456789012:execution:APICfnWorkflowCfnDeploymentStateMachineFC154A5B-g5tjKvJSuaqT:6cc7ee05-8618-47d3-bd29-209b18e17310",
    "parameters": [
        {"ParameterKey": "srcType", "ParameterValue": "Amazon_S3"},
        {"ParameterKey": "srcEndpoint", "ParameterValue": ""},
        {"ParameterKey": "srcBucket", "ParameterValue": "noexist"},
        {"ParameterKey": "srcPrefix", "ParameterValue": ""},
        {"ParameterKey": "srcPrefixsListFile", "ParameterValue": ""},
        {"ParameterKey": "srcEvent", "ParameterValue": "No"},
        {"ParameterKey": "srcRegion", "ParameterValue": "ap-southeast-1"},
        {"ParameterKey": "srcInCurrentAccount", "ParameterValue": "false"},
        {"ParameterKey": "srcCredentials", "ParameterValue": "qiniu-key"},
        {"ParameterKey": "destBucket", "ParameterValue": "dth-us-west-2"},
        {"ParameterKey": "destPrefix", "ParameterValue": ""},
        {"ParameterKey": "destStorageClass", "ParameterValue": "STANDARD"},
        {"ParameterKey": "destRegion", "ParameterValue": "us-west-2"},
        {"ParameterKey": "destInCurrentAccount", "ParameterValue": "true"},
        {"ParameterKey": "destCredentials", "ParameterValue": ""},
        {"ParameterKey": "includeMetadata", "ParameterValue": "false"},
        {"ParameterKey": "destAcl", "ParameterValue": "bucket-owner-full-control"},
        {"ParameterKey": "ecsCronExpression", "ParameterValue": "0 */1 ? * * *"},
        {"ParameterKey": "maxCapacity", "ParameterValue": "20"},
        {"ParameterKey": "minCapacity", "ParameterValue": "0"},
        {"ParameterKey": "desiredCapacity", "ParameterValue": "0"},
        {"ParameterKey": "srcSkipCompare", "ParameterValue": "false"},
        {"ParameterKey": "finderDepth", "ParameterValue": "0"},
        {"ParameterKey": "finderNumber", "ParameterValue": "1"},
        {"ParameterKey": "ecsFargateMemory", "ParameterValue": "8192"},
        {"ParameterKey": "workerNumber", "ParameterValue": "4"},
        {"ParameterKey": "alarmEmail", "ParameterValue": "xxxxxx"},
        {"ParameterKey": "ecsVpcId", "ParameterValue": "vpc-0f96aaaa8a4f5c38d"},
        {
            "ParameterKey": "ecsClusterName",
            "ParameterValue": "DataTransferHub-TaskCluster-l77WIQA2Y4ps",
        },
        {
            "ParameterKey": "ecsSubnets",
            "ParameterValue": "subnet-0e416ad949f9b4250,subnet-08fdf96eeb87e9c0d",
        },
    ],
    "progress": "IN_PROGRESS",
    "stackId": "arn:aws:cloudformation:ap-southeast-1:123456789012:stack/DTH-S3EC2-sKKUJ/9dd81670-0a96-11ed-9cc1-021ceb982872",
    "stackOutputs": [
        {
            "Description": "Task Definition Name",
            "OutputKey": "ECSStackTaskDefinitionNameE8E07C57",
            "OutputValue": "DTH-S3EC2-sKKUJ-DTHFinderTask",
        },
        {
            "Description": "Alarm Topic Name",
            "OutputKey": "CommonAlarmTopicName54A80B94",
            "OutputValue": "DTH-S3EC2-sKKUJ-S3TransferAlarmTopic-1Q0IKPEMJV9JJ",
        },
        {
            "Description": "Queue Name",
            "OutputKey": "CommonQueueNameEB26B1B7",
            "OutputValue": "DTH-S3EC2-sKKUJ-S3TransferQueue-lHC3es0HYTJd",
        },
        {
            "Description": "Dead Letter Queue Name",
            "OutputKey": "CommonDLQQueueName98D51C56",
            "OutputValue": "DTH-S3EC2-sKKUJ-S3TransferQueueDLQ-u88iddww7XC0",
        },
        {
            "Description": "DynamoDB Table Name",
            "OutputKey": "CommonTableName4099A6E9",
            "OutputValue": "DTH-S3EC2-sKKUJ-S3TransferTable-1CT4T8M71I9QA",
        },
    ],
    "stackStatus": "CREATE_COMPLETE",
    "templateUrl": "https://aws-gcr-solutions.s3.amazonaws.com/data-transfer-hub-s3/v2.1.0/DataTransferS3Stack-ec2.template",
    "type": "S3EC2",
}


@pytest.fixture
def ddb_client():
    with mock_dynamodb():
        region = os.environ.get("AWS_REGION")
        ddb = boto3.resource("dynamodb", region_name=region)
        # Mock App Log Configuration Table
        task_table_name = os.environ.get("TRANSFER_TASK_TABLE")
        app_log_config_table = ddb.create_table(
            TableName=task_table_name,
            KeySchema=[{
                "AttributeName": "id",
                "KeyType": "HASH"
            }],
            AttributeDefinitions=[{
                "AttributeName": "id",
                "AttributeType": "S"
            }],
            ProvisionedThroughput={
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10
            },
        )
        data_list = [task_info_1]
        with app_log_config_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)
        yield


@pytest.fixture
def auto_scaling_client():
    with mock_autoscaling():
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
    with mock_autoscaling():
        region = os.environ.get("AWS_REGION")
        launch_template_name = os.environ.get("LAUNCH_TEMPLATE_NAME")
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
    with mock_ec2():
        region = os.environ.get("AWS_REGION")
        launch_template_name = os.environ.get("LAUNCH_TEMPLATE_NAME")
        client = boto3.client("ec2", region_name=region)
        client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            LaunchTemplateData={"ImageId": "ami-12c6146b", "InstanceType": "t2.medium"},
        )
        yield

@pytest.fixture
def cfn_client():
    with mock_cloudformation():
        region = os.environ.get("AWS_REGION")
        client = boto3.client("cloudformation", region_name=region)
        client.create_stack(
            StackName='DTH-S3EC2-sKKUJ',
            TemplateBody='{"Resources": {}}',
        )
        yield


def test_lambda_function(cfn_client, ddb_client, ec2_client, auto_scaling_client):
    import change_asg_size

    # Create a service linked role in a brand new account
    result = change_asg_size.lambda_handler(
            {
                "arguments": {
                    "id": "0ff94440-331e-4678-a53c-768c6720db55"
                }
            },
            None,
        )
    print(result)
    # Expect Execute successfully.
    assert result == {
            "status": "OK",
            "arguments": {
                "id": "0ff94440-331e-4678-a53c-768c6720db55"
            }
        }


def test_lambda_function_2(ddb_client, ec2_client, auto_scaling_client_2):
    import change_asg_size

    with pytest.raises(Exception):
        change_asg_size.lambda_handler(
            {
                "arguments": {
                    "id": "0ff94440-331e-4678-a53c-768c6720db55"
                }
            },
            None,
        )
