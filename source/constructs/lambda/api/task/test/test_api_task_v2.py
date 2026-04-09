# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws

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


task_info_2 = {
    "id": "19c9d25f-90ae-4397-98b6-855d75c38473",
    "createdAt": "2024-01-08T06:03:25.680647Z",
    "description": "",
    "executionArn": "arn:aws:states:us-west-2:123456789012:execution:APICfnWorkflowCfnDeploymentStateMachineFC154A5B-fkxpvfKrg7iD:9990ba90-963e-465d-8799-2162b25279ca",
    "parameters": [
        {"ParameterKey": "srcType", "ParameterValue": "Amazon_S3"},
        {"ParameterKey": "srcEndpoint", "ParameterValue": ""},
        {"ParameterKey": "srcBucket", "ParameterValue": "dth-dev-tokyo-kervin-01"},
        {"ParameterKey": "srcPrefix", "ParameterValue": ""},
        {"ParameterKey": "srcPrefixsListFile", "ParameterValue": "prefix_list.txt"},
        {"ParameterKey": "srcPrefixListBucket", "ParameterValue": "prefix_list_bucket"},
        {"ParameterKey": "srcEvent", "ParameterValue": "No"},
        {"ParameterKey": "srcRegion", "ParameterValue": "ap-northeast-1"},
        {"ParameterKey": "srcInCurrentAccount", "ParameterValue": "true"},
        {"ParameterKey": "srcCredentials", "ParameterValue": ""},
        {"ParameterKey": "destBucket", "ParameterValue": "dth-sse-debug-cn-north-1"},
        {"ParameterKey": "destPrefix", "ParameterValue": "v260-dev-e2e-0108-01"},
        {"ParameterKey": "destStorageClass", "ParameterValue": "INTELLIGENT_TIERING"},
        {"ParameterKey": "destRegion", "ParameterValue": "cn-north-1"},
        {"ParameterKey": "destInCurrentAccount", "ParameterValue": "false"},
        {"ParameterKey": "destCredentials", "ParameterValue": "dev-account-dth"},
        {"ParameterKey": "includeMetadata", "ParameterValue": "false"},
        {"ParameterKey": "isPayerRequest", "ParameterValue": "false"},
        {"ParameterKey": "destPutObjectSSEType", "ParameterValue": "AES256"},
        {"ParameterKey": "destPutObjectSSEKmsKeyId", "ParameterValue": ""},
        {"ParameterKey": "destAcl", "ParameterValue": "bucket-owner-full-control"},
        {"ParameterKey": "ec2CronExpression", "ParameterValue": "0 */1 ? * * *"},
        {"ParameterKey": "maxCapacity", "ParameterValue": "20"},
        {"ParameterKey": "minCapacity", "ParameterValue": "1"},
        {"ParameterKey": "desiredCapacity", "ParameterValue": "1"},
        {"ParameterKey": "srcSkipCompare", "ParameterValue": "false"},
        {"ParameterKey": "finderDepth", "ParameterValue": "0"},
        {"ParameterKey": "finderNumber", "ParameterValue": "1"},
        {"ParameterKey": "finderEc2Memory", "ParameterValue": "512"},
        {"ParameterKey": "workerNumber", "ParameterValue": "4"},
        {"ParameterKey": "alarmEmail", "ParameterValue": "xxxxxx"},
        {"ParameterKey": "ec2VpcId", "ParameterValue": "vpc-0ecf829216cbb6f25"},
        {
            "ParameterKey": "ec2Subnets",
            "ParameterValue": "subnet-0f909c9db82df2026,subnet-086fc4c755dfcbac1",
        },
    ],
    "progress": "IN_PROGRESS",
    "scheduleType": "FIXED_RATE",
    "stackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/DTH-S3EC2-ab5f8/a379eaa0-adeb-11ee-bd63-0a997cb6160f",
    "stackOutputs": [
        {
            "Description": "Split Part DynamoDB Table Name",
            "OutputKey": "CommonSplitPartTableName68CB1187",
            "OutputValue": "DTH-S3EC2-ab5f8-S3SplitPartTable-2PIFDU7JHQ4M",
        },
        {
            "Description": "SFN ARN",
            "OutputKey": "MultiPartStateMachineSfnArnFA9E5135",
            "OutputValue": "arn:aws:states:us-west-2:123456789012:stateMachine:DTH-S3EC2-ab5f8-MultiPart-ControllerSM",
        },
        {
            "Description": "Alarm Topic Name",
            "OutputKey": "CommonAlarmTopicName54A80B94",
            "OutputValue": "DTH-S3EC2-ab5f8-S3TransferAlarmTopic-aTXEi0GbJHtH",
        },
        {
            "Description": "Stack Name",
            "OutputKey": "CommonStackName013B3BAB",
            "OutputValue": "DTH-S3EC2-ab5f8",
        },
        {
            "Description": "Worker ASG Name",
            "OutputKey": "EC2WorkerStackWorkerASGName4A04CB6D",
            "OutputValue": "DTH-S3EC2-ab5f8-Worker-ASG",
        },
        {
            "Description": "Queue Name",
            "OutputKey": "CommonQueueNameEB26B1B7",
            "OutputValue": "DTH-S3EC2-ab5f8-S3TransferQueue-swVYDUd40h1z",
        },
        {
            "Description": "Dead Letter Queue Name",
            "OutputKey": "CommonDLQQueueName98D51C56",
            "OutputValue": "DTH-S3EC2-ab5f8-S3TransferQueueDLQ-xTUXojgnYlkB",
        },
        {
            "Description": "DynamoDB Table Name",
            "OutputKey": "CommonTableName4099A6E9",
            "OutputValue": "DTH-S3EC2-ab5f8-S3TransferTable-1EAIM9YBKD15G",
        },
        {
            "Description": "Worker Log Group Name",
            "OutputKey": "EC2WorkerStackWorkerLogGroupName752FB4C3",
            "OutputValue": "DTH-S3EC2-ab5f8-CommonS3RepWorkerLogGroupE38567D7-4OC3GMr616VT",
        },
        {
            "Description": "Finder Log Group Name",
            "OutputKey": "FinderStackFinderLogGroupNameB966FCFB",
            "OutputValue": "DTH-S3EC2-ab5f8-FinderStackFinderLogGroup9408DAAE-SRIf6z1UPORs",
        },
    ],
    "stackStatus": "CREATE_COMPLETE",
    "templateUrl": "https://solutions-features-reference.s3.amazonaws.com/data-transfer-hub/develop/DataTransferS3Stack.template",
    "totalObjectCount": "4",
    "type": "S3EC2",
    "updatedDt": "2024-01-08T06:07:37Z",
}


@pytest.fixture
def ddb_client():
    with mock_aws():
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
        data_list = [task_info_1, task_info_2]
        with app_log_config_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)
        yield


def test_lambda_function(ddb_client):
    import api_task_v2

    # Create a service linked role in a brand new account
    result = api_task_v2.lambda_handler(
        {
            "arguments": {
                "page": 1,
                "count": 10,
            },
            "info": {
                "fieldName": "listTasksV2",
                "parentTypeName": "Query",
                "variables": {"page": 1, "count": 10},
            },
        },
        None,
    )
    # Expect Execute successfully.
    assert result["total"] == 2
    tasks = result["items"]
    specific_task = next(
        (
            task
            for task in tasks
            if task["id"] == "19c9d25f-90ae-4397-98b6-855d75c38473"
        ),
        None,
    )
    assert specific_task is not None

    src_prefix_list_bucket_value = "prefix_list_bucket"
    assert any(
        param["ParameterKey"] == "srcPrefixListBucket"
        and param["ParameterValue"] == src_prefix_list_bucket_value
        for param in specific_task["parameters"]
    )
    assert any(
        param["ParameterKey"] == "srcPrefixListBucket"
        for param in specific_task["parameters"]
    )
    assert any(
        param["ParameterKey"] == "srcPrefixListBucket"
        for param in specific_task["parameters"]
    )

def test_args_error(ddb_client):
    import api_task_v2

    with pytest.raises(RuntimeError):
        api_task_v2.lambda_handler(
            {
                "arguments": {
                    "id": "773cb34e-59de-4a6e-9e87-0e0e9e0ff2a0"
                },
                "info": {
                    "fieldName": "no_exist",
                    "parentTypeName": "Query",
                },
            },
            None,
        )