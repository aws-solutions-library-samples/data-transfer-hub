# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws
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
        data_list = [task_info_1]
        with app_log_config_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)
        yield


@pytest.fixture
def logs_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        client = boto3.client('logs', region_name=region)

        log_group_name = os.environ.get("MOCK_LOG_GROUP_NAME")
        client.create_log_group(
            logGroupName=log_group_name,
        )

        for i in range(10):
            log_stream_name = "mock_log_stream_name" + str(i)
            client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            for j in range(100):
                client.put_log_events(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name,
                    logEvents=[
                        {
                            'timestamp': 123,
                            'message': f'hello world id: {j}'
                        },
                    ],
                )
        yield


def test_list_log_streams(logs_client):
    import lambda_function

    result = lambda_function.lambda_handler(
        {
            "arguments": {
                "page": 1,
                "count": 10,
                "logGroupName": os.environ.get("MOCK_LOG_GROUP_NAME")
            },
            "info": {
                "fieldName": "listLogStreams",
                "parentTypeName": "Query",
                "variables": {
                    "page": 1,
                    "count": 10,
                    "logGroupName": os.environ.get("MOCK_LOG_GROUP_NAME")
                },
            },
        },
        None,
    )
    # Expect Execute successfully.
    assert result["total"] == 10


def test_args_error(logs_client):
    import lambda_function

    with pytest.raises(RuntimeError):
        lambda_function.lambda_handler(
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


def test_set_period_time(ddb_client):
    from cwl_metric_data_helper import MetricData

    metricData = MetricData('0ff94440-331e-4678-a53c-768c6720db55')
    assert metricData._set_period_time(1614843400, 1614850000) == 3600


def test_get_sorted_merged_xaxis(ddb_client):
    from cwl_metric_data_helper import MetricData
    metricData = MetricData('0ff94440-331e-4678-a53c-768c6720db55')

    xaxis_array = [
        [1, 2, 3, 4, 5],
        [3, 4, 5],
        [6, 5, 7]
    ]
    merged_xaxis = metricData._get_sorted_merged_xaxis(xaxis_array)
    assert merged_xaxis == [1, 2, 3, 4, 5, 6, 7]


def test_apex_chart_data_adaptor(ddb_client):
    """
    This function will test the _apex_chart_data_adaptor function
    """
    from cwl_metric_data_helper import MetricData
    metricData = MetricData('0ff94440-331e-4678-a53c-768c6720db55')

    merged_xaxis = ['time1', 'time2', 'time3', 'time4']
    data_points_dict_array = [
        {
            "name": "serie_1",
            "datapoints": {
                "time1": 22.0,
                "time2": 23.0,
                "time4": 31.0,
            }
        },
        {
            "name": "serie_2",
            "datapoints": {
                "time3": 27.0,
            }
        }
    ]
    result = metricData._apex_chart_data_adaptor(
        merged_xaxis, data_points_dict_array)

    assert result == {'series': [{'name': 'serie_1', 'data': [22.0, 23.0, -1, 31.0]}, {
        'name': 'serie_2', 'data': [-1, -1, 27.0, -1]}], 'xaxis': {'categories': ['time1', 'time2', 'time3', 'time4']}}

def test_network_graph_helper(ddb_client):
    from cwl_metric_data_helper import MetricDataHelper

    metric_data_helper = MetricDataHelper('0ff94440-331e-4678-a53c-768c6720db55', "Network")
    result = metric_data_helper.get_data(1614843400, 1614850000, 60)
    assert result == {'series': [{'name': 'Network', 'data': []}], 'xaxis': {'categories': []}}


def test_TransferredFailedObjects_graph_helper(ddb_client):
    from cwl_metric_data_helper import MetricDataHelper

    metric_data_helper = MetricDataHelper('0ff94440-331e-4678-a53c-768c6720db55', "TransferredFailedObjects")
    result = metric_data_helper.get_data(1614843400, 1614850000, 60)
    assert result == {'series': [{'data': [], 'name': 'TransferredObjects'}, {'data': [], 'name': 'FailedObjects'}], 'xaxis': {'categories': []}}


def test_RunningWaitingJobHistory_graph_helper(ddb_client):
    from cwl_metric_data_helper import MetricDataHelper

    metric_data_helper = MetricDataHelper('0ff94440-331e-4678-a53c-768c6720db55', "RunningWaitingJobHistory")
    result = metric_data_helper.get_data(1614843400, 1614850000, 60)
    assert result == {'series': [{'data': [], 'name': 'WaitingJob'}, {'data': [], 'name': 'RunningJob'}], 'xaxis': {'categories': []}}


def test_DesiredInServiceInstances_graph_helper(ddb_client):
    from cwl_metric_data_helper import MetricDataHelper

    metric_data_helper = MetricDataHelper('0ff94440-331e-4678-a53c-768c6720db55', "DesiredInServiceInstances")
    result = metric_data_helper.get_data(1614843400, 1614850000, 60)
    assert result == {'series': [{'data': [], 'name': 'DesiredCapacity'}, {'data': [], 'name': 'InServiceInstances'}], 'xaxis': {'categories': []}}


def test_none_exist_graph_helper(ddb_client):
    from cwl_metric_data_helper import MetricDataHelper
    with pytest.raises(RuntimeError):
        metric_data_helper = MetricDataHelper('0ff94440-331e-4678-a53c-768c6720db55', "NoExist")
