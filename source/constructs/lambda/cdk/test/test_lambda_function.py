# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
import json
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
    "stackStatus": "CREATE_IN_PROGRESS",
    "progress": "IN_PROGRESS",
    "stackId": "arn:aws:cloudformation:ap-southeast-1:123456789012:stack/DTH-S3EC2-sKKUJ/9dd81670-0a96-11ed-9cc1-021ceb982872",
    "templateUrl": "https://my-assets.s3.amazonaws.com/dth-ec2.template",
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
def cfn_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        client = boto3.client("cloudformation", region_name=region)
        response = client.create_stack(
            StackName='DTH-S3EC2-sKKUJ',
            TemplateBody='{"Resources": {}}',
        )
        os.environ['MOCK_CFN_ID'] = response['StackId']
        yield


@pytest.fixture
def s3_client():
    with mock_aws():
        # Dummy CloudFormation Template
        dummy_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Stack 1",
            "Resources": {
                "EC2Instance1": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": "EXAMPLE_AMI_ID",
                        "KeyName": "dummy",
                        "InstanceType": "t2.micro",
                        "Tags": [
                            {"Key": "Description", "Value": "Test tag"},
                            {"Key": "Name", "Value": "Name tag for tests"},
                        ],
                    },
                }
            },
        }
        region = os.environ.get("AWS_REGION")
        s3 = boto3.client('s3', region_name=region)
        s3.create_bucket(Bucket='my-assets')
        s3.put_object(Bucket='my-assets', Key='dth-ec2.template',
                      Body=json.dumps(dummy_template))
        yield


def test_lambda_function_stop(ddb_client, cfn_client):
    from lambda_function import stop_task_cfn

    response = stop_task_cfn(
        {
            "errMessage": "2023/09/08 03:20:33 Error listing objects in destination bucket - operation error S3: ListObjectsV2, https response error StatusCode: 301, RequestID: G409Z7BSZ23H88KY, HostID: klnWHkzuSRrBXl0sK//srXAkXCTvLcZPPys2IwRNcPpocVsGV+dvNK23UwWiKIPVp7/i3ZPZqyI=, api error PermanentRedirect: The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint.",
            "stackId": "arn:aws:cloudformation:us-west-1:123456789012:stack/DTH-S3EC2-8748c/1fb54110-4df6-11ee-b76a-06061c3a0e9f",
            "createdAt": "2023-09-08T03:16:37.609935Z",
            "stackOutputs": [
                {
                    "OutputKey": "CommonSplitPartTableName68CB1187",
                    "OutputValue": "DTH-S3EC2-8748c-S3SplitPartTable-AX7L3SHNN7V1",
                    "Description": "Split Part DynamoDB Table Name"
                }
            ],
            "executionArn": "arn:aws:states:us-west-1:123456789012:execution:APICfnWorkflowCfnDeploymentStateMachineFC154A5B-y2TQO51TD4mD:2dd8afe1-0b02-4bb1-9ef9-0f41e5b458c8",
            "updatedDt": "2023-09-08T03:20:52Z",
            "errCode": "FINDER_ERROR",
            "parameters": [
                {
                    "ParameterValue": "Amazon_S3",
                    "ParameterKey": "srcType"
                }
            ],
            "progress": "ERROR",
            "templateUrl": "https://solutions-features-reference.s3.amazonaws.com/data-transfer-hub/develop/DataTransferS3Stack.template",
            "scheduleType": "FIXED_RATE",
            "description": "",
            "id": "0ff94440-331e-4678-a53c-768c6720db55",
            "stackStatus": "CREATE_COMPLETE",
            "type": "S3EC2",
            "action": "STOP"
        },
        None,
    )

    assert "S" in response.get("id")


def test_lambda_function_create(ddb_client, cfn_client, s3_client):
    from lambda_function import create_task_cfn

    response = create_task_cfn(
        {
            "type": "S3EC2",
            "description": "",
            "scheduleType": "FIXED_RATE",
            "parameters": [
                {
                    "ParameterKey": "srcType",
                    "ParameterValue": "Amazon_S3"
                },
                {
                    "ParameterKey": "srcEndpoint",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "srcBucket",
                    "ParameterValue": "aaaaa"
                },
                {
                    "ParameterKey": "srcPrefix",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "srcPrefixsListFile",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "srcEvent",
                    "ParameterValue": "No"
                },
                {
                    "ParameterKey": "srcRegion",
                    "ParameterValue": "us-east-1"
                },
                {
                    "ParameterKey": "srcInCurrentAccount",
                    "ParameterValue": "false"
                },
                {
                    "ParameterKey": "srcCredentials",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "destBucket",
                    "ParameterValue": "bbbbb"
                },
                {
                    "ParameterKey": "destPrefix",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "destStorageClass",
                    "ParameterValue": "INTELLIGENT_TIERING"
                },
                {
                    "ParameterKey": "destRegion",
                    "ParameterValue": "us-west-2"
                },
                {
                    "ParameterKey": "destInCurrentAccount",
                    "ParameterValue": "true"
                },
                {
                    "ParameterKey": "destCredentials",
                    "ParameterValue": ""
                },
                {
                    "ParameterKey": "includeMetadata",
                    "ParameterValue": "false"
                },
                {
                    "ParameterKey": "isPayerRequest",
                    "ParameterValue": "false"
                },
                {
                    "ParameterKey": "destAcl",
                    "ParameterValue": "bucket-owner-full-control"
                },
                {
                    "ParameterKey": "ec2CronExpression",
                    "ParameterValue": "0 */1 ? * * *"
                },
                {
                    "ParameterKey": "maxCapacity",
                    "ParameterValue": "0"
                },
                {
                    "ParameterKey": "minCapacity",
                    "ParameterValue": "0"
                },
                {
                    "ParameterKey": "desiredCapacity",
                    "ParameterValue": "0"
                },
                {
                    "ParameterKey": "srcSkipCompare",
                    "ParameterValue": "false"
                },
                {
                    "ParameterKey": "finderDepth",
                    "ParameterValue": "0"
                },
                {
                    "ParameterKey": "finderNumber",
                    "ParameterValue": "1"
                },
                {
                    "ParameterKey": "finderEc2Memory",
                    "ParameterValue": "8"
                },
                {
                    "ParameterKey": "workerNumber",
                    "ParameterValue": "4"
                },
                {
                    "ParameterKey": "alarmEmail",
                    "ParameterValue": "xxxxxx"
                },
                {
                    "ParameterKey": "ec2VpcId",
                    "ParameterValue": "vpc-00435d5729dddd5b6"
                },
                {
                    "ParameterKey": "ec2Subnets",
                    "ParameterValue": "subnet-0e0402cd5e17375b2,subnet-0dc128ee46fceac91"
                }
            ],
            "id": "0ff94440-331e-4678-a53c-768c6720db55",
            "templateUrl": "https://my-assets.s3.amazonaws.com/dth-ec2.template",
            "createdAt": "2023-09-08T03:16:37.609935Z",
            "action": "START"
        },
        None,
    )

    assert "S" in response.get("id")


def test_lambda_function_query(ddb_client, cfn_client, s3_client):
    from lambda_function import query_task_cfn

    response = query_task_cfn(
        {
            "stackId": {
                "S": os.environ['MOCK_CFN_ID']
            },
            "createdAt": {
                "S": "2023-09-08T03:16:37.609935Z"
            },
            "stackOutputs": {
                "L": []
            },
            "executionArn": {
                "S": "arn:aws:states:us-west-1:123456789012:execution:APICfnWorkflowCfnDeploymentStateMachineFC154A5B-y2TQO51TD4mD:2dd8afe1-0b02-4bb1-9ef9-0f41e5b458c8"
            },
            "parameters": {
                "L": [
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "Amazon_S3"
                            },
                            "ParameterKey": {
                                "S": "srcType"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "srcEndpoint"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "aaaaa"
                            },
                            "ParameterKey": {
                                "S": "srcBucket"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "srcPrefix"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "srcPrefixsListFile"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "No"
                            },
                            "ParameterKey": {
                                "S": "srcEvent"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "us-east-1"
                            },
                            "ParameterKey": {
                                "S": "srcRegion"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "false"
                            },
                            "ParameterKey": {
                                "S": "srcInCurrentAccount"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "srcCredentials"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "bbbbb"
                            },
                            "ParameterKey": {
                                "S": "destBucket"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "destPrefix"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "INTELLIGENT_TIERING"
                            },
                            "ParameterKey": {
                                "S": "destStorageClass"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "us-west-2"
                            },
                            "ParameterKey": {
                                "S": "destRegion"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "true"
                            },
                            "ParameterKey": {
                                "S": "destInCurrentAccount"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": ""
                            },
                            "ParameterKey": {
                                "S": "destCredentials"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "false"
                            },
                            "ParameterKey": {
                                "S": "includeMetadata"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "false"
                            },
                            "ParameterKey": {
                                "S": "isPayerRequest"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "bucket-owner-full-control"
                            },
                            "ParameterKey": {
                                "S": "destAcl"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "0 */1 ? * * *"
                            },
                            "ParameterKey": {
                                "S": "ec2CronExpression"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "0"
                            },
                            "ParameterKey": {
                                "S": "maxCapacity"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "0"
                            },
                            "ParameterKey": {
                                "S": "minCapacity"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "0"
                            },
                            "ParameterKey": {
                                "S": "desiredCapacity"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "false"
                            },
                            "ParameterKey": {
                                "S": "srcSkipCompare"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "0"
                            },
                            "ParameterKey": {
                                "S": "finderDepth"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "1"
                            },
                            "ParameterKey": {
                                "S": "finderNumber"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "8"
                            },
                            "ParameterKey": {
                                "S": "finderEc2Memory"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "4"
                            },
                            "ParameterKey": {
                                "S": "workerNumber"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "xxxxxx"
                            },
                            "ParameterKey": {
                                "S": "alarmEmail"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "vpc-00435d5729dddd5b6"
                            },
                            "ParameterKey": {
                                "S": "ec2VpcId"
                            }
                        }
                    },
                    {
                        "M": {
                            "ParameterValue": {
                                "S": "subnet-0e0402cd5e17375b2,subnet-0dc128ee46fceac91"
                            },
                            "ParameterKey": {
                                "S": "ec2Subnets"
                            }
                        }
                    }
                ]
            },
            "progress": {
                "S": "STARTING"
            },
            "templateUrl": {
                "S": "https://solutions-features-reference.s3.amazonaws.com/data-transfer-hub/develop/DataTransferS3Stack.template"
            },
            "scheduleType": {
                "S": "FIXED_RATE"
            },
            "description": {
                "S": ""
            },
            "id": {
                "S": "0ff94440-331e-4678-a53c-768c6720db55"
            },
            "stackStatus": {
                "S": "CREATE_IN_PROGRESS"
            },
            "type": {
                "S": "S3EC2"
            }
        },
        None,
    )
    assert "S" in response.get("id")
