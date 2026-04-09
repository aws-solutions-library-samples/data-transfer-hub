# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws


part_info_1 = {
    "UploadId": "PpxsD1E.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm.TAJ_67Q2a1GIDnvMVZA6c3FhFDcegFeyHc95tDlwPTf6.z.L2VoBM.C",
    "PartNumber": 1,
    "EndTime": "2023/09/01 02:24:04",
    "EndTimestamp": 1693535044,
    "Etag": "2798abd1fe0a963f01054d2525634047",
    "JobStatus": "PART_DONE",
    "ObjectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin",
    "RetryCount": 0,
    "SpentTime": 3,
    "StartTime": "2023/09/01 02:24:01",
    "StartTimestamp": 1693535041,
    "TotalPartsCount": 3
}

part_info_2 = {
    "UploadId": "PpxsD1E.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm.TAJ_67Q2a1GIDnvMVZA6c3FhFDcegFeyHc95tDlwPTf6.z.L2VoBM.C",
    "PartNumber": 2,
    "EndTime": "2023/09/01 02:24:04",
    "EndTimestamp": 1693535044,
    "Etag": "2798abd1fe0a963f01054d2525634046",
    "JobStatus": "PART_DONE",
    "ObjectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin",
    "RetryCount": 0,
    "SpentTime": 3,
    "StartTime": "2023/09/01 02:24:01",
    "StartTimestamp": 1693535041,
    "TotalPartsCount": 3
}

part_info_3 = {
    "UploadId": "PpxsD1E.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm.TAJ_67Q2a1GIDnvMVZA6c3FhFDcegFeyHc95tDlwPTf6.z.L2VoBM.C",
    "PartNumber": 3,
    "EndTime": "2023/09/01 02:24:04",
    "EndTimestamp": 1693535044,
    "Etag": "2798abd1fe0a963f01054d2525634046",
    "JobStatus": "PART_DONE",
    "ObjectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin",
    "RetryCount": 0,
    "SpentTime": 3,
    "StartTime": "2023/09/01 02:24:01",
    "StartTimestamp": 1693535041,
    "TotalPartsCount": 3
}

item_info_1 = {
    "ObjectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin",
    "EndTime": "2023/09/01 02:25:05",
    "EndTimestamp": 1693535105,
    "Etag": "",
    "JobStatus": "SPLIT_DONE",
    "Sequencer": "",
    "Size": 117576402565,
    "SpentTime": 66,
    "StartTime": "2023/09/01 02:23:59",
    "StartTimestamp": 1693535039
}


@pytest.fixture
def ddb_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        ddb = boto3.resource("dynamodb", region_name=region)
        # Mock App Log Configuration Table
        task_table_name = os.environ.get("SPLIT_PART_TABLE_NAME")
        split_part_table = ddb.create_table(
            TableName=task_table_name,
            KeySchema=[
                {
                    "AttributeName": "UploadId",
                    "KeyType": "HASH"
                },
                {
                    "AttributeName": "PartNumber",
                    "KeyType": "RANGE"  # This specifies the SortKey
                }
            ],
            AttributeDefinitions=[
                {
                    "AttributeName": "UploadId",
                    "AttributeType": "S"
                },
                {
                    "AttributeName": "PartNumber",
                    "AttributeType": "N"  # Assuming PartNumber is a number
                }
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10
            },
        )

        data_list = [part_info_1, part_info_2, part_info_3]
        with split_part_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)

        object_table_name = os.environ.get("OBJECT_TRANSFER_TABLE_NAME")
        object_transfer_table = ddb.create_table(
            TableName=object_table_name,
            KeySchema=[
                {
                    "AttributeName": "ObjectKey",
                    "KeyType": "HASH"
                }
            ],
            AttributeDefinitions=[
                {
                    "AttributeName": "ObjectKey",
                    "AttributeType": "S"
                }
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10
            },
        )
        data_list = [item_info_1]
        with object_transfer_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)
        yield


@pytest.fixture
def s3_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        s3 = boto3.client('s3', region_name=region)

        bucket_name = os.environ.get("DESTINATION_BUCKET_NAME")
        object_key = "v2-5-0-dev-0822/ami-055bae28e98705972.bin"
        s3.create_bucket(Bucket=bucket_name)

        response = s3.create_multipart_upload(
            Bucket=bucket_name, Key=object_key)
        os.environ["MOCK_UPLOAD_ID"] = response['UploadId']


@pytest.fixture
def log_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        logs_client = boto3.client('logs', region_name=region)

        worker_log_group_name = os.environ.get("WORKER_LOG_GROUP_NAME")

        logs_client.create_log_group(logGroupName=worker_log_group_name)


def test_lambda_function(ddb_client, s3_client, log_client):
    """test lambda function"""
    import multi_part_upload_result

    result = multi_part_upload_result.lambda_handler(
        {
            "status": "COMPLETED",
            "arguments": {
                "uploadID": os.environ["MOCK_UPLOAD_ID"],
                "totalPartsCount": 3,
                "objectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin"
            }
        },
        None,
    )
    print(result)
    assert result["status"] == "ERROR"
