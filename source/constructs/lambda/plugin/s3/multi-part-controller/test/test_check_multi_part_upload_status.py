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

part_info_4 = {
    "UploadId": "fake.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm",
    "PartNumber": 1,
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


@pytest.fixture
def ddb_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        ddb = boto3.resource("dynamodb", region_name=region)
        # Mock App Log Configuration Table
        task_table_name = os.environ.get("SPLIT_PART_TABLE_NAME")
        app_log_config_table = ddb.create_table(
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
        data_list = [part_info_1, part_info_2, part_info_3, part_info_4]
        with app_log_config_table.batch_writer() as batch:
            for data in data_list:
                batch.put_item(Item=data)
        yield


def test_lambda_function(ddb_client):
    """test lambda function"""
    import check_multi_part_upload_status

    result = check_multi_part_upload_status.lambda_handler(
        {
            "status": "NOT_COMPLETED",
            "arguments": {
                "uploadID": "PpxsD1E.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm.TAJ_67Q2a1GIDnvMVZA6c3FhFDcegFeyHc95tDlwPTf6.z.L2VoBM.C",
                "totalPartsCount": 3,
                "objectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin"
            }
        },
        None,
    )
    assert result["status"] == "COMPLETED"

    result = check_multi_part_upload_status.lambda_handler(
        {
            "status": "NOT_COMPLETED",
            "arguments": {
                "uploadID": "fake.Hr0VNChyhRk_syuZCzFegskaF8Ag57DSyTJYvki57wTdj50yIQGtKm",
                "totalPartsCount": 3,
                "objectKey": "v2-5-0-dev-0822/ami-055bae28e98705972.bin"
            }
        },
        None,
    )
    assert result["status"] == "NOT_COMPLETED"
