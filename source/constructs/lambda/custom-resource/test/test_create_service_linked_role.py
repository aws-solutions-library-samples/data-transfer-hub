# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws


@pytest.fixture
def iam_client():

    with mock_aws():
        region = os.environ.get("AWS_REGION")

        iam = boto3.client("iam", region_name=region)

        yield


def test_lambda_function(iam_client):
    import create_service_linked_role

    # Create a service linked role in a brand new account
    result = create_service_linked_role.lambda_handler(
        {
            "RequestType": "Create",
        },
        None,
    )
    # Expect Execute successfully.
    assert result == "OK"