# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws


@pytest.fixture
def secret_manager_client():

    with mock_aws():
        region = os.environ.get("AWS_REGION")

        client = boto3.client("secretsmanager", region_name=region)

        yield


def test_lambda_function(secret_manager_client):
    import api_sm_param

    # Create a service linked role in a brand new account
    result = api_sm_param.lambda_handler(None, None)
    print(result)
    # Expect Execute successfully.
    assert len(result) == 0