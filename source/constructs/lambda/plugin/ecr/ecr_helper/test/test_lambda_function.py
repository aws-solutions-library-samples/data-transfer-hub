# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
from moto import mock_aws


@pytest.fixture
def ecr_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        ecr = boto3.client("ecr", region_name=region)
        # create a ecr repository 01
        repository_name = "test-repository-01"
        ecr.create_repository(repositoryName=repository_name)

        # upload a image to above ecr repository
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:01"}}',
            imageTag="latest"
        )
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:01"}}',
            imageTag="v1.3.0"
        )
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:02"}}',
            imageTag="v1.2.0"
        )

        # create a ecr repository 02
        repository_name = "ubuntu"
        ecr.create_repository(repositoryName=repository_name)

        # upload a image to above ecr repository
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:01"}}',
            imageTag="latest"
        )
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:02"}}',
            imageTag="v2.3.0"
        )
        ecr.put_image(
            repositoryName=repository_name,
            imageManifest='{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": "sha256:03"}}',
            imageTag="v2.2.0"
        )

        yield


@pytest.fixture
def ssm_client():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        ssm = boto3.client("ssm", region_name=region)
        ssm.put_parameter(
            Name="test_ssm_param_name",
            Value="""
ubuntu:v2.2.0, 
test-repository-01
""",
            Type='String'
        )

        yield


# Test Amazon ECR with all images
@pytest.fixture
def env_variables_01():
    """Mocked AWS evivronment variables such as AWS credentials and region"""
    os.environ["AWS_ACCESS_KEY_ID"] = "mocked-aws-access-key-id"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "mocked-aws-secret-access-key"
    os.environ["AWS_SESSION_TOKEN"] = "mocked-aws-session-token"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    os.environ["SOURCE_TYPE"] = "Amazon_ECR"
    os.environ["SRC_LIST"] = "ALL"
    os.environ["SRC_REGION"] = "us-east-1"
    os.environ["SRC_ACCOUNT_ID"] = ""
    os.environ["SELECTED_IMAGE_PARAM"] = ""
    os.environ["SRC_CREDENTIAL_NAME"] = "test_key"

    yield


def test_lambda_function_01(ecr_client, env_variables_01):
    import lambda_function

    response = lambda_function.lambda_handler(
        {},
        None,
    )
    assert len(response['Payload']) == 6


# Test Amazon ECR with selected images
@pytest.fixture
def env_variables_02():
    """Mocked AWS evivronment variables such as AWS credentials and region"""
    os.environ["AWS_ACCESS_KEY_ID"] = "mocked-aws-access-key-id"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "mocked-aws-secret-access-key"
    os.environ["AWS_SESSION_TOKEN"] = "mocked-aws-session-token"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    os.environ["SOURCE_TYPE"] = "Amazon_ECR"
    os.environ["SRC_LIST"] = "SELECTED"
    os.environ["SRC_REGION"] = "us-east-1"
    os.environ["SRC_ACCOUNT_ID"] = ""
    os.environ["SELECTED_IMAGE_PARAM"] = "test_ssm_param_name"
    os.environ["SRC_CREDENTIAL_NAME"] = "test_key"

    yield


def test_lambda_function_02(ecr_client, ssm_client, env_variables_02):
    import lambda_function

    response = lambda_function.lambda_handler(
        {},
        None,
    )
    assert len(response['Payload']) == 2
    assert response['Payload'] == [{'repositoryName': 'ubuntu', 'imageTag': 'v2.2.0', 'multiArchOption': 'all'},
                                   {'repositoryName': 'test-repository-01', 'imageTag': 'latest', 'multiArchOption': 'all'}]


# Test Public repos
@pytest.fixture
def env_variables_03():
    """Mocked AWS evivronment variables such as AWS credentials and region"""
    os.environ["AWS_ACCESS_KEY_ID"] = "mocked-aws-access-key-id"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "mocked-aws-secret-access-key"
    os.environ["AWS_SESSION_TOKEN"] = "mocked-aws-session-token"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    os.environ["SOURCE_TYPE"] = "Public"
    os.environ["SRC_LIST"] = "SELECTED"
    os.environ["SRC_REGION"] = "us-east-1"
    os.environ["SRC_ACCOUNT_ID"] = ""
    os.environ["SELECTED_IMAGE_PARAM"] = "test_ssm_param_name"
    os.environ["SRC_CREDENTIAL_NAME"] = "test_key"

    yield


def test_lambda_function_03(ecr_client, ssm_client, env_variables_03):
    import lambda_function

    response = lambda_function.lambda_handler(
        {},
        None,
    )
    assert len(response['Payload']) == 2
    assert response['Payload'] == [{'repositoryName': 'ubuntu', 'imageTag': 'v2.2.0', 'multiArchOption': 'all'},
                                   {'repositoryName': 'test-repository-01', 'imageTag': 'latest', 'multiArchOption': 'all'}]


# Test Amazon ECR repos with tag ALL_TAGS
@pytest.fixture
def env_variables_04():
    """Mocked AWS evivronment variables such as AWS credentials and region"""
    os.environ["AWS_ACCESS_KEY_ID"] = "mocked-aws-access-key-id"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "mocked-aws-secret-access-key"
    os.environ["AWS_SESSION_TOKEN"] = "mocked-aws-session-token"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    os.environ["SOURCE_TYPE"] = "Amazon_ECR"
    os.environ["SRC_LIST"] = "SELECTED"
    os.environ["SRC_REGION"] = "us-east-1"
    os.environ["SRC_ACCOUNT_ID"] = ""
    os.environ["SELECTED_IMAGE_PARAM"] = "test_ssm_param_name_all"
    os.environ["SRC_CREDENTIAL_NAME"] = "test_key"

    yield


@pytest.fixture
def ssm_client_02():
    with mock_aws():
        region = os.environ.get("AWS_REGION")
        ssm = boto3.client("ssm", region_name=region)
        ssm.put_parameter(
            Name="test_ssm_param_name_all",
            Value="""
ubuntu:ALL_TAGS, 
test-repository-01
""",
            Type='String'
        )

        yield


def test_lambda_function_04(ecr_client, ssm_client_02, env_variables_04):
    import lambda_function

    response = lambda_function.lambda_handler(
        {},
        None,
    )
    assert len(response['Payload']) == 4
    assert response['Payload'] == [{'repositoryName': 'ubuntu', 'imageTag': 'latest', 'multiArchOption': 'all'},
                                   {'repositoryName': 'ubuntu', 'imageTag': 'v2.3.0', 'multiArchOption': 'all'},
                                   {'repositoryName': 'ubuntu', 'imageTag': 'v2.2.0', 'multiArchOption': 'all'},
                                   {'repositoryName': 'test-repository-01', 'imageTag': 'latest', 'multiArchOption': 'all'}]
