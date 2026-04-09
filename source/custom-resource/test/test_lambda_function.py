# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import boto3
import json
from moto import mock_aws


@pytest.fixture
def s3_client():

    with mock_aws():
        region = os.environ.get("AWS_REGION")

        s3 = boto3.resource("s3", region_name=region)
        # Create the buckets
        default_bucket = os.environ.get("WEB_BUCKET_NAME")
        s3.create_bucket(Bucket=default_bucket)
        yield


@pytest.fixture
def iam_client():

    with mock_aws():
        region = os.environ.get("AWS_REGION")

        iam = boto3.client("iam", region_name=region)
        policy_json = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:us-east-1:123456789012:*",
                    "Effect": "Allow",
                }
            ],
        }
        response = iam.create_policy(
            PolicyName="mock-central-assume-role-policy",
            PolicyDocument=json.dumps(policy_json),
        )
        os.environ["CENTRAL_ASSUME_ROLE_POLICY_ARN"] = response["Policy"]["Arn"]
        yield


@pytest.fixture
def cloudfront_client():

    with mock_aws():
        region = os.environ.get("AWS_REGION")

        cloudfront = boto3.client("cloudfront", region_name=region)

        response = cloudfront.create_distribution(
            DistributionConfig=dict(
                CallerReference="firstOne",
                Aliases=dict(Quantity=1, Items=["mydomain.com"]),
                DefaultRootObject="index.html",
                Comment="Test distribution",
                Enabled=True,
                Origins=dict(
                    Quantity=1,
                    Items=[
                        dict(
                            Id="1",
                            DomainName="mydomain.com.s3.amazonaws.com",
                            S3OriginConfig=dict(OriginAccessIdentity=""),
                        )
                    ],
                ),
                DefaultCacheBehavior=dict(
                    TargetOriginId="1",
                    ViewerProtocolPolicy="redirect-to-https",
                    TrustedSigners=dict(Quantity=0, Enabled=False),
                    ForwardedValues=dict(
                        Cookies={"Forward": "all"},
                        Headers=dict(Quantity=0),
                        QueryString=False,
                        QueryStringCacheKeys=dict(Quantity=0),
                    ),
                    MinTTL=1000,
                ),
            )
        )
        os.environ["CLOUDFRONT_DISTRIBUTION_ID"] = response["Distribution"]["Id"]
        yield


def test_lambda_function(s3_client, cloudfront_client, iam_client):
    import lambda_function

    result = lambda_function.lambda_handler(None, None)
    # Expect Execute successfully.
    assert result == "OK"

    region = os.environ.get("AWS_REGION")
    s3 = boto3.resource("s3", region_name=region)

    default_bucket = os.environ.get("WEB_BUCKET_NAME")

    # Expect Config file is uploaded to S3
    obj = s3.Object(default_bucket, "aws-exports.json").get()
    assert "ContentLength" in obj
    assert obj["ContentLength"] > 0