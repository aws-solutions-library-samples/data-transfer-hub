# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os

from botocore import config

from util.monitor_helper import S3TaskMonitorHelper

logger = logging.getLogger()
logger.setLevel(logging.INFO)

solution_version = os.environ.get("SOLUTION_VERSION", "v1.0.0")
solution_id = os.environ.get("SOLUTION_ID", "SO8001")
user_agent_config = {
    "user_agent_extra": f"AwsSolution/{solution_id}/{solution_version}"
}
default_config = config.Config(**user_agent_config)


def lambda_handler(event, context):
    # logger.info("Received event: " + json.dumps(event, indent=2))

    args = event["arguments"]
    task_id = args.get("id")
    check_round = event.get("checkRound", 0)

    monitor_helper = S3TaskMonitorHelper(task_id)
    return monitor_helper.check_sqs_empty(check_round)
