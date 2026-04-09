# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
import boto3

from botocore import config
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

solution_version = os.environ.get("SOLUTION_VERSION", "v1.0.0")
solution_id = os.environ.get("SOLUTION_ID", "SO8001")
user_agent_config = {
    "user_agent_extra": f"AwsSolution/{solution_id}/{solution_version}"
}
default_config = config.Config(**user_agent_config)

default_region = os.environ.get("AWS_REGION")

cwl_client = boto3.client('cloudwatch', config=default_config)
logs_client = boto3.client('logs', config=default_config)
dynamodb_resource = boto3.resource('dynamodb', config=default_config)
cfn_client = boto3.client('cloudformation', config=default_config)
sqs_client = boto3.client('sqs', config=default_config)
sts_client = boto3.client('sts', config=default_config)
asg_client = boto3.client('autoscaling', config=default_config)
sns_client = boto3.client('sns', config=default_config)
sfn_client = boto3.client('stepfunctions', config=default_config)

transfer_task_table_name = os.environ.get('TRANSFER_TASK_TABLE')
transfer_task_table = dynamodb_resource.Table(transfer_task_table_name)
topic_arn = os.environ.get('CENTRAL_SNS_ARN')


class MonitorHelper:
    """Base Class for monitor helper"""

    def __init__(self, task_id):
        self._task_id = task_id

    def get_stack_name(self, stack_id):
        """return the stack name"""
        regex = r"arn:.*?:cloudformation:.*?:.*?:stack/(.*)/.*"
        match_obj = re.match(regex, stack_id, re.I)
        if match_obj:
            stack_name = match_obj.group(1)
        else:
            raise APIException("Error parse stack name.")

        return stack_name

    def get_task_attributes(self, resp, output_description):
        """ Get the task output attributes from ddb
        """
        for stack_output in resp["Item"].get("stackOutputs"):
            if stack_output.get("Description") == output_description:
                return stack_output.get("OutputValue")
        return ""

    def get_task_param(self, resp, param_description):
        """ Get the task param from ddb
        """
        for stack_param in resp["Item"].get("parameters"):
            if stack_param.get("ParameterKey") == param_description:
                return stack_param.get("ParameterValue")
        return ""

    def get_cloudformation_stack_info(self, stack_name, attr_name):
        """
        This function will get the status of cfn stack
        """
        response = cfn_client.describe_stacks(
            StackName=stack_name
        )
        return response.get("Stacks")[0].get(attr_name)

    def update_ddb_task_status(self, update_key_value_dict):
        """This function will update the transfer task info in DDB table.
        Args:
            update_key_value_dict (dict): key-value pair to update
                {
                    'key1': 'value1',
                    'key2': 'value2',
                    'key3': 'value3'
                }
        """
        update_expresssion = "SET #updatedDt= :updatedDt"
        expression_attribute_names = {
            "#updatedDt": "updatedDt"
        }
        expression_attribute_values = {
            ":updatedDt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        for key, value in update_key_value_dict.items():
            update_expresssion += f", #{key} = :{key}"
            expression_attribute_names[f"#{key}"] = key
            expression_attribute_values[f":{key}"] = value

        response = transfer_task_table.update_item(
            Key={"id": self._task_id},
            UpdateExpression=update_expresssion,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info("Successfully updated the ddb")
        else:
            raise APIException("Unable to update the ddb!")


class FinderMonitorHelper(MonitorHelper):
    """Helper Class for Finder Job Monitor"""

    def __init__(self, task_id):
        super().__init__(task_id)
        resp = transfer_task_table.get_item(Key={"id": self._task_id})
        if "Item" not in resp:
            raise APIException("Transfer task Not Found")

        self._finder_log_group_name = self.get_task_attributes(
            resp, "Finder Log Group Name")

    def check_finder_job_status(self):
        """check the finder job status

        Return:
            stream_result: {
                "status": "COMPLETED" | "ERROR" | "SKIPPED" | "IN_PROGRESS" | "NO_NEED",
                "message": "error message",
                "total_object_count": int | -1
            }
        """
        stream_result = {"status": "IN_PROGRESS"}

        if self._finder_log_group_name == "" or self._finder_log_group_name is None:
            # This task is not a S3 transfer task, break the step function.
            return {
                "status": "NO_NEED",
                "arguments": {
                    "id": self._task_id
                }
            }

        log_streams = self._list_log_streams()
        for log_stream in log_streams:
            log_stream_name = log_stream["logStreamName"]
            log_events = self._get_latest_x_log_events(log_stream_name)
            stream_result = self._check_finder_log_events(log_events)

            # find the working / key log stream
            if stream_result["status"] == "SKIPPED":
                continue
            if stream_result["status"] == "ERROR":
                self.update_ddb_task_status({
                    "progress": "ERROR",
                    "errCode": "FINDER_ERROR",
                    "errMessage": stream_result["message"]
                })
                break
            if stream_result["status"] == "COMPLETED":
                self.update_ddb_task_status({
                    "totalObjectCount": stream_result["total_object_count"]
                })
                break
        return {
            "status": stream_result["status"],
            "arguments": {
                "id": self._task_id
            }
        }

    def _check_finder_log_events(self, log_events):
        """This function will check the finder log events to determin wheather the finder job is completed or there is a error.

        Args:
            log_events: log events list, order in event time.

        Return:
            {
                "status": "COMPLETED" | "ERROR" | "SKIPPED" | "IN_PROGRESS",
                "message": "error message",
                "total_object_count": int | -1
            }
        """
        if len(log_events) == 0:
            return {
                "status": "IN_PROGRESS",
                "message": "",
                "total_object_count": -1
            }

        now_time = datetime.utcnow()
        last_log_event_time = datetime.fromtimestamp(
            log_events[-1].get("timestamp") / 1000)

        if "Exit Finder proccess" not in log_events[-1].get("message"):
            # Check for OOM error.
            if self._check_finder_oom(now_time, last_log_event_time):
                return {
                    "status": "ERROR",
                    "message": "Out of memory error detected, please increase Finder Job Memory or use Finder Depth and Finder Number to optimize the job",
                    "total_object_count": -1
                }
            else:
                return {
                    "status": "IN_PROGRESS",
                    "message": "",
                    "total_object_count": -1
                }

        # Check whether the finder job is completed
        if len(log_events) < 2:
            return {
                "status": "SKIPPED",
                "message": "",
                "total_object_count": -1
            }
        last_message = log_events[-1].get("message")
        second_last_message = log_events[-2].get("message")
        if "Exit Finder proccess" in last_message:
            if "Finder Job Completed" in second_last_message:
                # message is like: "Finder Job Completed in 2.65350598s, found 4918 objects in total"
                pattern = re.compile(r"found (\d+) objects")
                match = pattern.search(second_last_message)
                total_object_count = match.group(1)
                return {
                    "status": "COMPLETED",
                    "message": "",
                    "total_object_count": total_object_count
                }
            elif "Queue might not be empty" in second_last_message:
                return {
                    "status": "SKIPPED",
                    "message": "",
                    "total_object_count": -1
                }
            else:
                err_message = ""
                for events in log_events:
                    if ("error" in events.get("message")) or ("Error" in events.get("message")):
                        err_message = events.get("message")
                return {
                    "status": "ERROR",
                    "message": err_message,
                    "total_object_count": -1
                }

    def _check_finder_oom(self, now_time, last_log_event_time):
        """
        This function will check the OOM error of finder log

        Args:
            now_time,
            last_log_event_time

        Return:
            is_oom: True | False
        """
        if (now_time - last_log_event_time).total_seconds() > 300:  # 5 minutes
            return True
        else:
            return False

    def _list_log_streams(self):
        """
        This function will list all the log streams
            in this task's finder log group.
        """
        response = logs_client.describe_log_streams(
            logGroupName=self._finder_log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=50
        )
        log_streams = response.get("logStreams")
        while "NextToken" in response:
            response = logs_client.describe_log_streams(
                logGroupName=self._finder_log_group_name,
                orderBy='LastEventTime',
                descending=True,
                nextToken=response["nextToken"],
                limit=50
            )
            log_streams.extend(response["Accounts"])
        return log_streams

    def _get_latest_x_log_events(self, log_stream_name, limit=50):
        """
        This function will return last x log events.
        """
        response = logs_client.get_log_events(
            logGroupName=self._finder_log_group_name,
            logStreamName=log_stream_name,
            limit=limit
        )
        return response.get("events")


class S3TaskMonitorHelper(MonitorHelper):
    """Helper Class for S3 Transfer Task Monitor"""

    def __init__(self, task_id):
        super().__init__(task_id)
        resp = transfer_task_table.get_item(Key={"id": self._task_id})
        if "Item" not in resp:
            raise APIException("Transfer task Not Found")

        self.stack_id = resp["Item"].get("stackId")
        self.task_type = resp["Item"].get("type")
        self._stack_name = self.get_stack_name(self.stack_id)
        self._name_space = self.get_stack_name(self.stack_id)
        self._sqs_name = self.get_task_attributes(resp, "Queue Name")
        self._sfn_arn = self.get_task_attributes(resp, "SFN ARN")
        self._task_schedule = self.get_task_param(resp, "ec2CronExpression")
        self._finder_object_count = resp["Item"].get("totalObjectCount")
        self._worker_asg_name = self._stack_name + "-Worker-ASG"
        self._stack_create_time = self.get_cloudformation_stack_info(
            self._stack_name, "CreationTime")

    def _get_worker_asg_transferred_task_count(self):
        """
        This function will return the worker asg transsferred task count.
        Here we assume that a one time transfer task will completed in 60 days(3600 seconds * 1440).
        """
        start_time = self._calculate_start_time(self._stack_create_time)
        response = cwl_client.get_metric_statistics(
            Namespace=self._name_space,
            Period=3600,
            StartTime=start_time,
            EndTime=datetime.utcnow(),
            MetricName="TransferredObjects",
            Statistics=['Sum'],
        )
        total_transferred_object_count = 0

        for data_point in response.get("Datapoints"):
            total_transferred_object_count += data_point.get("Sum")

        return int(total_transferred_object_count)

    def _calculate_start_time(self, stack_create_time):
        """
        Args:
            stack_create_time: datetime
        """
        return stack_create_time - timedelta(hours=1)

    def check_sqs_empty(self, check_round):
        """
        This function will check the SQS queue is empty or not .
        After v2.5.0, it will also check the Giant Controller Step Function is completed or not.

        Args:
            check_round
        """
        account_id = sts_client.get_caller_identity()["Account"]
        response = sqs_client.get_queue_url(
            QueueName=self._sqs_name,
            QueueOwnerAWSAccountId=account_id
        )
        queue_url = response.get("QueueUrl")

        response = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                'All',
            ]
        )
        # We will check this value multi-times for the approximate.
        message_available = response["Attributes"].get(
            "ApproximateNumberOfMessages")
        message_in_flight = response["Attributes"].get(
            "ApproximateNumberOfMessagesNotVisible")
        logger.info(
            f"The approximate avaliable message count {message_available} and in flight message cound {message_in_flight}")

        # Get the giant object merging step function status
        sfn_response = sfn_client.list_executions(
            stateMachineArn=self._sfn_arn,
            statusFilter='RUNNING'
        )

        giant_merging_running_task_count = len(sfn_response['executions'])

        if int(message_in_flight) == 0 and int(message_available) == 0 and giant_merging_running_task_count == 0:
            check_round += 1
            return {
                "isEmpty": "true",
                "checkRound": check_round,
                "arguments": {
                    "id": self._task_id
                }
            }

        return {
            "isEmpty": "false",
            "checkRound": check_round,
            "arguments": {
                "id": self._task_id
            }
        }

    def check_transfer_complete(self):
        """This function will check the transfer task is completed or not ."""
        transferred_object_count = self._get_worker_asg_transferred_task_count()

        # One Time Transfer task completed
        if int(transferred_object_count) == int(self._finder_object_count):
            logger.info(
                f"Transfer task is completed, found {self._finder_object_count} objects, transferred {transferred_object_count} objects")
            self.update_ddb_task_status(
                {
                    "progress": "DONE",
                    "transferredObjects": transferred_object_count,
                }
            )

            return {
                "isCompleted": "true",
                "arguments": {
                    "id": self._task_id
                }
            }

        # One Time Transfer task failed
        err_message = f"Transfer task is not completed, found {self._finder_object_count} objects, transferred {transferred_object_count} objects"
        logger.info(err_message)

        self.update_ddb_task_status({
            "progress": "ERROR",
            "transferredObjects": transferred_object_count,
            "errCode": "COMPLETE_CHECK_ERROR",
            "errMessage": err_message
        })
        return {
            "isCompleted": "false",
            "arguments": {
                "id": self._task_id
            }
        }

    def check_is_one_time_task(self):
        """This function will check the transfer task is one time task or not .
        Return:
            true | false
        """
        if self._task_schedule == "":
            return {
                "isOneTime": "true",
                "arguments": {
                    "id": self._task_id
                }
            }

        return {
            "isOneTime": "false",
            "arguments": {
                "id": self._task_id
            }
        }

    def change_asg_size_to_zero(self):
        """This function will change the asg size to zero."""
        try:
            asg_client.update_auto_scaling_group(
                AutoScalingGroupName=self._worker_asg_name,
                DesiredCapacity=0,
                MinSize=0,
            )
            logger.info("Resize the Worker ASG to zero")
        except Exception as err:
            logger.info(
                "Failed to resize worker ASG to zero, please manully resize it.")
            logger.error(err)
            raise err

        return {
            "status": "OK",
            "arguments": {
                "id": self._task_id
            }
        }


class TaskNotificationHelper(MonitorHelper):
    """Helper Class for Task Notification"""

    def __init__(self, task_id):
        super().__init__(task_id)
        resp = transfer_task_table.get_item(Key={"id": self._task_id})
        if "Item" not in resp:
            raise APIException("Transfer task Not Found")

        self.stack_id = resp["Item"].get("stackId")
        self.task_type = resp["Item"].get("type")
        self._stack_name = self.get_stack_name(self.stack_id)
        self._finder_object_count = resp["Item"].get("totalObjectCount")
        self._transferred_object_count = resp["Item"].get("transferredObjects")
        self._err_code = resp["Item"].get("errCode")
        self._err_message = resp["Item"].get("errMessage")
        self._progress = resp["Item"].get("progress")

    def generate_sns_message(self):
        """This function will generate sns message."""
        base_message = f"""
Data Transfer Hub Task Monitoring Notification

Task Type: {self.task_type}
Task Name: {self._stack_name}
Task Id: {self._task_id}
Task Progress: {self._progress}
"""

        if self._progress == "ERROR":
            message = base_message + f"""

Error Code: {self._err_code}
Error Message: {self._err_message}
"""
        else:
            message = base_message + f"""

Transferred Objects: {self._transferred_object_count}
"""

        return message

    def send_sns_notification(self):
        """Send notification to SNS topic"""
        message = self.generate_sns_message()

        try:
            response = sns_client.publish(
                Message=message,
                TopicArn=topic_arn
            )

            logger.info(
                f'Successfully sent SNS notification with message ID: {response["MessageId"]}')
            return 'OK'
        except Exception as err:
            logger.exception(err)
            raise err


class APIException(Exception):
    """Exception class for API"""

    def __init__(self, message, code: str = None):
        if code:
            super().__init__("[{}] {}".format(code, message))
        else:
            super().__init__(message)
