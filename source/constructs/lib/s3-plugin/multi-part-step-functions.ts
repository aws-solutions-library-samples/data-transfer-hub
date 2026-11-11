// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  CfnOutput,
  Duration,
  Aws,
  Fn,
  aws_iam as iam,
  aws_logs as logs,
  aws_dynamodb as ddb,
  aws_stepfunctions as sfn,
  aws_stepfunctions_tasks as sfnTasks,
  aws_lambda as lambda,
  aws_s3 as s3
} from "aws-cdk-lib";
import * as path from "path";

import { addCfnNagSuppressRules } from "../constructs-stack";

export interface MultiPartStateMachineProps {
  splitPartTable: ddb.Table;
  jobTable: ddb.Table;
  destIBucket: s3.IBucket;
  destPrefix: string;
  defaultPolicy: iam.Policy;
  workerLogGroup: logs.ILogGroup;
  destCredentials: string;
  destRegion: string;
}

export class MultiPartStateMachine extends Construct {
  readonly multiPartControllerStateMachine: sfn.StateMachine;

  constructor(scope: Construct, id: string, props: MultiPartStateMachineProps) {
    super(scope, id);

    const checkMultiPartUploadStatusFn = new lambda.Function(
      this,
      "CheckMultiPartUploadStatusFn",
      {
        runtime: lambda.Runtime.PYTHON_3_13,
        code: lambda.AssetCode.fromAsset(
          path.join(__dirname, "../../lambda/plugin/s3/multi-part-controller")
        ),
        handler: "check_multi_part_upload_status.lambda_handler",
        environment: {
          STACK_NAME: Aws.STACK_NAME,
          SOLUTION_VERSION: process.env.VERSION || "v1.0.0",
          SPLIT_PART_TABLE_NAME: props.splitPartTable.tableName,
          DESTINATION_BUCKET_NAME: props.destIBucket.bucketName,
          OBJECT_TRANSFER_TABLE_NAME: props.jobTable.tableName,
          WORKER_LOG_GROUP_NAME: props.workerLogGroup.logGroupName,
          DESTINATION_PREFIX: props.destPrefix
        },
        memorySize: 512,
        timeout: Duration.minutes(15),
        description: "Data Transfer Hub - Multi-Part Check Job Status Handler"
      }
    );
    props.splitPartTable.grantReadWriteData(checkMultiPartUploadStatusFn);
    checkMultiPartUploadStatusFn.role?.attachInlinePolicy(props.defaultPolicy);

    const multiPartUploadResultFn = new lambda.Function(
      this,
      "MultiPartUploadResultFn",
      {
        runtime: lambda.Runtime.PYTHON_3_13,
        code: lambda.AssetCode.fromAsset(
          path.join(__dirname, "../../lambda/plugin/s3/multi-part-controller")
        ),
        handler: "multi_part_upload_result.lambda_handler",
        environment: {
          STACK_NAME: Aws.STACK_NAME,
          SOLUTION_VERSION: process.env.VERSION || "v1.0.0",
          SPLIT_PART_TABLE_NAME: props.splitPartTable.tableName,
          DESTINATION_BUCKET_NAME: props.destIBucket.bucketName,
          OBJECT_TRANSFER_TABLE_NAME: props.jobTable.tableName,
          WORKER_LOG_GROUP_NAME: props.workerLogGroup.logGroupName,
          DEST_CREDENTIALS: props.destCredentials,
          DEST_REGION: props.destRegion,
          DESTINATION_PREFIX: props.destPrefix
        },
        memorySize: 512,
        timeout: Duration.minutes(15),
        description: "Data Transfer Hub - Multi-Part Upload Result Handler"
      }
    );
    props.jobTable.grantReadWriteData(multiPartUploadResultFn);
    props.splitPartTable.grantReadWriteData(multiPartUploadResultFn);
    props.destIBucket.grantReadWrite(multiPartUploadResultFn);
    multiPartUploadResultFn.role?.attachInlinePolicy(props.defaultPolicy);
    props.workerLogGroup.grantRead(multiPartUploadResultFn);
    props.workerLogGroup.grantWrite(multiPartUploadResultFn);

    const checkMultiPartUploadStatusTask = new sfnTasks.LambdaInvoke(
      this,
      "Check Multi-Part Upload Job Status",
      {
        lambdaFunction: checkMultiPartUploadStatusFn,
        outputPath: "$.Payload"
      }
    );

    const multiPartUploadResultTask = new sfnTasks.LambdaInvoke(
      this,
      "Handle Multi-Part Upload Result",
      {
        lambdaFunction: multiPartUploadResultFn,
        outputPath: "$.Payload"
      }
    );

    const waitFor1Minute = new sfn.Wait(this, "Wait for 1 minute", {
      time: sfn.WaitTime.duration(Duration.minutes(1))
    });
    waitFor1Minute.next(checkMultiPartUploadStatusTask);

    const multiPartUploadComplete = new sfn.Succeed(
      this,
      "Multi-Part Upload Complete"
    );

    const multiPartUploadFailed = new sfn.Fail(
      this,
      "Multi-Part Upload Failed"
    );

    const completeMultiPartUploadStatusChoice = new sfn.Choice(
      this,
      "Complete or Abort Multi-Part Upload Job Status Choice"
    )
      .when(
        sfn.Condition.stringEquals("$.status", "COMPLETED"),
        multiPartUploadComplete
      )
      .otherwise(multiPartUploadFailed);

    multiPartUploadResultTask.next(completeMultiPartUploadStatusChoice);

    const checkMultiPartUploadStatusChoice = new sfn.Choice(
      this,
      "Check Multi-Part Upload Job Status Choice"
    )
      .when(
        sfn.Condition.stringEquals("$.status", "ERROR"),
        multiPartUploadResultTask
      )
      .when(
        sfn.Condition.stringEquals("$.status", "COMPLETED"),
        multiPartUploadResultTask
      )
      .otherwise(waitFor1Minute);

    const definition = checkMultiPartUploadStatusTask.next(
      checkMultiPartUploadStatusChoice
    );

    // State machine log group
    const logGroup = new logs.LogGroup(this, "ErrorLogGroup", {
      logGroupName: `/aws/vendedlogs/states/${Fn.select(
        6,
        Fn.split(":", checkMultiPartUploadStatusFn.functionArn)
      )}-MultiPart-Controller`
    });
    const cfnLogGroup = logGroup.node.defaultChild as logs.CfnLogGroup;
    addCfnNagSuppressRules(cfnLogGroup, [
      {
        id: "W84",
        reason: "log group is encrypted with the default master key"
      }
    ]);

    this.multiPartControllerStateMachine = new sfn.StateMachine(
      this,
      "multiPartControllerStateMachine",
      {
        stateMachineName: `${Aws.STACK_NAME}-MultiPart-ControllerSM`,
        definitionBody: sfn.DefinitionBody.fromChainable(definition),
        logs: {
          destination: logGroup,
          level: sfn.LogLevel.ALL
        },
        tracingEnabled: true
      }
    );

    new CfnOutput(this, "SfnArn", {
      value: this.multiPartControllerStateMachine.stateMachineArn,
      description: "SFN ARN"
    });
  }
}
