// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
    Construct,
  } from 'constructs';
  import {  
    Duration,
    Aws,
    Fn,
    aws_iam as iam,
    aws_logs as logs,
    aws_dynamodb as ddb,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as sfnTasks,
    aws_lambda as lambda, 
  } from 'aws-cdk-lib';
import * as path from 'path'

import { addCfnNagSuppressRules } from "./constructs-stack";

export interface MonitorStateMachineProps {
    taskTable: ddb.Table,
    centralSnsArn: string,
}

export class MonitorStateMachine extends Construct {

    readonly taskMonitorStateMachineArn: string

    constructor(scope: Construct, id: string, props: MonitorStateMachineProps) {
        super(scope, id);

        const checkFinderJobStatusFnPolicy = new iam.Policy(this, 'CheckFinderJobStatusFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    actions: [
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "cloudwatch:GetMetricStatistics",
                        "cloudformation:DescribeStacks"
                    ],
                    resources: [
                        `*`,
                    ]
                }),
                new iam.PolicyStatement({
                    actions: [
                      "logs:CreateLogGroup",
                      "logs:CreateLogStream",
                      "logs:PutLogEvents"
                    ],
                    resources: [
                      '*'
                    ]
                })
            ]
        });

        const cfnCheckFinderJobStatusFnPolicy = checkFinderJobStatusFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfnCheckFinderJobStatusFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
            },
            {
                id: 'F39',
                reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
            }
        ])

        const checkFinderJobStatusFn = new lambda.Function(this, 'CheckFinderJobStatusFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'check_finder_job_status.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Check Finder Job Status Handler'
        })

        const cfnCheckFinderJobStatusFn = checkFinderJobStatusFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnCheckFinderJobStatusFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])
        checkFinderJobStatusFn.role?.attachInlinePolicy(checkFinderJobStatusFnPolicy)
        props.taskTable.grantReadWriteData(checkFinderJobStatusFn)

        const checkSqsStatusFnPolicy = new iam.Policy(this, 'CheckSqsStatusFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    actions: [
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "cloudwatch:GetMetricStatistics",
                        "cloudformation:DescribeStacks",
                        "sqs:GetQueueUrl",
                        "sqs:GetQueueAttributes",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources: [
                        `*`,
                    ]
                }),
                new iam.PolicyStatement({
                    actions: [
                        "states:ListExecutions",
                        "states:ListStateMachines"
                    ],
                    resources: [
                        `*`,
                    ]
                })
            ]
        });
        const cfncheckSqsStatusFnPolicy = checkSqsStatusFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfncheckSqsStatusFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
            },
            {
                id: 'F39',
                reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
            }
        ])

        const checkSqsStatusFn = new lambda.Function(this, 'CheckSqsStatusFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'check_sqs_status.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Check SQS Status Handler'
        })

        const cfnCheckSqsStatusFn = checkSqsStatusFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnCheckSqsStatusFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])

        checkSqsStatusFn.role?.attachInlinePolicy(checkSqsStatusFnPolicy)
        props.taskTable.grantReadWriteData(checkSqsStatusFn)

        const checkTransferCompleteFnPolicy = new iam.Policy(this, 'CheckTransferCompleteFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    actions: [
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "cloudwatch:GetMetricStatistics",
                        "cloudformation:DescribeStacks",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources: [
                        `*`,
                    ]
                })
            ]
        });
        const cfnCheckTransferCompleteFnPolicy = checkTransferCompleteFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfnCheckTransferCompleteFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
            },
            {
                id: 'F39',
                reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
            }
        ])

        const checkTransferCompleteFn = new lambda.Function(this, 'CheckTransferCompleteFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'check_transfer_complete.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Check Transfer Complete Handler'
        })

        const cfnCheckTransferCompleteFn = checkTransferCompleteFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnCheckTransferCompleteFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])

        checkTransferCompleteFn.role?.attachInlinePolicy(checkTransferCompleteFnPolicy)
        props.taskTable.grantReadWriteData(checkTransferCompleteFn)

        const changeAsgSizeFnPolicy = new iam.Policy(this, 'ChangeAsgSizeFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    resources: ["*"],
                    actions: [
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "cloudwatch:GetMetricStatistics",
                        "cloudformation:DescribeStacks",
                        "autoscaling:UpdateAutoScalingGroup",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                })
            ]
        });
        const cfnChangeAsgSizeFnPolicy = changeAsgSizeFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfnChangeAsgSizeFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
            },
            {
                id: 'F39',
                reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
            }
        ])

        const changeAsgSizeFn = new lambda.Function(this, 'ChangeAsgSizeFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'change_asg_size.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Change ASG Size Handler'
        })

        const cfnChangeAsgSizeFn = changeAsgSizeFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnChangeAsgSizeFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])

        changeAsgSizeFn.role?.attachInlinePolicy(changeAsgSizeFnPolicy)
        props.taskTable.grantReadWriteData(changeAsgSizeFn)

        const checkIsOneTimeTransferFnPolicy = new iam.Policy(this, 'CheckIsOneTimeTransferFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    actions: [
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "cloudwatch:GetMetricStatistics",
                        "cloudformation:DescribeStacks",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources: [
                        `*`,
                    ]
                })
            ]
        });
        const cfnCheckIsOneTimeTransferFnPolicy = checkIsOneTimeTransferFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfnCheckIsOneTimeTransferFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
            },
            {
                id: 'F39',
                reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
            }
        ])

        const checkIsOneTimeTransferFn = new lambda.Function(this, 'CheckIsOneTimeTransferFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'check_is_onetime_transfer_task.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Check Is One Time Transfer Task Handler'
        })

        const cfnCheckIsOneTimeTransferFn = checkIsOneTimeTransferFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnCheckIsOneTimeTransferFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])

        checkIsOneTimeTransferFn.role?.attachInlinePolicy(checkIsOneTimeTransferFnPolicy)
        props.taskTable.grantReadWriteData(checkIsOneTimeTransferFn)

        const sendSnsNotificationFnPolicy = new iam.Policy(this, 'SendSnsNotificationFnPolicy', {
            statements: [
                new iam.PolicyStatement({
                    actions: [
                        "sns:Publish",
                    ],
                    resources: [props.centralSnsArn]
                }),
                new iam.PolicyStatement({
                    actions: [
                      "logs:CreateLogGroup",
                      "logs:CreateLogStream",
                      "logs:PutLogEvents"
                    ],
                    resources: [
                      '*'
                    ]
                  }),
                new iam.PolicyStatement({
                    actions: [
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:GenerateDataKey",
                        "kms:ImportKeyMaterial",
                        "kms:TagResource",
                        "kms:UntagResource",
                        "kms:UpdateAlias",
                        "kms:GetPublicKey",
                        "kms:ListKeyPolicies",
                        "kms:ListRetirableGrants",
                        "kms:PutKeyPolicy",
                        "kms:GetKeyPolicy",
                        "kms:ListResourceTags",
                        "kms:RetireGrant",
                        "kms:ListGrants",
                        "kms:GetParametersForImport",
                        "kms:DescribeCustomKeyStores",
                        "kms:ListKeys",
                        "kms:GetKeyRotationStatus",
                        "kms:ListAliases",
                        "kms:RevokeGrant",
                        "kms:DescribeKey",
                        "kms:CreateGrant"
                    ],
                    resources: [`arn:${Aws.PARTITION}:kms:${Aws.REGION}:${Aws.ACCOUNT_ID}:key/*`]
                }),
            ]
        });
        const cfnSendSnsNotificationFnPolicy = sendSnsNotificationFnPolicy.node.defaultChild as iam.CfnPolicy
        addCfnNagSuppressRules(cfnSendSnsNotificationFnPolicy, [
            {
                id: 'F4',
                reason: 'This policy requires related actions'
            }
        ])
        const sendSnsNotificationFn = new lambda.Function(this, 'SendSnsNotificationFn', {
            runtime: lambda.Runtime.PYTHON_3_13,
            code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
            handler: 'send_sns_notification.lambda_handler',
            environment: {
                TRANSFER_TASK_TABLE: props.taskTable.tableName,
                CENTRAL_SNS_ARN: props.centralSnsArn
            },
            memorySize: 512,
            timeout: Duration.seconds(300),
            description: 'Data Transfer Hub - Task Monitor Send Task Alarm to SNS'
        })

        const cfnSendSnsNotificationFn = sendSnsNotificationFn.node.defaultChild as lambda.CfnFunction
        addCfnNagSuppressRules(cfnSendSnsNotificationFn, [
            {
                id: 'W58',
                reason: 'Lambda function already has permission to write CloudWatch Logs'
            }
        ])

        sendSnsNotificationFn.role?.attachInlinePolicy(sendSnsNotificationFnPolicy)
        props.taskTable.grantReadWriteData(sendSnsNotificationFn)

        const checkFinderJobStatusTask = new sfnTasks.LambdaInvoke(this, 'Check Finder Job Status', {
            lambdaFunction: checkFinderJobStatusFn,
            outputPath: '$.Payload'
        })

        const checkSQSStatusTask = new sfnTasks.LambdaInvoke(this, 'Check SQS Status', {
            lambdaFunction: checkSqsStatusFn,
            outputPath: '$.Payload'
        })

        const scareDownAsgTask = new sfnTasks.LambdaInvoke(this, 'Scare Down ASG', {
            lambdaFunction: changeAsgSizeFn,
            outputPath: '$.Payload'
        })


        const checkWorkerJobCompleteTask = new sfnTasks.LambdaInvoke(this, 'Check Worker Job Complete', {
            lambdaFunction: checkTransferCompleteFn,
            outputPath: '$.Payload'
        })

        const checkIsOneTimeTransferTask = new sfnTasks.LambdaInvoke(this, 'Check is One Time Job', {
            lambdaFunction: checkIsOneTimeTransferFn,
            outputPath: '$.Payload'
        })

        const sendSnsNotificationTask = new sfnTasks.LambdaInvoke(this, 'Send Alarm to Central SNS', {
            lambdaFunction: sendSnsNotificationFn,
            outputPath: '$.Payload'
        })

        const waitFor1MinuteForFinder = new sfn.Wait(this, 'Wait for 1 minute for Finder', {
            time: sfn.WaitTime.duration(Duration.minutes(1))
        })
        waitFor1MinuteForFinder.next(checkFinderJobStatusTask)

        const waitFor1MinuteForSqs = new sfn.Wait(this, 'Wait for 1 minute for SQS', {
            time: sfn.WaitTime.duration(Duration.minutes(1))
        })
        waitFor1MinuteForSqs.next(checkSQSStatusTask)

        const taskMonitoringComplete = new sfn.Succeed(this, 'Task Monitor Complete')
        scareDownAsgTask.next(sendSnsNotificationTask
            .next(taskMonitoringComplete))

        const checkSqsEmptyChoice = new sfn.Choice(this, 'SQS and SFN are Empty?')
            .when(sfn.Condition.stringEquals('$.isEmpty', 'true'),
                new sfn.Choice(this, 'Has Checked 3 times?')
                    .when(
                        sfn.Condition.numberLessThan("$.checkRound", 3),
                        waitFor1MinuteForSqs
                    )
                    .otherwise(checkWorkerJobCompleteTask
                        .next(scareDownAsgTask)
                    )
            )
            .otherwise(waitFor1MinuteForSqs)

        const checkOneTimeTransferJobChoice = new sfn.Choice(this, 'Is One Time Job?')
            .when(sfn.Condition.stringEquals('$.isOneTime', 'true'), checkSQSStatusTask
                .next(checkSqsEmptyChoice))
            .otherwise(taskMonitoringComplete);

        checkIsOneTimeTransferTask.next(checkOneTimeTransferJobChoice)

        const checkFinderStatusChoice = new sfn.Choice(this, 'Check Finder Status Choice')
            .when(sfn.Condition.stringEquals('$.status', 'ERROR'), scareDownAsgTask)
            .when(sfn.Condition.stringEquals('$.status', 'COMPLETED'), checkIsOneTimeTransferTask)
            .when(sfn.Condition.stringEquals('$.status', 'NO_NEED'), taskMonitoringComplete)
            .otherwise(waitFor1MinuteForFinder)

        const definition = checkFinderJobStatusTask
            .next(checkFinderStatusChoice)

        // State machine log group 
        const logGroup = new logs.LogGroup(this, "ErrorLogGroup", {
            logGroupName: `/aws/vendedlogs/states/${Fn.select(
                6,
                Fn.split(":", checkFinderJobStatusFn.functionArn)
            )}-SM-Monitor`,
        });
        const cfnLogGroup = logGroup.node.defaultChild as logs.CfnLogGroup
        addCfnNagSuppressRules(cfnLogGroup, [
            {
                id: 'W84',
                reason: 'log group is encrypted with the default master key'
            }
        ])
        const taskMonitorStateMachine = new sfn.StateMachine(this, 'taskMonitorStateMachine', {
            definitionBody: sfn.DefinitionBody.fromChainable(definition),
            logs: {
                destination: logGroup,
                level: sfn.LogLevel.ALL,
            },
            tracingEnabled: true,
        })

        this.taskMonitorStateMachineArn = taskMonitorStateMachine.stateMachineArn

    }

}