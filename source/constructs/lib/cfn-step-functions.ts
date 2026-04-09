// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  Construct,
} from 'constructs';
import {
  Aws,
  Duration,
  CfnOutput,
  aws_stepfunctions as sfn,
  aws_stepfunctions_tasks as sfnTasks,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  Fn
} from 'aws-cdk-lib';

import * as path from 'path'

import { addCfnNagSuppressRules } from "./constructs-stack";

export interface CloudFormationStateMachineProps {
  taskTableName: string,
  taskTableArn: string,
  taskMonitorSfnArn: string
}

export class CloudFormationStateMachine extends Construct {

  readonly stateMachineArn: string

  constructor(scope: Construct, id: string, props: CloudFormationStateMachineProps) {
    super(scope, id);

    const createTaskCfnFn = new lambda.Function(this, 'CreateTaskCfnFn', {
      runtime: lambda.Runtime.PYTHON_3_9,
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/cdk'), {
      }),
      handler: 'lambda_function.create_task_cfn',
      environment: {
        TASK_TABLE: props.taskTableName
      },
      memorySize: 512,
      timeout: Duration.seconds(60),
      description: 'Data Transfer Hub - Create Task'
    })

    const cfnCreateTaskCfnFn = createTaskCfnFn.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfnCreateTaskCfnFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    const stopTaskCfnFn = new lambda.Function(this, 'StopTaskCfnFn', {
      runtime: lambda.Runtime.PYTHON_3_9,
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/cdk'), {
      }),
      handler: 'lambda_function.stop_task_cfn',
      environment: {
        TASK_TABLE: props.taskTableName
      },
      memorySize: 512,
      timeout: Duration.seconds(60),
      description: 'Data Transfer Hub - Stop Task'
    })

    const cfnStopTaskCfnFn = stopTaskCfnFn.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfnStopTaskCfnFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    const taskFnPolicy = new iam.Policy(this, 'TaskFnPolicy', {
      statements: [
        new iam.PolicyStatement({
          actions: [
            "states:CreateStateMachine",
            "states:DeleteStateMachine",
            "states:DescribeStateMachine",
            "states:TagResource",
          ],
          resources: [
            `arn:${Aws.PARTITION}:states:${Aws.REGION}:${Aws.ACCOUNT_ID}:activity:DTH*`,
            `arn:${Aws.PARTITION}:states:${Aws.REGION}:${Aws.ACCOUNT_ID}:stateMachine:DTH*`,
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "autoscaling:CreateLaunchConfiguration",
            "autoscaling:CreateAutoScalingGroup",
            "autoscaling:DeleteAutoScalingGroup",
            "autoscaling:DeleteLaunchConfiguration",
            "autoscaling:UpdateAutoScalingGroup",
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:EnableMetricsCollection",
            "autoscaling:DescribeScalingActivities",
            "autoscaling:PutScalingPolicy",
            "autoscaling:DeletePolicy",
            "autoscaling:DescribePolicies",
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "SNS:CreateTopic",
            "SNS:GetTopicAttributes",
            "SNS:DeleteTopic",
            "SNS:Subscribe",
            "SNS:Unsubscribe",
            "SNS:TagResource"
          ],
          resources: [`arn:${Aws.PARTITION}:sns:${Aws.REGION}:${Aws.ACCOUNT_ID}:DTH*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "ssm:GetParameters",
            "ssm:PutParameter",
            "ssm:AddTagsToResource",
            "ssm:DeleteParameter",
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "events:PutRule",
            "events:RemoveTargets",
            "events:DescribeRule",
            "events:PutTargets",
            "events:DeleteRule",
          ],
          resources: [`arn:${Aws.PARTITION}:events:${Aws.REGION}:${Aws.ACCOUNT_ID}:rule/DTH*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "cloudformation:Create*",
            "cloudformation:Update*",
            "cloudformation:Delete*",
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "s3:PutBucketNotification",
            "s3:GetBucketNotification",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:GetBucketLocation",
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "dynamodb:CreateTable",
            "dynamodb:DescribeTable",
            "dynamodb:DeleteTable",
            "dynamodb:UpdateItem",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:UpdateContinuousBackups",
            "dynamodb:UpdateContinuousBackups",
            "dynamodb:TagResource",
            "dynamodb:ListTagsOfResource",
          ],
          resources: [
            `arn:${Aws.PARTITION}:dynamodb:${Aws.REGION}:${Aws.ACCOUNT_ID}:table/DTH*`,
            props.taskTableArn
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "sqs:SendMessage",
            "sqs:CreateQueue",
            "sqs:GetQueueAttributes",
            "sqs:SetQueueAttributes",
            "sqs:DeleteQueue",
            "sqs:TagQueue",
          ],
          resources: [`arn:${Aws.PARTITION}:sqs:${Aws.REGION}:${Aws.ACCOUNT_ID}:DTH*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "ec2:createTags",
            "ec2:DescribeImages",
            "ec2:DescribeVpcs",
            "ec2:DescribeInstances",
            "ec2:DescribeSubnets",
            "ec2:DescribeVolumes",
            "ec2:DescribeTags",
            "ec2:CreateSecurityGroup",
            "ec2:DeleteSecurityGroup",
            "ec2:LaunchTemplate",
            "ec2:CreateLaunchTemplate",
            "ec2:DeleteLaunchTemplate",
            'ec2:CreateLaunchTemplateVersion',
            'ec2:DeleteLaunchTemplateVersions',
            'ec2:GetLaunchTemplateData',
            "ec2:DescribeSecurityGroups",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:DescribeLaunchTemplates",
            "ec2:DescribeLaunchTemplateVersions",
            'ec2:Describe*',
            'ec2:AuthorizeSecurityGroupIngress',
            'ec2:RevokeSecurityGroupIngress',
            'ec2:RunInstances',
            'ec2:TerminateInstances',
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "ecs:RunTask",
            "ecs:ListTasks",
            "ecs:RegisterTaskDefinition",
            "ecs:DeregisterTaskDefinition",
            "ecs:DescribeTaskDefinition",
            "ecs:TagResource",
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "logs:CreateLogGroup",
            "logs:DeleteLogGroup",
            "logs:DeleteLogStream",
            "logs:CreateLogStream",
            "logs:PutRetentionPolicy",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            "logs:GetLogEvents",
            "logs:PutMetricFilter",
            "logs:DeleteMetricFilter",
            "logs:DescribeMetricFilters",
            "logs:PutLogEvents",
            "logs:TagResource"
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "cloudwatch:ListMetrics",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:Describe*",
            "cloudwatch:PutMetricData",
            "cloudwatch:PutMetricAlarm",
            "cloudwatch:GetDashboard",
            "cloudwatch:DeleteDashboards",
            "cloudwatch:DeleteAlarms",
            "cloudwatch:PutDashboard",
            "cloudwatch:ListDashboards",
          ],
          resources: [
            `*`
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "tag:TagResources"
          ],
          resources: [
            `*`
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "iam:CreateInstanceProfile",
            "iam:CreateRole",
            "iam:PutRolePolicy",
            "iam:PassRole",
            "iam:AttachRolePolicy",
            "iam:AddRoleToInstanceProfile",
            "iam:RemoveRoleFromInstanceProfile",
            "iam:DeleteInstanceProfile",
            "iam:GetRole",
            "iam:GetPolicy",
            "iam:GetRolePolicy",
            "iam:ListRoles",
            "iam:ListPolicies",
            "iam:ListRolePolicies",
            "iam:DeleteRole",
            "iam:DeleteRolePolicy",
            "iam:DetachRolePolicy",
            "iam:GetInstanceProfile",
            "iam:TagRole",
          ],
          resources: [
            `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:instance-profile/DTH*`,
            `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:role/DTH*`,
            `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:policy/DTH*`,
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "lambda:InvokeFunction",
            "lambda:AddPermission",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
            "lambda:DeleteEventSourceMapping",
            "lambda:PublishLayerVersion",
            "lambda:DeleteLayerVersion",
            "lambda:DeleteFunction",
            "lambda:RemovePermission",
            "lambda:UpdateFunctionConfiguration",
            "lambda:UpdateFunctionCode",
            "lambda:PublishVersion",
            "lambda:TagResource",
            "lambda:Get*",
            "lambda:List*",
          ],
          resources: [
            `*`
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "kms:CreateKey",
            "kms:CreateAlias",
            "kms:CreateGrant",
            "kms:DeleteAlias",
            "kms:DescribeKey",
            "kms:DisableKey",
            "kms:EnableKey",
            "kms:EnableKeyRotation",
            "kms:GetKeyRotationStatus",
            "kms:GetKeyPolicy",
            "kms:GetParametersForImport",
            "kms:ImportKeyMaterial",
            "kms:PutKeyPolicy",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:UpdateAlias",
            "kms:ScheduleKeyDeletion",
          ],
          resources: [
            `*`,
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "ecr:CreateRepository",
            "ecr:CompleteLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:InitiateLayerUpload",
            "ecr:PutImage",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "ecr:GetAuthorizationToken"
          ],
          resources: [`*`]
        }),
        new iam.PolicyStatement({
          actions: [
            "iam:CreateServiceLinkedRole",
          ],
          resources: [
            `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling`
          ]
        }),
      ]
    });

    createTaskCfnFn.role?.attachInlinePolicy(taskFnPolicy)
    stopTaskCfnFn.role?.attachInlinePolicy(taskFnPolicy)

    const cfnTaskFnPolicy = taskFnPolicy.node.defaultChild as iam.CfnPolicy
    addCfnNagSuppressRules(cfnTaskFnPolicy, [
      {
        id: 'F4',
        reason: 'This policy requires related actions in order to start/delete other cloudformation stacks of the plugin with many other services'
      },
      {
        id: 'F39',
        reason: 'This policy requires related PassRole actions to unknown resources created by plugin cloudformation stacks'
      },
      {
        id: 'W76',
        reason: 'This policy needs to be able to start/delete other complex cloudformation stacks'
      },
      {
        id: 'W12',
        reason: 'This policy needs to be able to start/delete other cloudformation stacks of the plugin with unknown resources names'
      }
    ])

    const queryTaskCfnFn = new lambda.Function(this, 'QueryTaskCfnFn', {
      runtime: lambda.Runtime.PYTHON_3_9,
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/cdk'), {
      }),
      handler: 'lambda_function.query_task_cfn',
      environment: {
        TASK_TABLE: props.taskTableName
      },
      memorySize: 512,
      timeout: Duration.seconds(60),
      description: 'Data Transfer Hub - Query Task'
    })

    const cfnQueryTaskCfnFn = queryTaskCfnFn.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfnQueryTaskCfnFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    queryTaskCfnFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [props.taskTableArn],
      actions: [
        'dynamodb:Query',
        'dynamodb:UpdateItem'
      ]
    }))
    queryTaskCfnFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [`arn:${Aws.PARTITION}:cloudformation:${Aws.REGION}:${Aws.ACCOUNT_ID}:stack/DTH*`],
      actions: [
        'cloudformation:DescribeStacks'
      ]
    }))
    queryTaskCfnFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: ["*"],
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
    }))

    const startMonitorFlowFn = new lambda.Function(this, 'StartMonitorFlowFn', {
      runtime: lambda.Runtime.PYTHON_3_9,
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task-monitoring')),
      handler: 'start_monitor_flow.lambda_handler',
      environment: {
        MONITOR_SFN_ARN: props.taskMonitorSfnArn
      },
      memorySize: 512,
      timeout: Duration.seconds(60),
      description: 'Data Transfer Hub - Start Task Monitoring Flow Handler'
    })
    startMonitorFlowFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [props.taskMonitorSfnArn],
      actions: [
        'states:StartExecution'
      ]
    }))
    startMonitorFlowFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: ["*"],
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
    }))

    const cfnStartMonitorFlowFn = startMonitorFlowFn.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfnStartMonitorFlowFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    const startStackTask = new sfnTasks.LambdaInvoke(this, 'Start Stack', {
      lambdaFunction: createTaskCfnFn,
      outputPath: '$.Payload'
    })

    const stopStackTask = new sfnTasks.LambdaInvoke(this, 'Stop Stack', {
      lambdaFunction: stopTaskCfnFn,
      outputPath: '$.Payload'
    })

    const queryStackStatus = new sfnTasks.LambdaInvoke(this, 'Query Stack Status', {
      lambdaFunction: queryTaskCfnFn,
      outputPath: '$.Payload'
    })

    const startMonitorFlow = new sfnTasks.LambdaInvoke(this, 'Start Monitoring Flow', {
      lambdaFunction: startMonitorFlowFn,
      outputPath: '$.Payload'
    })

    const stackOperationSucceed = new sfn.Succeed(this, 'Stack Ops Succeed')
    const stackOperationFailed = new sfn.Fail(this, 'Stack Ops Failed')

    const waitFor5Seconds = new sfn.Wait(this, 'Wait for 5 seconds', {
      time: sfn.WaitTime.duration(Duration.seconds(5))
    })

    const queryStackStatusChoice = new sfn.Choice(this, 'Query Stack Status Choice')
      .when(
        sfn.Condition.stringEquals('$.stackStatus.S', 'CREATE_COMPLETE')
        , startMonitorFlow.next(stackOperationSucceed))
      .when(
        sfn.Condition.or(
          sfn.Condition.stringEquals('$.stackStatus.S', 'UPDATE_COMPLETE'),
          sfn.Condition.stringEquals('$.stackStatus.S', 'DELETE_COMPLETE')
        )
        , stackOperationSucceed)
      .when(
        sfn.Condition.or(
          sfn.Condition.stringEquals('$.stackStatus.S', 'CREATE_FAILED'),
          sfn.Condition.stringEquals('$.stackStatus.S', 'DELETE_FAILED'),
          sfn.Condition.stringEquals('$.stackStatus.S', 'UPDATE_ROLLBACK_FAILED'),
          sfn.Condition.stringEquals('$.stackStatus.S', 'ROLLBACK_COMPLETE')
        )
        , stackOperationFailed
      )
      .otherwise(waitFor5Seconds)


    const definition = new sfn.Choice(this, 'Stack Action Choice')
      .when(
        sfn.Condition.stringEquals('$.action', 'START'), startStackTask.next(waitFor5Seconds))
      .when(
        sfn.Condition.stringEquals('$.action', 'STOP'), stopStackTask.next(waitFor5Seconds))

    waitFor5Seconds.next(queryStackStatus).next(queryStackStatusChoice)

    // State machine log group 
    const logGroup = new logs.LogGroup(this, "CfnDeploySMLogGroup", {
      logGroupName: `/aws/vendedlogs/states/${Fn.select(
          6,
          Fn.split(":", startMonitorFlowFn.functionArn)
      )}-CfnDeploy-SM`,
    });
    const cfnLogGroup = logGroup.node.defaultChild as logs.CfnLogGroup
    addCfnNagSuppressRules(cfnLogGroup, [
      {
          id: 'W84',
          reason: 'log group is encrypted with the default master key'
      }
    ])
    const stateMachine = new sfn.StateMachine(this, 'CfnDeploymentStateMachine', {
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: Duration.minutes(120),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
      tracingEnabled: true,
    })

    new CfnOutput(this, 'CfnDeploymentStateMachineArn', {
      value: stateMachine.stateMachineArn,
      description: 'StateMachine Arn',
      exportName: 'StateMachineArn'
    })

    this.stateMachineArn = stateMachine.stateMachineArn

  }

}