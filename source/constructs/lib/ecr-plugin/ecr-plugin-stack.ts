// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  Construct,
} from 'constructs';
import {
  Aws,
  Fn,
  Stack,
  StackProps,
  CfnParameter,
  CfnCondition,
  Duration,
  CfnResource,
  RemovalPolicy,
  aws_iam as iam,
  aws_dynamodb as ddb,
  aws_sns as sns,
  aws_kms as kms,
  aws_stepfunctions as sfn,
  aws_stepfunctions_tasks as tasks,
  aws_lambda as lambda,
  aws_ecs as ecs,
  aws_ec2 as ec2,
  aws_ssm as ssm,
  aws_sns_subscriptions as subscriptions,
  aws_events as events,
  aws_events_targets as targets,
  aws_secretsmanager as secretsmanager,
  aws_logs as logs,
  custom_resources as cr
} from 'aws-cdk-lib';

import * as path from 'path';

const { VERSION } = process.env;

/**
 * cfn-nag suppression rule interface
 */
interface CfnNagSuppressRule {
  readonly id: string;
  readonly reason: string;
}


export function addCfnNagSuppressRules(resource: CfnResource, rules: CfnNagSuppressRule[]) {
  resource.addMetadata('cfn_nag', {
    rules_to_suppress: rules
  });
}

/***
 * Main Stack
 */
export class DataTransferECRStack extends Stack {
  private paramGroups: any[] = [];
  private paramLabels: any = {};

  private addToParamGroups(label: string, ...param: string[]) {
    this.paramGroups.push({
      Label: { default: label },
      Parameters: param

    });
  };

  private addToParamLabels(label: string, param: string) {
    this.paramLabels[param] = {
      default: label
    }
  }


  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // The code that defines your stack goes here

    const sourceType = new CfnParameter(this, 'sourceType', {
      description: 'Choose type of source container registry, for example Amazon_ECR, or Public from Docker Hub, gco.io, etc.',
      type: 'String',
      default: 'Amazon_ECR',
      allowedValues: ['Amazon_ECR', 'Public']
    })
    this.addToParamLabels('Source Type', sourceType.logicalId)

    // Only required for ECR
    const srcRegion = new CfnParameter(this, 'srcRegion', {
      description: 'Source Region Name (only required if source type is Amazon ECR), for example, us-west-1',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Source Region Name', srcRegion.logicalId)

    // Only required for ECR
    const srcAccountId = new CfnParameter(this, 'srcAccountId', {
      description: 'Source AWS Account ID (only required if source type is Amazon ECR), leave it blank if source is in current account',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Source AWS Account ID', srcAccountId.logicalId)
    //
    const srcList = new CfnParameter(this, 'srcList', {
      description: 'Type of Source Image List, either ALL or SELECTED, for public registry, please use SELECTED only',
      type: 'String',
      default: 'ALL',
      allowedValues: ['ALL', 'SELECTED']
    })
    this.addToParamLabels('Source Image List Type', srcList.logicalId)

    const srcImageList = new CfnParameter(this, 'srcImageList', {
      description: 'Selected Image List delimited by comma, for example, ubuntu:latest,alpine:latest..., leave it blank if Type is ALL. For ECR source, using ALL_TAGS tag to get all tags.',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Source Image List', srcImageList.logicalId)

    // Currently, only required if source type is ECR
    const srcCredential = new CfnParameter(this, 'srcCredential', {
      description: 'The secret name in Secrets Manager only when using AK/SK credentials to pull images from source Amazon ECR, leave it blank for public registry',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Source Credentials', srcCredential.logicalId)


    const destRegion = new CfnParameter(this, 'destRegion', {
      description: 'Destination Region Name, for example, cn-north-1',
      type: 'String',
    })
    this.addToParamLabels('Destination Region Name', destRegion.logicalId)

    const destAccountId = new CfnParameter(this, 'destAccountId', {
      description: 'Destination AWS Account ID, leave it blank if destination is in current account',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Destination AWS Account ID', destAccountId.logicalId)

    const destPrefix = new CfnParameter(this, 'destPrefix', {
      description: 'Destination Repo Prefix',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Destination Repo Prefix', destPrefix.logicalId)

    const destCredential = new CfnParameter(this, 'destCredential', {
      description: 'The secret name in Secrets Manager only when using AK/SK credentials to push images to destination Amazon ECR',
      type: 'String',
      default: '',
    })
    this.addToParamLabels('Destination Credentials', destCredential.logicalId)

    const includeUntagged = new CfnParameter(this, 'includeUntagged', {
      description: 'Whether to include untagged images in the replication',
      default: "true",
      type: "String",
      allowedValues: ["true", "false"]
    })
    this.addToParamLabels('Include Untagged', includeUntagged.logicalId)

    const ecsClusterName = new CfnParameter(this, 'ecsClusterName', {
      description: 'ECS Cluster Name to run ECS task (Please make sure the cluster exists)',
      type: 'String'
    })
    this.addToParamLabels('ECS Cluster Name', ecsClusterName.logicalId)

    const ecsVpcId = new CfnParameter(this, 'ecsVpcId', {
      description: 'VPC ID to run ECS task, e.g. vpc-bef13dc7',
      type: 'AWS::EC2::VPC::Id'
    })
    this.addToParamLabels('VPC ID', ecsVpcId.logicalId)

    const ecsSubnetA = new CfnParameter(this, 'ecsSubnetA', {
      description: 'First Subnet ID to run ECS task, e.g. subnet-97bfc4cd',
      type: 'AWS::EC2::Subnet::Id'
    })
    this.addToParamLabels('First Subnet ID', ecsSubnetA.logicalId)

    const ecsSubnetB = new CfnParameter(this, 'ecsSubnetB', {
      description: 'Second Subnet ID to run ECS task, e.g. subnet-7ad7de32',
      type: 'AWS::EC2::Subnet::Id'
    })
    this.addToParamLabels('Second Subnet ID', ecsSubnetB.logicalId)

    const alarmEmail = new CfnParameter(this, 'alarmEmail', {
      description: 'Alarm Email address to receive notification in case of any failure',
      // default: '',
      allowedPattern: '\\w[-\\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\\.)+[A-Za-z]{2,14}',
      type: 'String',
    })
    this.addToParamLabels('Alarm Email', alarmEmail.logicalId)

    this.addToParamGroups('Type', sourceType.logicalId)
    this.addToParamGroups('Source Information', srcRegion.logicalId, srcAccountId.logicalId, srcList.logicalId, srcImageList.logicalId, srcCredential.logicalId)
    this.addToParamGroups('Destination Information', destRegion.logicalId, destAccountId.logicalId, destPrefix.logicalId, destCredential.logicalId)
    this.addToParamGroups('ECS Cluster Information', ecsClusterName.logicalId, ecsVpcId.logicalId, ecsSubnetA.logicalId, ecsSubnetB.logicalId)
    this.addToParamGroups('Notification Information', alarmEmail.logicalId)

    this.templateOptions.description = `(SO8003) - Data Transfer Hub - ECR Plugin - Template version ${VERSION}`;

    this.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: this.paramGroups,
        ParameterLabels: this.paramLabels,
      }
    }

    const isSelectedImage = new CfnCondition(this, 'isSelectedImage', {
      expression: Fn.conditionEquals('SELECTED', srcList),
    });


    const isSrcInCurrentAccount = new CfnCondition(this, 'isSrcInCurrentAccount', {
      expression: Fn.conditionAnd(
        // Source Account ID is blank
        Fn.conditionEquals('', srcAccountId),
        // Source Type is Amazon ECR
        Fn.conditionEquals('Amazon_ECR', sourceType)),

    });

    const isDestInCurrentAccount = new CfnCondition(this, 'isDestInCurrentAccount', {
      // Destination in Current Account
      expression: Fn.conditionEquals('', destAccountId),
    });

    const selectedImages = Fn.conditionIf(isSelectedImage.logicalId, srcImageList.valueAsString, 'Not Applicable').toString();


    // Set up SSM for selected image list
    const selectedImageParam = new ssm.StringParameter(this, 'selectedImageParam', {
      description: `Parameter to store the selected image list delimited by comma for stack ${Aws.STACK_NAME}`,
      // parameterName: 'SelectedImageList',
      stringValue: selectedImages,
    });


    // Setup DynamoDB
    const imageTable = new ddb.Table(this, 'ECRTransferTable', {
      partitionKey: { name: 'Image', type: ddb.AttributeType.STRING },
      sortKey: { name: 'Tag', type: ddb.AttributeType.STRING },
      billingMode: ddb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    })

    const cfnTable = imageTable.node.defaultChild as ddb.CfnTable
    addCfnNagSuppressRules(cfnTable, [
      {
        id: 'W74',
        reason: 'This table is set to use DEFAULT encryption, the key is owned by DDB.'
      },
    ])

    const listImagesLambda = new lambda.Function(this, 'ListImagesFunction', {
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../../lambda/plugin/ecr/ecr_helper'), {
      }),
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'lambda_function.lambda_handler',
      memorySize: 256,
      timeout: Duration.minutes(15),
      description: 'Data Transfer Hub ECR Plugin - List Image Handler',
      environment: {
        SOURCE_TYPE: sourceType.valueAsString,
        SRC_ACCOUNT_ID: srcAccountId.valueAsString,
        SRC_LIST: srcList.valueAsString,
        SRC_REGION: srcRegion.valueAsString,
        SRC_CREDENTIAL_NAME: srcCredential.valueAsString,
        SELECTED_IMAGE_PARAM: selectedImageParam.parameterName,
        INCLUDE_UNTAGGED: includeUntagged.valueAsString,
      }
    });

    const srcSecretParam = secretsmanager.Secret.fromSecretNameV2(this, 'srcSecretParam', srcCredential.valueAsString);
    const desSecretParam = secretsmanager.Secret.fromSecretNameV2(this, 'desSecretParam', destCredential.valueAsString);

    listImagesLambda.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "ecr:DescribeRepositories",
          "ecr:DescribeImages",
        ],
        resources: [
          `arn:${Aws.PARTITION}:ecr:${srcRegion.valueAsString}:${Aws.ACCOUNT_ID}:repository/*`
        ]
      })
    );

    selectedImageParam.grantRead(listImagesLambda);
    srcSecretParam.grantRead(listImagesLambda);

    const vpc = ec2.Vpc.fromVpcAttributes(this, 'ECSVpc', {
      vpcId: ecsVpcId.valueAsString,
      availabilityZones: Fn.getAzs(),
      publicSubnetIds: [ecsSubnetA.valueAsString, ecsSubnetB.valueAsString]
    })

    const cluster = ecs.Cluster.fromClusterAttributes(this, 'ECSCluster', {
      clusterName: ecsClusterName.valueAsString,
      vpc: vpc,
      securityGroups: []
    })

    const containerlogGroup = new logs.LogGroup(this, `DTH-ECR-Container-LogGroup`, {
      retention: 365
    });
    const cfncontainerlogGroup = containerlogGroup.node.defaultChild as logs.CfnLogGroup
    addCfnNagSuppressRules(cfncontainerlogGroup, [
      {
        id: 'W84',
        reason: 'Log group data is always encrypted in CloudWatch Logs using an AWS Managed KMS Key'
      },
    ])

    // Create ECS executionRole and executionPolicy
    const ecsTaskExecutionRole = new iam.Role(this, `DTH-ECR-TaskExecutionRole`, {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com')
    });

    const taskExecutionPolicy = new iam.Policy(this, 'TaskExecutionPolicy', {
      policyName: `${Aws.STACK_NAME}TaskExecutionPolicy`,
      statements: [
        new iam.PolicyStatement({
          actions: [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          resources: [
            containerlogGroup.logGroupArn
          ]
        }),
      ]
    });
    taskExecutionPolicy.node.addDependency(containerlogGroup);
    taskExecutionPolicy.attachToRole(ecsTaskExecutionRole);

    const taskDefinition = new ecs.TaskDefinition(this, 'ECRTransferTask', {
      memoryMiB: '1024',
      cpu: '512',
      compatibility: ecs.Compatibility.FARGATE,
      family: `${Aws.STACK_NAME}-ECRTransferTask`,
      executionRole: ecsTaskExecutionRole.withoutPolicyUpdates()
    });
    srcSecretParam.grantRead(taskDefinition.taskRole);
    desSecretParam.grantRead(taskDefinition.taskRole);

    const ecrRegistry = 'public.ecr.aws/aws-gcr-solutions'
    const ecrImageName = 'data-transfer-hub-ecr'
    const ecrImageTag = VERSION

    const ecrImageUrl = `${ecrRegistry}/${ecrImageName}:${ecrImageTag}`

    const containerDefinition = taskDefinition.addContainer('DefaultContainer', {
      image: ecs.ContainerImage.fromRegistry(ecrImageUrl),
      environment: {
        SOURCE_TYPE: sourceType.valueAsString,
        AWS_DEFAULT_REGION: this.region,
        AWS_ACCOUNT_ID: this.account,
        SRC_REGION: srcRegion.valueAsString,
        SRC_ACCOUNT_ID: srcAccountId.valueAsString,
        SRC_CREDENTIAL_NAME: srcCredential.valueAsString,
        DEST_REGION: destRegion.valueAsString,
        DEST_ACCOUNT_ID: destAccountId.valueAsString,
        DEST_PREFIX: destPrefix.valueAsString,
        DEST_CREDENTIAL_NAME: destCredential.valueAsString,

      },
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'DTH-ECR',
        logGroup: containerlogGroup,
      })
    });


    const ecrSrcReadOnlyPolicy = new iam.Policy(this, 'ECRSrcReadOnlyPolicy', {
      policyName: `${Aws.STACK_NAME}ECRSrcReadOnlyPolicy`,
      statements: [
        new iam.PolicyStatement({
          actions: [
            "ecr:GetAuthorizationToken",
          ],
          resources: [
            '*'
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
          ],
          resources: [
            `arn:${Aws.PARTITION}:ecr:${srcRegion.valueAsString}:${Aws.ACCOUNT_ID}:repository/*`

          ]
        }),
      ]
    });

    const cfnecrSrcReadOnlyPolicy = ecrSrcReadOnlyPolicy.node.defaultChild as iam.CfnPolicy
    addCfnNagSuppressRules(cfnecrSrcReadOnlyPolicy, [
      {
        id: 'W12',
        reason: 'This IAM policy need * resource'
      },
    ])

    const ecrSrcPolicy = ecrSrcReadOnlyPolicy.node.defaultChild as iam.CfnPolicy
    ecrSrcPolicy.cfnOptions.condition = isSrcInCurrentAccount

    ecrSrcReadOnlyPolicy.attachToRole(taskDefinition.taskRole);

    const ecrDestWritePolicy = new iam.Policy(this, 'ECRDestWritePolicy', {
      policyName: `${Aws.STACK_NAME}ECRDestWritePolicy`,
      statements: [
        new iam.PolicyStatement({
          actions: [
            "ecr:GetAuthorizationToken",
          ],
          resources: [
            '*'
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
          ],
          resources: [
            `arn:${Aws.PARTITION}:ecr:${destRegion.valueAsString}:${Aws.ACCOUNT_ID}:repository/*`

          ]
        }),
      ]
    });
    const cfnecrDestWritePolicy = ecrDestWritePolicy.node.defaultChild as iam.CfnPolicy
    addCfnNagSuppressRules(cfnecrDestWritePolicy, [
      {
        id: 'W12',
        reason: 'This IAM policy need * resource'
      },
    ])

    const ecrDestPolicy = ecrDestWritePolicy.node.defaultChild as iam.CfnPolicy
    ecrDestPolicy.cfnOptions.condition = isDestInCurrentAccount
    ecrDestWritePolicy.attachToRole(taskDefinition.taskRole);


    const submitJob = new tasks.LambdaInvoke(this, 'Submit Lambda', {
      lambdaFunction: listImagesLambda,
      // Lambda's result is in the attribute `Payload`
      outputPath: '$.Payload'
    });

    const clusterSG = new ec2.SecurityGroup(this, 'clusterSG', {
      allowAllOutbound: true,
      description: `SG for ${Aws.STACK_NAME} Fargate Tasks`,
      vpc: vpc,
    });
    const cfnclusterSG = clusterSG.node.defaultChild as ec2.CfnSecurityGroup
    addCfnNagSuppressRules(cfnclusterSG, [
      {
        id: 'W5',
        reason: 'Egress of 0.0.0.0/0 is required'
      },
      {
        id: 'W40',
        reason: 'Egress IPProtocol of -1 is required'
      },
    ])

    const runTask = new tasks.EcsRunTask(this, 'Run Fargate Task', {
      integrationPattern: sfn.IntegrationPattern.RUN_JOB,
      cluster,
      taskDefinition,
      assignPublicIp: true,
      containerOverrides: [{
        containerDefinition,
        environment: [
          { name: 'IMAGE', value: sfn.JsonPath.stringAt('$.repositoryName') },
          { name: 'TAG', value: sfn.JsonPath.stringAt('$.imageTag') },
          { name: 'MULTI_ARCH_OPTION', value: sfn.JsonPath.stringAt('$.multiArchOption') },
        ],
      }],
      launchTarget: new tasks.EcsFargateLaunchTarget(),
      resultPath: '$.result',
      securityGroups: [clusterSG]
    });


    const putSuccessInDDBTask = new tasks.DynamoPutItem(this, 'Log Success in DynamoDB', {
      item: {
        Image: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.repositoryName')),
        Tag: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.imageTag')),
        MultiArchOption: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.multiArchOption')),
        Execution: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$$.Execution.Name')),
        Status: tasks.DynamoAttributeValue.fromString('Done'),
      },
      table: imageTable,
      returnValues: tasks.DynamoReturnValues.NONE,
      resultPath: '$.result'
    });

    const putFailureInDDBTask = new tasks.DynamoPutItem(this, 'Log Failure in DynamoDB', {
      item: {
        Image: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.repositoryName')),
        Tag: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.imageTag')),
        MultiArchOption: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.multiArchOption')),
        Execution: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$$.Execution.Name')),
        ErrorMessage: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.result.Error')),
        Status: tasks.DynamoAttributeValue.fromString('Error'),
      },
      table: imageTable,
      returnValues: tasks.DynamoReturnValues.NONE,
      resultPath: '$.result'
    });

    const myKeyAlias = kms.Alias.fromAliasName(this, 'AwsSnsDefaultKey', 'alias/aws/sns');

    const topic = new sns.Topic(this,
      'EcrReplicationTopic',
      {
        masterKey: myKeyAlias,
      }
    );
    topic.addSubscription(new subscriptions.EmailSubscription(alarmEmail.valueAsString));

    const snsTask = new tasks.SnsPublish(this, 'Publish To SNS', {
      topic,
      integrationPattern: sfn.IntegrationPattern.REQUEST_RESPONSE,
      message: sfn.TaskInput.fromObject({
        error: "Failed to copy image",
        execution: sfn.JsonPath.stringAt('$$.Execution.Name'),
        image: sfn.JsonPath.stringAt('$.repositoryName'),
        tag: sfn.JsonPath.stringAt('$.imageTag'),
        multiArchOption: sfn.JsonPath.stringAt('$.multiArchOption'),
      })
    });

    const endState = new sfn.Pass(this, 'EndState');

    const map = new sfn.Map(this, 'Map State', {
      maxConcurrency: 10,
      itemsPath: sfn.JsonPath.stringAt('$.Payload'),
    });

    const retryParam: sfn.RetryProps = {
      backoffRate: 2,
      interval: Duration.seconds(60),
      maxAttempts: 3,
    }

    map.iterator(runTask
      .addRetry(retryParam)
      .addCatch(putFailureInDDBTask.next(snsTask), { resultPath: '$.result' })
      .next(putSuccessInDDBTask));

    submitJob.next(map).next(endState)

    const logGroup = new logs.LogGroup(this, `DTH-ECR-StepFunction-LogGroup`,{
      logGroupName: `/aws/vendedlogs/states/${Fn.select(6, Fn.split(":", listImagesLambda.functionArn))}-SM-log`
    });

    // Create role for Step Machine
    const ecrStateMachineRole = new iam.Role(this, `DTH-ECR-ecrStateMachineRole`, {
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com')
    });

    const taskDefArnNoVersion = Stack.of(this).formatArn({
      service: 'ecs',
      resource: 'task-definition',
      resourceName: taskDefinition.family
    })

    const ecrStateMachineRolePolicy = new iam.Policy(this, 'ecrStateMachineRolePolicy');

    ecrStateMachineRolePolicy.addStatements(
      new iam.PolicyStatement({
        actions: [
          'lambda:InvokeFunction'
        ],
        resources: [
          listImagesLambda.functionArn
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          'ecs:RunTask'
        ],
        resources: [
          `${taskDefArnNoVersion}*`
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "ecs:StopTask",
          "ecs:DescribeTasks"
        ],
        resources: [
          '*'
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "iam:PassRole"
        ],
        resources: [
          taskDefinition.taskRole.roleArn,
          taskDefinition.executionRole!.roleArn
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "dynamodb:PutItem"
        ],
        resources: [
          imageTable.tableArn
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "sns:Publish"
        ],
        resources: [
          topic.topicArn
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "events:PutTargets",
          "events:PutRule",
          "events:DescribeRule"
        ],
        resources: [
          `arn:${Aws.PARTITION}:events:${Aws.REGION}:${Aws.ACCOUNT_ID}:rule/StepFunctionsGetEventsForECSTaskRule`,
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          'logs:CreateLogDelivery',
          'logs:GetLogDelivery',
          'logs:UpdateLogDelivery',
          'logs:DeleteLogDelivery',
          'logs:ListLogDeliveries',
          'logs:PutResourcePolicy',
          'logs:DescribeResourcePolicies',
          'logs:DescribeLogGroups'
        ],
        resources: [
          '*'
        ]
      }),
    );
    ecrStateMachineRolePolicy.node.addDependency(listImagesLambda, taskDefinition, imageTable, topic, logGroup);
    ecrStateMachineRolePolicy.attachToRole(ecrStateMachineRole);
    const cfnecrStateMachineRolePolicy = ecrStateMachineRolePolicy.node.defaultChild as iam.CfnPolicy
    addCfnNagSuppressRules(cfnecrStateMachineRolePolicy, [
      {
        id: 'W12',
        reason: '[*] Access granted as per documentation: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html'
      },
      {
        id: 'W76',
        reason: 'SPCM complexity greater then 25 is appropriate for the logic implemented'
      }
    ])

    const ecrStateMachine = new sfn.StateMachine(this, 'ECRReplicationStateMachine', {
      stateMachineName: `${Aws.STACK_NAME}-ECRReplicationSM`,
      role: ecrStateMachineRole.withoutPolicyUpdates(),
      definitionBody: sfn.DefinitionBody.fromChainable(submitJob),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
      tracingEnabled: true,
    });
    const cfnlogGroup = logGroup.node.defaultChild as logs.CfnLogGroup
    addCfnNagSuppressRules(cfnlogGroup, [
      {
        id: 'W84',
        reason: 'Log group data is always encrypted in CloudWatch Logs using an AWS Managed KMS Key'
      },
    ])

    ecrStateMachine.node.addDependency(containerDefinition, taskDefinition, submitJob, logGroup, ecrStateMachineRole, ecrStateMachineRolePolicy)

    const smRuleRole = new iam.Role(this, 'ECRReplicationSMExecRole', {
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com'),
    })
    smRuleRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        "states:StartExecution",
      ],
      resources: [
        ecrStateMachine.stateMachineArn,
      ]
    }))

    const ecrStateMachineTarget = new targets.SfnStateMachine(ecrStateMachine, { role: smRuleRole });
    const smRule = new events.Rule(this, 'ECRReplicationScheduleRule', {
      schedule: events.Schedule.rate(Duration.days(1)),
      targets: [ecrStateMachineTarget],
    });
    smRule.node.addDependency(ecrStateMachine, smRuleRole)

    const checkExecutionLambdaPolicy = new iam.Policy(this, 'CheckExecutionLambdaPolicy', {
      policyName: `${Aws.STACK_NAME}CheckExecutionLambdaPolicy`,
      statements: [
        new iam.PolicyStatement({
          actions: [
            "states:StartExecution",
            "states:ListExecutions",
            "states:ListStateMachines",
            "states:DescribeExecution",
            "states:DescribeStateMachineForExecution",
            "states:GetExecutionHistory",
            "states:ListActivities",
            "states:DescribeStateMachine",
            "states:DescribeActivity",
          ],
          resources: [
            '*'
          ]
        }),
      ]
    });

    const cfncheckExecutionLambdaPolicy = checkExecutionLambdaPolicy.node.defaultChild as iam.CfnPolicy
    addCfnNagSuppressRules(cfncheckExecutionLambdaPolicy, [
      {
        id: 'W12',
        reason: 'This IAM policy need * resource'
      },
    ])

    const checkExecutionLambdaRole = new iam.Role(this, 'CheckExecutionFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    })

    const checkExecutionLambda = new lambda.Function(this, 'CheckExecutionFunction', {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'lambda_function.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/plugin/ecr/sfn_helper')),
      memorySize: 256,
      timeout: Duration.minutes(15),
      environment: {
        STATE_MACHINE_ARN: ecrStateMachine.stateMachineArn
      },
      role: checkExecutionLambdaRole.withoutPolicyUpdates()
    });
    checkExecutionLambda.node.addDependency(checkExecutionLambdaRole, checkExecutionLambdaPolicy)

    checkExecutionLambdaPolicy.attachToRole(checkExecutionLambda.role!)
    ecrStateMachine.grantStartExecution(checkExecutionLambda)
    ecrStateMachine.grantRead(checkExecutionLambda)

    //Run checkExecutionLambda on Create
    const lambdaTrigger = new cr.AwsCustomResource(this, 'StatefunctionTrigger', {
      policy: cr.AwsCustomResourcePolicy.fromStatements([new iam.PolicyStatement({
        actions: ['lambda:InvokeFunction'],
        effect: iam.Effect.ALLOW,
        resources: [checkExecutionLambda.functionArn]
      })]),
      timeout: Duration.minutes(15),
      onCreate: {
        service: 'Lambda',
        action: 'invoke',
        parameters: {
          FunctionName: checkExecutionLambda.functionName,
          InvocationType: 'Event'
        },
        physicalResourceId: cr.PhysicalResourceId.of('JobSenderTriggerPhysicalId')
      },
      onUpdate: {
        service: 'Lambda',
        action: 'invoke',
        parameters: {
          FunctionName: checkExecutionLambda.functionName,
          InvocationType: 'Event'
        },
        physicalResourceId: cr.PhysicalResourceId.of('JobSenderTriggerPhysicalId')
      }
    })
    lambdaTrigger.node.addDependency(ecrStateMachine, smRule)
  }
}
