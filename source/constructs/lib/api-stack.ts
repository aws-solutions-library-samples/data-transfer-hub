// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  Construct,
} from 'constructs';
import {  
  CfnOutput, 
  Duration, 
  Aws, 
  Stack,
  RemovalPolicy, 
  CustomResource, 
  CfnParameter,
  custom_resources as cr,
  aws_iam as iam,
  aws_lambda as lambda, 
  aws_cognito as cognito,
  aws_dynamodb as ddb,
  aws_sns as sns,
  aws_sns_subscriptions as sub,
  aws_kms as kms
} from 'aws-cdk-lib';

import * as appsync from "aws-cdk-lib/aws-appsync";

 import * as path from 'path';
 import * as cfnSate from './cfn-step-functions';
 import * as monitorSate from './monitor-step-functions'
 import { AuthType, addCfnNagSuppressRules } from './constructs-stack';
 
 
 export interface ApiProps {
   readonly authType: string,
   readonly oidcProvider: CfnParameter | null,
   readonly usernameParameter: CfnParameter | null,
 }
 
 export class ApiStack extends Construct {
 
   readonly authDefaultConfig: any
   readonly taskTable: ddb.Table
   readonly userPool?: cognito.UserPool
   readonly api: appsync.GraphqlApi
   readonly userPoolApiClient?: cognito.UserPoolClient
   readonly userPoolDomain?: cognito.UserPoolDomain
 
   constructor(scope: Construct, id: string, props: ApiProps) {
     super(scope, id);
 
     // Can define custom bucket to hold the plugin url. Default to aws-gcr-solutions
     const templateBucket = process.env.TEMPLATE_OUTPUT_BUCKET || 'solutions-reference'
     const solutionName = process.env.SOLUTION_TRADEMARKEDNAME || 'data-transfer-hub'
     const solutionVersion = process.env.VERSION || 'latest'
 
     const PLUGIN_TEMPLATE_S3EC2 = `https://${templateBucket}.s3.amazonaws.com/${solutionName}/${solutionVersion}/DataTransferS3Stack.template`;
     const PLUGIN_TEMPLATE_ECR = `https://${templateBucket}.s3.amazonaws.com/${solutionName}/${solutionVersion}/DataTransferECRStack.template`;
 
     // This Lambda is to create the AppSync Service Linked Role
     const appSyncServiceLinkRoleFn = new lambda.Function(this, 'AppSyncServiceLinkRoleFn', {
       runtime: lambda.Runtime.PYTHON_3_9,
       code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/custom-resource')),
       handler: 'create_service_linked_role.lambda_handler',
       timeout: Duration.seconds(60),
       memorySize: 128,
       description: 'Data Transfer Hub - Service Linked Role Create Handler'
     });
 
     // Grant IAM Policy to the appSyncServiceLinkRoleFn lambda
     const serviceLikedRolePolicy = new iam.Policy(this, 'serviceLikedRolePolicy', {
       statements: [
         new iam.PolicyStatement({
           actions: [
             'iam:GetRole',
             'iam:CreateServiceLinkedRole'
           ],
           resources: [
             '*'
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
     appSyncServiceLinkRoleFn.role?.attachInlinePolicy(serviceLikedRolePolicy)
     addCfnNagSuppressRules(serviceLikedRolePolicy.node.defaultChild as iam.CfnPolicy, [
       {
         id: 'W12',
         reason: 'This policy needs to be able to have access to all resources'
       }
     ])
 
     const appSyncServiceLinkRoleFnProvider = new cr.Provider(this, 'appSyncServiceLinkRoleFnProvider', {
       onEventHandler: appSyncServiceLinkRoleFn,
     });
 
     appSyncServiceLinkRoleFnProvider.node.addDependency(appSyncServiceLinkRoleFn)
 
     const appSyncServiceLinkRoleFnTrigger = new CustomResource(this, 'appSyncServiceLinkRoleFnTrigger', {
       serviceToken: appSyncServiceLinkRoleFnProvider.serviceToken,
     });
 
     appSyncServiceLinkRoleFnTrigger.node.addDependency(appSyncServiceLinkRoleFnProvider)
 
     // Create the Progress DynamoDB Table
     this.taskTable = new ddb.Table(this, 'TaskTable', {
       billingMode: ddb.BillingMode.PAY_PER_REQUEST,
       partitionKey: {
         name: 'id',
         type: ddb.AttributeType.STRING
       },
       removalPolicy: RemovalPolicy.DESTROY,
       encryption: ddb.TableEncryption.DEFAULT,
       pointInTimeRecovery: true,
     })
 
     this.taskTable.addGlobalSecondaryIndex({
       indexName: 'byStackId',
       partitionKey: {
         name: 'stackId',
         type: ddb.AttributeType.STRING
       },
       projectionType: ddb.ProjectionType.INCLUDE,
       nonKeyAttributes: ['id', 'status', 'stackStatus']
     })
 
     const cfnTable = this.taskTable.node.defaultChild as ddb.CfnTable
     addCfnNagSuppressRules(cfnTable, [
       {
         id: 'W74',
         reason: 'This table is set to use DEFAULT encryption, the key is owned by DDB.'
       },
     ])
     const snsKey = new kms.Key(this, 'SNSTopicEncryptionKey', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: "Data Transfer Hub KMS-CMK for encrypting the objects in SNS",
      enableKeyRotation: true,
      enabled: true,
      alias: `alias/dth/sns/${Aws.STACK_NAME}`,
      // policy: snsKeyPolicy,
      policy: new iam.PolicyDocument({
          assignSids: true,
          statements: [
              new iam.PolicyStatement({
                  actions: [
                      "kms:GenerateDataKey*",
                      "kms:Decrypt",
                      "kms:Encrypt",
                  ],
                  resources: ["*"],
                  effect: iam.Effect.ALLOW,
                  principals: [
                      new iam.ServicePrincipal("sns.amazonaws.com"),
                      new iam.ServicePrincipal("cloudwatch.amazonaws.com"),
                      new iam.ServicePrincipal("lambda.amazonaws.com"),
                  ],
              }),
              new iam.PolicyStatement({
                actions: [
                  "kms:ImportKeyMaterial",
                  "kms:RetireGrant",
                  "kms:Decrypt",
                  "kms:Encrypt",
                  "kms:ConnectCustomKeyStore",
                  "sns:Publish"
                ],
                resources: ["*"],
                effect: iam.Effect.ALLOW,
                principals: [new iam.AccountRootPrincipal()],
              }),
              // This policy is in CDK v1, we just move it to here
              new iam.PolicyStatement({
                actions: [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion",
                    "kms:GenerateDataKey",
                    "kms:TagResource",
                    "kms:UntagResource"
                ],
                resources: ["*"],
                effect: iam.Effect.ALLOW,
                principals: [
                    new iam.AccountRootPrincipal()                        
                ],
            }),
          ],
      }),

    })

     const alarmTopic = new sns.Topic(this, 'DTHCentralAlarmTopic', {
         masterKey: snsKey,
         displayName: `Data Transfer Hub Central Monitor Alarm (${Aws.STACK_NAME})`,
         fifo: false,
     }) 
     alarmTopic.addSubscription(new sub.EmailSubscription(props.usernameParameter!.valueAsString));
     const cfnAlarmTopic = alarmTopic.node.defaultChild as sns.CfnTopic;
     cfnAlarmTopic.overrideLogicalId('DTHCentralAlarmTopic')
 

     const monitorStateMachine = new monitorSate.MonitorStateMachine(this, 'taskMonitorFlow', {
      taskTable: this.taskTable,
      centralSnsArn: alarmTopic.topicArn,
     })
 
     const stateMachine = new cfnSate.CloudFormationStateMachine(this, 'CfnWorkflow', {
       taskTableName: this.taskTable.tableName,
       taskTableArn: this.taskTable.tableArn,
       taskMonitorSfnArn: monitorStateMachine.taskMonitorStateMachineArn
     })

     if (props.authType === AuthType.OPENID) {
 
       // Open Id Auth Config
       this.authDefaultConfig = {
         authorizationType: appsync.AuthorizationType.OIDC,
         openIdConnectConfig: {
           oidcProvider: props.oidcProvider?.valueAsString
         }
       }
 
     } else {
 
       const poolSmsRole = new iam.Role(this, 'UserPoolSmsRole', {
         assumedBy: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
       });
 
       const poolSmsPolicy = new iam.Policy(this, 'PoolSmsPolicy', {
         // policyName: `${cdk.Aws.STACK_NAME}CustomResourcePolicy`,
         statements: [
           new iam.PolicyStatement({
             actions: [
               'sns:Publish',
             ],
             resources: [
               '*'
             ]
           }),
         ]
       });
       poolSmsRole.attachInlinePolicy(
         poolSmsPolicy
       )
 
       const cfnPoolSmsPolicy = poolSmsPolicy.node.defaultChild as iam.CfnPolicy
       addCfnNagSuppressRules(cfnPoolSmsPolicy, [
         {
           id: 'W12',
           reason: 'User Pool SMS notification requires to publish to any resources'
         }
       ])
 
       // Create Cognito User Pool
       this.userPool = new cognito.UserPool(this, 'UserPool', {
         selfSignUpEnabled: false,
         signInCaseSensitive: false,
         signInAliases: {
           email: true,
           username: false,
           phone: true
         },
         smsRole: poolSmsRole,
         removalPolicy: RemovalPolicy.DESTROY,
         passwordPolicy: {
          minLength: 8,
          requireUppercase: true,
          requireDigits: true,
          requireSymbols: true,
        },
       })
 
       this.userPool.node.addDependency(poolSmsRole, poolSmsPolicy)
 
       const cfnUserPool = this.userPool.node.defaultChild as cognito.CfnUserPool
       cfnUserPool.overrideLogicalId('DataTransferHubUserPool')
       cfnUserPool.userPoolAddOns = {
         advancedSecurityMode: 'ENFORCED'
       }
 
       // Create User Pool Client
       this.userPoolApiClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
         userPool: this.userPool,
         userPoolClientName: 'DTHPortal',
         preventUserExistenceErrors: true
       })
 
       // Create an Admin User
       new cognito.CfnUserPoolUser(this, 'AdminUser', {
         userPoolId: this.userPool.userPoolId,
         username: props?.usernameParameter?.valueAsString,
         userAttributes: [
           {
             name: 'email',
             value: props?.usernameParameter?.valueAsString
           }
         ]
       })
 
       this.userPoolDomain = new cognito.UserPoolDomain(this, 'UserPoolDomain', {
         userPool: this.userPool,
         cognitoDomain: {
           domainPrefix: `dth-portal-${Stack.of(this).account}`
         }
       })
 
       this.authDefaultConfig = {
         authorizationType: appsync.AuthorizationType.USER_POOL,
         userPoolConfig: {
           userPool: this.userPool,
           appIdClientRegex: this.userPoolApiClient.userPoolClientId,
           defaultAction: appsync.UserPoolDefaultAction.ALLOW
         }
       }
     }
 
     // AWSAppSyncPushToCloudWatchLogs managed policy is not available in China regions.
     // Create the policy manually
     const apiLogRole = new iam.Role(this, 'ApiLogRole', {
       assumedBy: new iam.ServicePrincipal('appsync.amazonaws.com'),
     });
 
     const apiLogPolicy = new iam.Policy(this, 'ApiLogPolicy', {
       statements: [
         new iam.PolicyStatement({
           actions: [
             'logs:CreateLogGroup',
             'logs:CreateLogStream',
             'logs:PutLogEvents',
           ],
           resources: [
             '*'
           ]
         }),
       ]
     });
     apiLogRole.attachInlinePolicy(apiLogPolicy)
 
     const cfnApiLogRoley = apiLogPolicy.node.defaultChild as iam.CfnPolicy
     addCfnNagSuppressRules(cfnApiLogRoley, [
       {
         id: 'W12',
         reason: 'The managed policy AWSAppSyncPushToCloudWatchLogs needs to use any resources'
       }
     ])
 
     // Create the GraphQL API Endpoint, enable Cognito User Pool Auth and IAM Auth.
     this.api = new appsync.GraphqlApi(this, 'ApiEndpoint202301', {
       name: `${Aws.STACK_NAME} - GraphQL APIs`,
       schema: appsync.SchemaFile.fromAsset(path.join(__dirname, '../../schema/schema.graphql')),
       authorizationConfig: {
         defaultAuthorization: this.authDefaultConfig,
         additionalAuthorizationModes: [
           {
             authorizationType: appsync.AuthorizationType.IAM
           }
         ]
       },
       logConfig: {
         fieldLogLevel: appsync.FieldLogLevel.ERROR,
         role: apiLogRole,
       },
       xrayEnabled: true
     })
     this.api.node.addDependency(appSyncServiceLinkRoleFnTrigger);
 
     const taskDS = this.api.addDynamoDbDataSource('TaskTableDS', this.taskTable)
 
     taskDS.createResolver('QueryGetTaskResolver', {
       typeName: 'Query',
       fieldName: 'getTask',
       requestMappingTemplate: appsync.MappingTemplate.dynamoDbGetItem('id', 'id'),
       responseMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/GetTaskResult.vtl'))
     })
 
 
     // Create Lambda Data Source
     const isDryRun = this.node.tryGetContext('DRY_RUN')
    const taskHandlerFn = new lambda.Function(this, 'TaskHandlerFn', {
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task'), {
      }),
      runtime: lambda.Runtime.PYTHON_3_9,
      description: 'Data Transfer Hub - API V1',
      handler: 'api_task_v2.lambda_handler',
      timeout: Duration.seconds(60),
      memorySize: 512,
      environment: {
        STATE_MACHINE_ARN: stateMachine.stateMachineArn,
        TRANSFER_TASK_TABLE: this.taskTable.tableName,
        PLUGIN_TEMPLATE_S3EC2: PLUGIN_TEMPLATE_S3EC2,
        PLUGIN_TEMPLATE_ECR: PLUGIN_TEMPLATE_ECR,
        DRY_RUN: isDryRun ? 'True' : 'False'
      },
    })
 
     const cfnTaskHandlerFn = taskHandlerFn.node.defaultChild as lambda.CfnFunction
     addCfnNagSuppressRules(cfnTaskHandlerFn, [
       {
         id: 'W58',
         reason: 'Lambda function already has permission to write CloudWatch Logs'
       }
     ])
 
     this.taskTable.grantReadWriteData(taskHandlerFn)
     taskHandlerFn.addToRolePolicy(new iam.PolicyStatement({
       effect: iam.Effect.ALLOW,
       resources: [`${stateMachine.stateMachineArn}`],
       actions: [
         'states:StartExecution'
       ]
     }))
     taskHandlerFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [`*`],
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
    }))
 
     const lambdaDS = this.api.addLambdaDataSource('TaskLambdaDS', taskHandlerFn, {
       description: 'Lambda Resolver Datasource'
     });
 
     lambdaDS.createResolver('MutationCreateTaskResolver', {
       typeName: 'Mutation',
       fieldName: 'createTask',
       requestMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/CreateTask.vtl')),
       responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
     })
 
     lambdaDS.createResolver('MutationStopTaskResolver', {
       typeName: 'Mutation',
       fieldName: 'stopTask',
       requestMappingTemplate: appsync.MappingTemplate.lambdaRequest(),
       responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
     })
 
     // Create Lambda Data Source for listing secrets
     const secretManagerHandlerFn = new lambda.Function(this, 'SecretManagerHandlerFn', {
       code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/secrets_manager'), {
         exclude: ['cdk/*', 'layer/*']
       }),
       runtime: lambda.Runtime.PYTHON_3_9,
       handler: 'api_sm_param.lambda_handler',
       timeout: Duration.seconds(60),
       memorySize: 128,
       description: 'Data Transfer Hub - Secrets Manager API',
     })
 
     const cfnSecretManagerHandlerFn = secretManagerHandlerFn.node.defaultChild as lambda.CfnFunction
     addCfnNagSuppressRules(cfnSecretManagerHandlerFn, [
       {
         id: 'W58',
         reason: 'Lambda function already has permission to write CloudWatch Logs'
       }
     ])
 
     const secretManagerReadOnlyPolicy = new iam.Policy(this, 'secretManagerReadOnlyPolicy')
     secretManagerReadOnlyPolicy.addStatements(new iam.PolicyStatement({
       effect: iam.Effect.ALLOW,
       resources: ['*'],
       actions: [
         "secretsmanager:ListSecrets",
       ]
     }))
     secretManagerReadOnlyPolicy.addStatements(new iam.PolicyStatement({
       effect: iam.Effect.ALLOW,
       resources: ['*'],
       actions: [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
       ]
     }))
 
     const cfnSecretManagerReadOnlyPolicy = secretManagerReadOnlyPolicy.node.defaultChild as iam.CfnPolicy
     addCfnNagSuppressRules(cfnSecretManagerReadOnlyPolicy, [
       {
         id: 'W12',
         reason: 'Need to be able to list all secrets in Secrets Manager'
       },
     ])
 
     secretManagerHandlerFn.role?.attachInlinePolicy(secretManagerReadOnlyPolicy)
 
     const secretManagerLambdaDS = this.api.addLambdaDataSource('secretManagerLambdaDS', secretManagerHandlerFn, {
       description: 'Lambda Resolver Datasource for Secret Manager'
     });
 
     secretManagerLambdaDS.createResolver('QueryListSecretsResolver', {
       typeName: 'Query',
       fieldName: 'listSecrets',
       requestMappingTemplate: appsync.MappingTemplate.lambdaRequest(),
       responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
     })
 
     // Create Lambda Data Source for tasks v2
     const taskV2HandlerFn = new lambda.Function(this, 'TaskV2HandlerFn', {
       code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/task'), {
       }),
       runtime: lambda.Runtime.PYTHON_3_9,
       handler: 'api_task_v2.lambda_handler',
       timeout: Duration.seconds(60),
       memorySize: 128,
       description: 'Data Transfer Hub - Task Handler API V2',
       environment: {
         TRANSFER_TASK_TABLE: this.taskTable.tableName,
       }
     })
     taskV2HandlerFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [`arn:${Aws.PARTITION}:cloudformation:${Aws.REGION}:${Aws.ACCOUNT_ID}:stack/DTH*`],
      actions: [
        'cloudformation:DescribeStacks',
        'cloudformation:DescribeStackEvents'
      ]
    }))
    taskV2HandlerFn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      resources: [`*`],
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
    }))
 
     const cfntaskV2HandlerFn = taskV2HandlerFn.node.defaultChild as lambda.CfnFunction
     addCfnNagSuppressRules(cfntaskV2HandlerFn, [
       {
         id: 'W58',
         reason: 'Lambda function already has permission to write CloudWatch Logs'
       }
     ])
     this.taskTable.grantReadWriteData(taskV2HandlerFn)
 
     const taskLambdaDS = this.api.addLambdaDataSource('taskLambdaDS', taskV2HandlerFn, {
       description: 'Lambda Resolver Datasource v2'
     });
 
     taskLambdaDS.createResolver('QueryListTasksV2Resolver', {
       typeName: 'Query',
       fieldName: 'listTasksV2',
       requestMappingTemplate: appsync.MappingTemplate.lambdaRequest(),
       responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
     })

     taskLambdaDS.createResolver('QueryGetErrorMessageResolver', {
      typeName: 'Query',
      fieldName: 'getErrorMessage',
      requestMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/GetErrorMessage.vtl')),
      responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
    })


    // Create Lambda Data Source for CloudWatch API
    const cwlMonitorHandlerFn = new lambda.Function(this, 'CWLMonitorHandlerFn', {
      code: lambda.AssetCode.fromAsset(path.join(__dirname, '../lambda/api/cwl'), {
      }),
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'lambda_function.lambda_handler',
      timeout: Duration.seconds(60),
      memorySize: 128,
      description: 'Data Transfer Hub - CloudWatch Monitoring Handler',
      environment: {
        TRANSFER_TASK_TABLE: this.taskTable.tableName,
      }
    })

    this.taskTable.grantReadWriteData(cwlMonitorHandlerFn)

    cwlMonitorHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        resources: ["*"],
        actions: [
          "logs:GetLogDelivery",
          "logs:ListLogDeliveries",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "cloudwatch:GetMetricStatistics",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
      })
    );

    const cfncwlMonitorHandlerFn = cwlMonitorHandlerFn.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfncwlMonitorHandlerFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    const cwlMonitorLambdaDS = this.api.addLambdaDataSource('cwlMonitorLambdaDS', cwlMonitorHandlerFn, {
      description: 'Lambda Resolver Datasource v2'
    });

    cwlMonitorLambdaDS.createResolver('QueryListLogStreamsResolver', {
      typeName: 'Query',
      fieldName: 'listLogStreams',
      requestMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/ListLogStreams.vtl')),
      responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
    })

    cwlMonitorLambdaDS.createResolver('QueryGetLogEventsResolver', {
      typeName: 'Query',
      fieldName: 'getLogEvents',
      requestMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/GetLogEvents.vtl')),
      responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
    })

    cwlMonitorLambdaDS.createResolver('QueryGetMetricHistoryDataResolver', {
      typeName: 'Query',
      fieldName: 'getMetricHistoryData',
      requestMappingTemplate: appsync.MappingTemplate.fromFile(path.join(__dirname, '../../schema/vtl/GetMetricHistoryData.vtl')),
      responseMappingTemplate: appsync.MappingTemplate.lambdaResult()
    })

    new CfnOutput(this, 'CentralAlarmTopicName', {
      value: alarmTopic.topicName,
      description: 'Central Alarm Topic Name'
    })
 
   }
 }
