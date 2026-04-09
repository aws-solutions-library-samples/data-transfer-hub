// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  Aws,
  Fn,
  CfnParameter,
  CfnCondition,
  CfnResource,
  Stack,
  StackProps,
  Duration,
  CustomResource,
  aws_secretsmanager as sm,
  aws_s3 as s3,
  aws_ec2 as ec2,
  aws_iam as iam,
  custom_resources as cr,
  aws_lambda as lambda
} from "aws-cdk-lib";
import { NagSuppressions } from "cdk-nag";

import { CommonStack, CommonProps } from "./common-resources";
import { Ec2FinderStack, Ec2FinderProps } from "./ec2-finder-stack";
import { Ec2WorkerStack, Ec2WorkerProps } from "./ec2-worker-stack";
import { DashboardStack, DBProps } from "./dashboard-stack";

import * as path from "path";
import { MultiPartStateMachine } from "./multi-part-step-functions";

const { VERSION } = process.env;

export const enum RunType {
  EC2 = "EC2",
  LAMBDA = "Lambda"
}

/**
 * cfn-nag suppression rule interface
 */
interface CfnNagSuppressRule {
  readonly id: string;
  readonly reason: string;
}

export function addCfnNagSuppressRules(
  resource: CfnResource,
  rules: CfnNagSuppressRule[]
) {
  resource.addMetadata("cfn_nag", {
    rules_to_suppress: rules
  });
}

/***
 * Main Stack
 */
export class DataTransferS3Stack extends Stack {
  private paramGroups: any[] = [];
  private paramLabels: any = {};

  private addToParamGroups(label: string, ...param: string[]) {
    this.paramGroups.push({
      Label: { default: label },
      Parameters: param
    });
  }

  private addToParamLabels(label: string, param: string) {
    this.paramLabels[param] = {
      default: label
    };
  }

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const runType: RunType = this.node.tryGetContext("runType") || RunType.EC2;

    const cliRelease = "1.4.3";

    const srcType = new CfnParameter(this, "srcType", {
      description:
        "Choose type of source storage, including Amazon S3, Aliyun OSS, Qiniu Kodo, Tencent COS or Google GCS",
      type: "String",
      default: "Amazon_S3",
      allowedValues: ["Amazon_S3", "Aliyun_OSS", "Qiniu_Kodo", "Tencent_COS"]
    });
    this.addToParamLabels("Source Type", srcType.logicalId);

    const srcBucket = new CfnParameter(this, "srcBucket", {
      description: "Source Bucket Name",
      type: "String"
    });
    this.addToParamLabels("Source Bucket", srcBucket.logicalId);

    const srcPrefix = new CfnParameter(this, "srcPrefix", {
      description: "Source Prefix (Optional)",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Source Prefix", srcPrefix.logicalId);

    const srcPrefixsListFile = new CfnParameter(this, "srcPrefixsListFile", {
      description:
        "Source Prefix List File S3 path (Optional), support txt type, the maximum number of lines is 10 millions. e.g. my_prefix_list.txt",
      default: "",
      type: "String"
    });
    this.addToParamLabels(
      "Source Prefix List File",
      srcPrefixsListFile.logicalId
    );

    const srcPrefixListBucket = new CfnParameter(this, "srcPrefixListBucket", {
      description:
        "Source prefix list file S3 bucket name (Optional). It used to store the Source prefix list file. The specified bucket must be located in the same AWS region and under the same account as the DTH deployment. If your PrefixList File is stored in the Source Bucket, please leave this parameter empty.",
      default: "",
      type: "String"
    });
    this.addToParamLabels(
      "Bucket Name for Source Prefix List File",
      srcPrefixListBucket.logicalId
    );

    const srcSkipCompare = new CfnParameter(this, "srcSkipCompare", {
      description:
        "Skip the data comparison in task finding process? If yes, all data in the source will be sent to the destination",
      default: "false",
      type: "String",
      allowedValues: ["true", "false"]
    });
    this.addToParamLabels("Skip Data Comparison", srcSkipCompare.logicalId);

    const srcRegion = new CfnParameter(this, "srcRegion", {
      description: "Source Region Name",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Source Region", srcRegion.logicalId);

    const srcEndpoint = new CfnParameter(this, "srcEndpoint", {
      description:
        "Source Endpoint URL (Optional), leave blank unless you want to provide a custom Endpoint URL",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Source Endpoint URL", srcEndpoint.logicalId);

    const srcInCurrentAccount = new CfnParameter(this, "srcInCurrentAccount", {
      description:
        "Source Bucket in current account? If not, you should provide a credential with read access",
      default: "false",
      type: "String",
      allowedValues: ["true", "false"]
    });
    this.addToParamLabels(
      "Source In Current Account",
      srcInCurrentAccount.logicalId
    );

    const srcCredentials = new CfnParameter(this, "srcCredentials", {
      description:
        "The secret name in Secrets Manager used to keep AK/SK credentials for Source Bucket. Leave blank if source bucket is in current account or source is open data",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Source Credentials", srcCredentials.logicalId);

    const isPayerRequest = new CfnParameter(this, "isPayerRequest", {
      description: "Enable Payer Request?",
      default: "false",
      type: "String",
      allowedValues: ["true", "false"]
    });
    this.addToParamLabels("Enable Payer Request", isPayerRequest.logicalId);

    const destBucket = new CfnParameter(this, "destBucket", {
      description: "Destination Bucket Name",
      type: "String"
    });
    this.addToParamLabels("Destination Bucket", destBucket.logicalId);

    const destPrefix = new CfnParameter(this, "destPrefix", {
      description: "Destination Prefix (Optional)",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Destination Prefix", destPrefix.logicalId);

    const destRegion = new CfnParameter(this, "destRegion", {
      description: "Destination Region Name",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Destination Region", destRegion.logicalId);

    const destInCurrentAccount = new CfnParameter(
      this,
      "destInCurrentAccount",
      {
        description:
          "Destination Bucket in current account? If not, you should provide a credential with read and write access",
        default: "true",
        type: "String",
        allowedValues: ["true", "false"]
      }
    );
    this.addToParamLabels(
      "Destination In Current Account",
      destInCurrentAccount.logicalId
    );

    const destCredentials = new CfnParameter(this, "destCredentials", {
      description:
        "The secret name in Secrets Manager used to keep AK/SK credentials for Destination Bucket. Leave blank if desination bucket is in current account",
      default: "",
      type: "String"
    });
    this.addToParamLabels("Destination Credentials", destCredentials.logicalId);

    // 'STANDARD'|'REDUCED_REDUNDANCY'|'STANDARD_IA'|'ONEZONE_IA'|'INTELLIGENT_TIERING'|'GLACIER'|'DEEP_ARCHIVE'|'OUTPOSTS',
    const destStorageClass = new CfnParameter(this, "destStorageClass", {
      description: "Destination Storage Class, Default to INTELLIGENT_TIERING",
      default: "INTELLIGENT_TIERING",
      type: "String",
      allowedValues: [
        "STANDARD",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING"
      ]
    });
    this.addToParamLabels(
      "Destination Storage Class",
      destStorageClass.logicalId
    );

    const destAcl = new CfnParameter(this, "destAcl", {
      description: "Destination Access Control List",
      default: "bucket-owner-full-control",
      type: "String",
      allowedValues: [
        "private",
        "public-read",
        "public-read-write",
        "authenticated-read",
        "aws-exec-read",
        "bucket-owner-read",
        "bucket-owner-full-control"
      ]
    });
    this.addToParamLabels("Destination Access Control List", destAcl.logicalId);

    const destPutObjectSSEType = new CfnParameter(
      this,
      "destPutObjectSSEType",
      {
        description:
          "Specifies the server-side encryption algorithm used for storing objects in Amazon S3 (PutObjectPolicy).",
        default: "None",
        type: "String",
        allowedValues: ["None", "AES256", "AWS_KMS"]
      }
    );
    this.addToParamLabels(
      "Destination Bucket PutObjectPolicy SSE Type",
      destPutObjectSSEType.logicalId
    );

    const destPutObjectSSEKmsKeyId = new CfnParameter(
      this,
      "destPutObjectSSEKmsKeyId",
      {
        description: "Destination Bucket SSE KMS Key ID (Optional). This field is required only if the SSE Type in your Destination Bucket's PutObject Policy is set to 'AWS_KMS'.",
        default: "",
        type: "String"
      }
    );
    this.addToParamLabels(
      "Destination Bucket SSE KMS Key ID",
      destPutObjectSSEKmsKeyId.logicalId
    );

    const ec2VpcId = new CfnParameter(this, "ec2VpcId", {
      description: "VPC ID to run EC2 task, e.g. vpc-bef13dc7",
      default: "",
      type: "AWS::EC2::VPC::Id"
    });
    this.addToParamLabels("VPC ID", ec2VpcId.logicalId);

    const ec2Subnets = new CfnParameter(this, "ec2Subnets", {
      description:
        "Subnet IDs to run EC2 task. Please provide two subnets at least delimited by comma, e.g. subnet-97bfc4cd,subnet-7ad7de32",
      default: "",
      type: "List<AWS::EC2::Subnet::Id>"
    });
    this.addToParamLabels("Subnet IDs", ec2Subnets.logicalId);

    const finderEc2Memory = new CfnParameter(this, "finderEc2Memory", {
      description: "The amount of memory (in GB) used by the Finder task.",
      default: "8",
      type: "String",
      allowedValues: ["8", "16", "32", "64", "128", "256", "384", "512"]
    });
    this.addToParamLabels("EC2 Finder Memory", finderEc2Memory.logicalId);

    const ec2CronExpression = new CfnParameter(this, "ec2CronExpression", {
      description:
        "Cron Expression For EC2 Finder Task. Leave blank to execute only once.",
      default: "0/60 * * * ? *",
      type: "String"
    });
    this.addToParamLabels("EC2 Cron Expression", ec2CronExpression.logicalId);

    const alarmEmail = new CfnParameter(this, "alarmEmail", {
      allowedPattern:
        "\\w[-\\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\\.)+[A-Za-z]{2,14}",
      type: "String",
      description: "Errors will be sent to this email."
    });
    this.addToParamLabels("Alarm Email", alarmEmail.logicalId);

    const includeMetadata = new CfnParameter(this, "includeMetadata", {
      description:
        "Add replication of object metadata, there will be additional API calls",
      default: "true",
      type: "String",
      allowedValues: ["true", "false"]
    });

    this.addToParamLabels("Include Metadata", includeMetadata.logicalId);

    const srcEvent = new CfnParameter(this, "srcEvent", {
      description:
        "Whether to enable S3 Event to trigger the replication. Note that S3Event is only applicable if source is in Current account",
      default: "No",
      type: "String",
      allowedValues: ["No", "Create", "CreateAndDelete"]
    });
    this.addToParamLabels("Enable S3 Event", srcEvent.logicalId);

    const finderDepth = new CfnParameter(this, "finderDepth", {
      description:
        "The depth of sub folders to compare in parallel. 0 means comparing all objects in sequence",
      default: "0",
      type: "String"
    });
    const finderNumber = new CfnParameter(this, "finderNumber", {
      description: "The number of finder threads to run in parallel",
      default: "1",
      type: "String"
    });
    const workerNumber = new CfnParameter(this, "workerNumber", {
      description:
        "The number of worker threads to run in one worker node/instance",
      default: "4",
      type: "String"
    });

    this.addToParamGroups(
      "Source Information",
      srcType.logicalId,
      srcBucket.logicalId,
      srcPrefix.logicalId,
      srcPrefixsListFile.logicalId,
      srcPrefixListBucket.logicalId,
      srcRegion.logicalId,
      srcEndpoint.logicalId,
      srcInCurrentAccount.logicalId,
      srcCredentials.logicalId,
      srcEvent.logicalId,
      srcSkipCompare.logicalId,
      isPayerRequest.logicalId
    );
    this.addToParamGroups(
      "Destination Information",
      destBucket.logicalId,
      destPrefix.logicalId,
      destRegion.logicalId,
      destInCurrentAccount.logicalId,
      destCredentials.logicalId,
      destStorageClass.logicalId,
      destAcl.logicalId,
      destPutObjectSSEType.logicalId,
      destPutObjectSSEKmsKeyId.logicalId
    );
    this.addToParamGroups("Notification Information", alarmEmail.logicalId);
    this.addToParamGroups(
      "EC2 Cluster Information",
      ec2VpcId.logicalId,
      ec2Subnets.logicalId,
      finderEc2Memory.logicalId,
      ec2CronExpression.logicalId
    );

    // let lambdaMemory: CfnParameter | undefined
    let maxCapacity: CfnParameter | undefined;
    let minCapacity: CfnParameter | undefined;
    let desiredCapacity: CfnParameter | undefined;

    if (runType === RunType.EC2) {
      maxCapacity = new CfnParameter(this, "maxCapacity", {
        description: "Maximum Capacity for Auto Scaling Group",
        default: "20",
        type: "Number"
      });
      this.addToParamLabels("Maximum Capacity", maxCapacity.logicalId);

      minCapacity = new CfnParameter(this, "minCapacity", {
        description: "Minimum Capacity for Auto Scaling Group",
        default: "1",
        type: "Number"
      });
      this.addToParamLabels("Minimum Capacity", minCapacity.logicalId);

      desiredCapacity = new CfnParameter(this, "desiredCapacity", {
        description: "Desired Capacity for Auto Scaling Group",
        default: "1",
        type: "Number"
      });
      this.addToParamLabels("Desired Capacity", desiredCapacity.logicalId);

      this.addToParamGroups(
        "Advanced Options",
        finderDepth.logicalId,
        finderNumber.logicalId,
        workerNumber.logicalId,
        includeMetadata.logicalId,
        maxCapacity.logicalId,
        minCapacity.logicalId,
        desiredCapacity.logicalId
      );
    }

    this.templateOptions.description = `(SO8002) - Data Transfer Hub - S3 Plugin - Template version ${VERSION}`;

    this.templateOptions.metadata = {
      "AWS::CloudFormation::Interface": {
        ParameterGroups: this.paramGroups,
        ParameterLabels: this.paramLabels
      }
    };

    // Get Secret for credentials from Secrets Manager
    const srcCred = sm.Secret.fromSecretNameV2(
      this,
      "SrcCredentialsParam",
      srcCredentials.valueAsString
    );
    const destCred = sm.Secret.fromSecretNameV2(
      this,
      "DestCredentialsParam",
      destCredentials.valueAsString
    );

    const srcIBucket = s3.Bucket.fromBucketName(
      this,
      `SrcBucket`,
      srcBucket.valueAsString
    );
    const destIBucket = s3.Bucket.fromBucketName(
      this,
      `DestBucket`,
      destBucket.valueAsString
    );
    const prefixListFileIBucket = s3.Bucket.fromBucketName(
      this,
      `PrefixListFileBucket`,
      srcPrefixListBucket.valueAsString
    );
    
    // Get VPC
    const vpc = ec2.Vpc.fromVpcAttributes(this, "EC2Vpc", {
      vpcId: ec2VpcId.valueAsString,
      availabilityZones: Fn.getAzs(),
      publicSubnetIds: ec2Subnets.valueAsList
    });

    // Start Common Stack
    const commonProps: CommonProps = {
      alarmEmail: alarmEmail.valueAsString,
      srcIBucket: srcIBucket
    };

    const commonStack = new CommonStack(this, "Common", commonProps);

    const defaultPolicy = new iam.Policy(this, "DefaultPolicy");

    defaultPolicy.addStatements(
      new iam.PolicyStatement({
        actions: [
          "dynamodb:BatchGetItem",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:Query",
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:ConditionCheckItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ],
        resources: [
          commonStack.jobTable.tableArn,
          commonStack.splitPartTable.tableArn
        ]
      }),
      new iam.PolicyStatement({
        actions: [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
        resources: [
          `${srcCred.secretArn}-??????`,
          `${destCred.secretArn}-??????`
        ]
      })
    );

    const multipartStateMachine = new MultiPartStateMachine(
      this,
      "MultiPartStateMachine",
      {
        splitPartTable: commonStack.splitPartTable,
        jobTable: commonStack.jobTable,
        destIBucket: destIBucket,
        destPrefix: destPrefix.valueAsString,
        workerLogGroup: commonStack.workerLogGroup,
        destCredentials: destCredentials.valueAsString,
        destRegion: destRegion.valueAsString,
        defaultPolicy: defaultPolicy
      }
    );

    // Start Finder - EC2 Stack
    const finderEnv = {
      AWS_DEFAULT_REGION: Aws.REGION,
      JOB_TABLE_NAME: commonStack.jobTable.tableName,
      JOB_QUEUE_NAME: commonStack.sqsQueue.queueName,
      SINGLE_PART_TABLE_NAME: commonStack.splitPartTable.tableName,
      SFN_ARN:
        multipartStateMachine.multiPartControllerStateMachine.stateMachineArn,

      SOURCE_TYPE: srcType.valueAsString,
      SRC_BUCKET: srcBucket.valueAsString,
      SRC_PREFIX: srcPrefix.valueAsString,
      SRC_PREFIX_LIST: srcPrefixsListFile.valueAsString,
      SRC_PREFIX_LIST_BUCKET: srcPrefixListBucket.valueAsString,
      SRC_REGION: srcRegion.valueAsString,
      SRC_ENDPOINT: srcEndpoint.valueAsString,
      SRC_CREDENTIALS: srcCredentials.valueAsString,
      SRC_IN_CURRENT_ACCOUNT: srcInCurrentAccount.valueAsString,
      PAYER_REQUEST: isPayerRequest.valueAsString,
      SKIP_COMPARE: srcSkipCompare.valueAsString,

      DEST_BUCKET: destBucket.valueAsString,
      DEST_PREFIX: destPrefix.valueAsString,
      DEST_REGION: destRegion.valueAsString,
      DEST_CREDENTIALS: destCredentials.valueAsString,
      DEST_IN_CURRENT_ACCOUNT: destInCurrentAccount.valueAsString,

      FINDER_DEPTH: finderDepth.valueAsString,
      FINDER_NUMBER: finderNumber.valueAsString
    };

    const finderProps: Ec2FinderProps = {
      env: finderEnv,
      vpc: vpc,
      ec2SubnetIds: ec2Subnets.valueAsList,
      cliRelease: cliRelease,
      ec2CronExpression: ec2CronExpression.valueAsString,
      ec2Memory: finderEc2Memory.valueAsString
    };
    const finderStack = new Ec2FinderStack(this, "FinderStack", finderProps);
    finderStack.finderRole.attachInlinePolicy(defaultPolicy);
    commonStack.sqsQueue.grantSendMessages(finderStack.finderRole);
    srcIBucket.grantRead(finderStack.finderRole);
    destIBucket.grantRead(finderStack.finderRole);
    const hasPrefixListBucket = new CfnCondition(this, 'HasPrefixListBucket', {
      expression: Fn.conditionNot(Fn.conditionEquals(srcPrefixListBucket.valueAsString, ''))
    });

    const prefixListBucketPolicy = new iam.Policy(this, 'PrefixListBucketPolicy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['s3:GetObject*', 's3:GetBucket*', 's3:List*'],
          resources: [
            prefixListFileIBucket.bucketArn,
            `${prefixListFileIBucket.bucketArn}/*`
          ]
        })
      ]
    });
    finderStack.finderRole.attachInlinePolicy(prefixListBucketPolicy);
    (prefixListBucketPolicy.node.defaultChild as CfnResource).cfnOptions.condition = hasPrefixListBucket;
    multipartStateMachine.multiPartControllerStateMachine.grantRead(
      finderStack.finderRole
    );

    const workerEnv = {
      JOB_TABLE_NAME: commonStack.jobTable.tableName,
      JOB_QUEUE_NAME: commonStack.sqsQueue.queueName,
      SINGLE_PART_TABLE_NAME: commonStack.splitPartTable.tableName,
      SFN_ARN:
        multipartStateMachine.multiPartControllerStateMachine.stateMachineArn,
      SOURCE_TYPE: srcType.valueAsString,

      SRC_BUCKET: srcBucket.valueAsString,
      SRC_PREFIX: srcPrefix.valueAsString,
      SRC_PREFIX_LIST: srcPrefixsListFile.valueAsString,
      SRC_REGION: srcRegion.valueAsString,
      SRC_ENDPOINT: srcEndpoint.valueAsString,
      SRC_CREDENTIALS: srcCredentials.valueAsString,
      SRC_IN_CURRENT_ACCOUNT: srcInCurrentAccount.valueAsString,
      PAYER_REQUEST: isPayerRequest.valueAsString,

      DEST_BUCKET: destBucket.valueAsString,
      DEST_PREFIX: destPrefix.valueAsString,
      DEST_REGION: destRegion.valueAsString,
      DEST_CREDENTIALS: destCredentials.valueAsString,
      DEST_IN_CURRENT_ACCOUNT: destInCurrentAccount.valueAsString,
      DEST_STORAGE_CLASS: destStorageClass.valueAsString,
      DEST_ACL: destAcl.valueAsString,
      DEST_SSE_TYPE: destPutObjectSSEType.valueAsString,
      DEST_SSE_KMS_KEY_ID: destPutObjectSSEKmsKeyId.valueAsString,

      FINDER_DEPTH: finderDepth.valueAsString,
      FINDER_NUMBER: finderNumber.valueAsString,
      WORKER_NUMBER: workerNumber.valueAsString,
      INCLUDE_METADATA: includeMetadata.valueAsString
    };

    let asgName = undefined;
    if (runType === RunType.EC2) {
      const ec2Props: Ec2WorkerProps = {
        env: workerEnv,
        vpc: vpc,
        queue: commonStack.sqsQueue,
        maxCapacity: maxCapacity?.valueAsNumber,
        minCapacity: minCapacity?.valueAsNumber,
        desiredCapacity: desiredCapacity?.valueAsNumber,
        ec2LG: commonStack.workerLogGroup,
        cliRelease: cliRelease,
      };

      const ec2Stack = new Ec2WorkerStack(this, "EC2WorkerStack", ec2Props);

      ec2Stack.workerAsg.role.attachInlinePolicy(defaultPolicy);
      commonStack.sqsQueue.grantConsumeMessages(ec2Stack.workerAsg.role);
      commonStack.sqsQueue.grantSendMessages(ec2Stack.workerAsg.role);
      srcIBucket.grantRead(ec2Stack.workerAsg.role);
      destIBucket.grantReadWrite(ec2Stack.workerAsg.role);
      ec2Stack.workerAsg.role.addToPrincipalPolicy(new iam.PolicyStatement({
        actions: ['s3:PutObjectAcl'],
        resources: [destIBucket.bucketArn, `${destIBucket.bucketArn}/*`]
      }));
      multipartStateMachine.multiPartControllerStateMachine.grantStartExecution(
        ec2Stack.workerAsg.role
      );

      asgName = ec2Stack.workerAsg.autoScalingGroupName;
    }

    // Setup Cloudwatch Dashboard
    const dbProps: DBProps = {
      runType: runType,
      queue: commonStack.sqsQueue,
      asgName: asgName
    };
    new DashboardStack(this, "DashboardStack", dbProps);

    commonStack.sqsQueue.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        conditions: {
          StringEquals: {
            "aws:SourceArn": srcIBucket.bucketArn
          }
        },
        principals: [new iam.ServicePrincipal("s3.amazonaws.com")],
        resources: [commonStack.sqsQueue.queueArn],
        actions: ["sqs:SendMessage"]
      })
    );

    // Here we using Custom resource Lambda to determine whether to enable or disable S3 Event.
    // We do not use CloudFormation intrinsic function to create S3 Event because our creation logic is complex.
    const s3NotificationHelperFn = new lambda.Function(
      this,
      "s3NotificationHelperFn",
      {
        description: `${Aws.STACK_NAME} - Create S3 Notification Processor`,
        runtime: lambda.Runtime.PYTHON_3_9,
        handler: "lambda_function.lambda_handler",
        code: lambda.Code.fromAsset(
          path.join(__dirname, "../../lambda/plugin/s3/custom-resource")
        ),
        memorySize: 256,
        timeout: Duration.seconds(60),
        environment: {
          STACK_NAME: Aws.STACK_NAME,
          SOLUTION_VERSION: process.env.VERSION || "v1.0.0",
          BUCKET_NAME: srcIBucket.bucketName,
          OBJECT_PREFIX: srcPrefix.valueAsString,
          EVENT_QUEUE_NAME: commonStack.sqsQueue.queueName,
          EVENT_QUEUE_ARN: commonStack.sqsQueue.queueArn,
          EVENT_ACTION: srcEvent.valueAsString
        }
      }
    );
    // Create the policy and role for the Lambda to create and delete S3 notification
    s3NotificationHelperFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetBucketNotification", "s3:PutBucketNotification"],
        effect: iam.Effect.ALLOW,
        resources: [
          `arn:${Aws.PARTITION}:s3:::${srcIBucket.bucketName}`,
          `arn:${Aws.PARTITION}:s3:::${srcIBucket.bucketName}/*`
        ]
      })
    );

    const s3NotificationHelperProvider = new cr.Provider(
      this,
      "s3NotificationHelperProvider",
      {
        onEventHandler: s3NotificationHelperFn
      }
    );

    s3NotificationHelperProvider.node.addDependency(s3NotificationHelperFn);
    NagSuppressions.addResourceSuppressions(s3NotificationHelperProvider, [
      {
        id: "AwsSolutions-L1",
        reason: "the lambda runtime is determined by aws cdk customer resource"
      }
    ]);

    const s3NotificationHelperLambdaTrigger = new CustomResource(
      this,
      "s3NotificationHelperLambdaTrigger",
      {
        serviceToken: s3NotificationHelperProvider.serviceToken
      }
    );

    s3NotificationHelperLambdaTrigger.node.addDependency(
      s3NotificationHelperProvider
    );
  }
}
