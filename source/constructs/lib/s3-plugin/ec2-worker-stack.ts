// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from "constructs";
import {
  Aws,
  Duration,
  CfnOutput,
  CfnMapping,
  Tags,
  aws_iam as iam,
  aws_ec2 as ec2,
  aws_logs as logs,
  aws_cloudwatch as cw,
  aws_sqs as sqs,
  aws_autoscaling as asg
} from "aws-cdk-lib";
import { NagSuppressions } from "cdk-nag";

import * as path from "path";
import { addCfnNagSuppressRules } from "./s3-plugin-stack";

export interface Env {
  [key: string]: any;
}

export interface Ec2WorkerProps {
  readonly env: Env;
  readonly vpc: ec2.IVpc;
  readonly queue: sqs.Queue;
  readonly maxCapacity?: number;
  readonly minCapacity?: number;
  readonly desiredCapacity?: number;
  readonly cliRelease: string;
  readonly dthCliUrl?: string;
  readonly ec2LG: logs.ILogGroup;
}

/***
 * EC2 Stack
 */
export class Ec2WorkerStack extends Construct {
  readonly workerAsg: asg.AutoScalingGroup;

  constructor(scope: Construct, id: string, props: Ec2WorkerProps) {
    super(scope, id);

    const instanceType = new ec2.InstanceType("t4g.micro");

    const amznLinux = ec2.MachineImage.latestAmazonLinux2({
      edition: ec2.AmazonLinuxEdition.STANDARD,
      storage: ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
      cpuType: ec2.AmazonLinuxCpuType.ARM_64
    });

    const ec2SG = new ec2.SecurityGroup(this, "S3RepEC2SG", {
      vpc: props.vpc,
      description: "Security Group for Data Replication Hub EC2 instances",
      allowAllOutbound: true
    });
    // For dev only
    // ec2SG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow ssh access');

    const cfnSG = ec2SG.node.defaultChild as ec2.CfnSecurityGroup;
    addCfnNagSuppressRules(cfnSG, [
      {
        id: "W5",
        reason: "Open egress rule is required to access public network"
      },
      {
        id: "W40",
        reason: "Open egress rule is required to access public network"
      }
    ]);

    const workerAsgRole = new iam.Role(this, "WorkerAsgRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com")
    });

    const cwAgentPolicy = new iam.Policy(this, "CWAgentPolicy", {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["*"],
          actions: [
            "cloudwatch:PutMetricData",
            "ec2:DescribeVolumes",
            "ec2:DescribeTags",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams",
            "logs:DescribeLogGroups"
          ]
        })
      ]
    });

    const cfnCwAgentPolicy = cwAgentPolicy.node.defaultChild as iam.CfnPolicy;
    addCfnNagSuppressRules(cfnCwAgentPolicy, [
      {
        id: "W12",
        reason: "Publish log streams requires any resources"
      }
    ]);

    workerAsgRole.attachInlinePolicy(cwAgentPolicy);
    workerAsgRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
    );

    const worker_ud = ec2.UserData.forLinux();

    const workerLaunchTemplate = new ec2.LaunchTemplate(
      this,
      "WorkerEC2LaunchTemplate",
      {
        instanceType: instanceType,
        machineImage: amznLinux,
        userData: worker_ud,
        role: workerAsgRole,
        // keyName: 'ad-key',  // dev only
        securityGroup: ec2SG,
        blockDevices: [
          {
            deviceName: "/dev/xvda",
            volume: asg.BlockDeviceVolume.ebs(8, {
              encrypted: true
            })
          }
        ],
        associatePublicIpAddress: true,
        detailedMonitoring: true,
        requireImdsv2: true
      }
    );

    this.workerAsg = new asg.AutoScalingGroup(this, "S3RepWorkerASG", {
      autoScalingGroupName: `${Aws.STACK_NAME}-Worker-ASG`,
      vpc: props.vpc,
      maxCapacity: props.maxCapacity ? props.maxCapacity : 20,
      minCapacity: props.minCapacity ? props.minCapacity : 1,
      desiredCapacity: props.desiredCapacity ? props.desiredCapacity : 1,
      groupMetrics: [
        new asg.GroupMetrics(
          asg.GroupMetric.DESIRED_CAPACITY,
          asg.GroupMetric.IN_SERVICE_INSTANCES
        )
      ],
      cooldown: Duration.minutes(2),
      signals: asg.Signals.waitForMinCapacity(),
      launchTemplate: workerLaunchTemplate
    });
    NagSuppressions.addResourceSuppressions(this.workerAsg, [
      {
        id: "AwsSolutions-AS3",
        reason: "we do not need notification, this asg will change automated"
      }
    ]);

    Tags.of(this.workerAsg).add(
      "Name",
      `${Aws.STACK_NAME}-Replication-Worker`,
      {}
    );

    const assetTable = new CfnMapping(this, 'AssetTable', {
        mapping: {
            'aws': {
                assetDomain: 'https://aws-gcr-solutions-assets.s3.amazonaws.com',
            },
            'aws-cn': {
                assetDomain: 'https://aws-gcr-solutions-assets.s3.cn-northwest-1.amazonaws.com.cn',
            },
            'aws-us-gov': {
              assetDomain: 'https://aws-gcr-solutions-assets.s3.amazonaws.com',
            },
        }
    });

    const cliAssetDomain = assetTable.findInMap(Aws.PARTITION, 'assetDomain')

    this.workerAsg.applyCloudFormationInit(
      ec2.CloudFormationInit.fromElements(
        ec2.InitFile.fromFileInline(
          "/home/ec2-user/cw_agent_config.json",
          path.join(__dirname, "./dashboard-config/cw_agent_config.json")
        )
      )
    );

    worker_ud.addCommands(
      "yum update -y",
      "cd /home/ec2-user/",

      // Enable BBR
      'echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf',
      'echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf',
      "sysctl -p",
      "echo `sysctl net.ipv4.tcp_congestion_control` > worker.log",

      // Enable Cloudwatch Agent
      "yum install -y amazon-cloudwatch-agent",
      `sed -i  -e "s/##log group##/${props.ec2LG.logGroupName}/g" cw_agent_config.json`,
      "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/home/ec2-user/cw_agent_config.json -s",

      // Get CLI from solution assets
      `curl -LO "${props.dthCliUrl ? `${props.dthCliUrl}v${props.cliRelease}/dthcli_${props.cliRelease}_linux_arm64.tar.gz` : `${cliAssetDomain}/data-transfer-hub-cli/v${props.cliRelease}/dthcli_${props.cliRelease}_linux_arm64.tar.gz`}"`,
      `tar zxvf dthcli_${props.cliRelease}_linux_arm64.tar.gz`,

      // Prepare the environment variables
      `echo "export JOB_TABLE_NAME=${props.env.JOB_TABLE_NAME}" >> env.sh`,
      `echo "export JOB_QUEUE_NAME=${props.env.JOB_QUEUE_NAME}" >> env.sh`,
      `echo "export SINGLE_PART_TABLE_NAME=${props.env.SINGLE_PART_TABLE_NAME}" >> env.sh`,
      `echo "export SFN_ARN=${props.env.SFN_ARN}" >> env.sh`,

      `echo "export SOURCE_TYPE=${props.env.SOURCE_TYPE}" >> env.sh`,
      `echo "export SRC_BUCKET=${props.env.SRC_BUCKET}" >> env.sh`,
      `echo "export SRC_PREFIX=${props.env.SRC_PREFIX}" >> env.sh`,
      `echo "export SRC_REGION=${props.env.SRC_REGION}" >> env.sh`,
      `echo "export SRC_ENDPOINT=${props.env.SRC_ENDPOINT}" >> env.sh`,
      `echo "export SRC_CREDENTIALS=${props.env.SRC_CREDENTIALS}" >> env.sh`,
      `echo "export SRC_IN_CURRENT_ACCOUNT=${props.env.SRC_IN_CURRENT_ACCOUNT}" >> env.sh`,
      `echo "export PAYER_REQUEST=${props.env.PAYER_REQUEST}" >> env.sh`,

      `echo "export DEST_BUCKET=${props.env.DEST_BUCKET}" >> env.sh`,
      `echo "export DEST_PREFIX=${props.env.DEST_PREFIX}" >> env.sh`,
      `echo "export DEST_REGION=${props.env.DEST_REGION}" >> env.sh`,
      `echo "export DEST_CREDENTIALS=${props.env.DEST_CREDENTIALS}" >> env.sh`,
      `echo "export DEST_IN_CURRENT_ACCOUNT=${props.env.DEST_IN_CURRENT_ACCOUNT}" >> env.sh`,
      `echo "export DEST_STORAGE_CLASS=${props.env.DEST_STORAGE_CLASS}" >> env.sh`,
      `echo "export DEST_ACL=${props.env.DEST_ACL}" >> env.sh`,
      `echo "export DEST_SSE_TYPE=${props.env.DEST_SSE_TYPE}" >> env.sh`,
      `echo "export DEST_SSE_KMS_KEY_ID=${props.env.DEST_SSE_KMS_KEY_ID}" >> env.sh`,

      // `echo "export MULTIPART_THRESHOLD=${props.env.MULTIPART_THRESHOLD}" >> env.sh`,
      // `echo "export CHUNK_SIZE=${props.env.CHUNK_SIZE}" >> env.sh`,
      `echo "export FINDER_DEPTH=${props.env.FINDER_DEPTH}" >> env.sh`,
      `echo "export FINDER_NUMBER=${props.env.FINDER_NUMBER}" >> env.sh`,
      `echo "export WORKER_NUMBER=${props.env.WORKER_NUMBER}" >> env.sh`,
      `echo "export INCLUDE_METADATA=${props.env.INCLUDE_METADATA}" >> env.sh`,
      `echo "export AWS_DEFAULT_REGION=${Aws.REGION}" >> env.sh`,

      // Create the script
      'echo "source /home/ec2-user/env.sh" >> start-worker.sh',
      'echo "nohup ./dthcli run -t Worker |& tee -a /home/ec2-user/worker.log" >> start-worker.sh',
      "echo \"echo 'Error occured, trying to terminate instance...' >> /home/ec2-user/worker.log\" >> start-worker.sh",
      'echo "shutdown" >> start-worker.sh', // shutdown will terminate the instance as asg will automatically replace the stopped one

      "chmod +x start-worker.sh",
      // Add to startup items
      'echo "@reboot /home/ec2-user/start-worker.sh" >> /var/spool/cron/root',
      // Run the script
      "./start-worker.sh"
    );

    props.ec2LG.addMetricFilter("CompletedBytes", {
      metricName: "CompletedBytes",
      metricNamespace: `${Aws.STACK_NAME}`,
      metricValue: "$Bytes",
      filterPattern: logs.FilterPattern.literal(
        '[data, time, p="----->Completed", Bytes, ...]'
      )
    });

    props.ec2LG.addMetricFilter("Transferred-Objects", {
      metricName: "TransferredObjects",
      metricNamespace: `${Aws.STACK_NAME}`,
      metricValue: "1",
      filterPattern: logs.FilterPattern.literal(
        '[data, time, p="----->Transferred", ..., s="DONE"]'
      )
    });

    props.ec2LG.addMetricFilter("Failed-Objects", {
      metricName: "FailedObjects",
      metricNamespace: `${Aws.STACK_NAME}`,
      metricValue: "1",
      filterPattern: logs.FilterPattern.literal(
        '[data, time, p="----->Transferred", ..., s="ERROR"]'
      )
    });

    const allMsg = new cw.MathExpression({
      expression: "notvisible + visible",
      usingMetrics: {
        notvisible: props.queue.metricApproximateNumberOfMessagesNotVisible(),
        visible: props.queue.metricApproximateNumberOfMessagesVisible()
      },
      period: Duration.minutes(1),
      label: "# of messages"
    });

    this.workerAsg.scaleOnMetric("ScaleOutSQS", {
      metric: allMsg,
      scalingSteps: [
        { upper: 0, change: -10000 }, // Scale in when no messages to process
        { lower: 100, change: +1 },
        { lower: 500, change: +2 },
        { lower: 2000, change: +5 },
        { lower: 10000, change: +10 }
      ],
      adjustmentType: asg.AdjustmentType.CHANGE_IN_CAPACITY
    });

    new CfnOutput(this, "WorkerLogGroupName", {
      value: props.ec2LG.logGroupName,
      description: "Worker Log Group Name"
    });

    new CfnOutput(this, "WorkerASGName", {
      value: this.workerAsg.autoScalingGroupName,
      description: "Worker ASG Name"
    });
  }
}
