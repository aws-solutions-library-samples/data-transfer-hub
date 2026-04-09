// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as path from "path";

import { Construct } from "constructs";
import {
  Aws,
  Duration,
  CfnOutput,
  CfnMapping,
  CfnCondition,
  Tags,
  Fn,
  aws_iam as iam,
  aws_ec2 as ec2,
  aws_logs as logs,
  aws_lambda as lambda,
  aws_events as events,
  aws_events_targets as targets,
  aws_autoscaling as asg
} from "aws-cdk-lib";
import { NagSuppressions } from "cdk-nag";

import { addCfnNagSuppressRules } from "./s3-plugin-stack";

export interface Env {
  [key: string]: any;
}

export interface Ec2FinderProps {
  readonly env: Env;
  readonly vpc: ec2.IVpc;
  readonly ec2SubnetIds: string[];
  readonly cliRelease: string;
  readonly dthCliUrl?: string;
  readonly ec2CronExpression: string;
  readonly ec2Memory: string;
}

export class Ec2FinderStack extends Construct {
  readonly finderRole: iam.Role;
  readonly securityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: Ec2FinderProps) {
    super(scope, id);

    const finderLG = new logs.LogGroup(this, "FinderLogGroup", {
      retention: logs.RetentionDays.TWO_WEEKS
    });
    finderLG.addMetricFilter("Finder-Error-Counts", {
      metricName: "FinderErrorCounts",
      metricNamespace: `${Aws.STACK_NAME}`,
      metricValue: "1",
      filterPattern: logs.FilterPattern.anyTerm("Error", "error")
    });

    const cfnfinderLG = finderLG.node.defaultChild as logs.CfnLogGroup;
    addCfnNagSuppressRules(cfnfinderLG, [
      {
        id: "W84",
        reason: "log group is encrypted with the default master key"
      }
    ]);

    const amznLinux = ec2.MachineImage.latestAmazonLinux2({
      edition: ec2.AmazonLinuxEdition.STANDARD,
      storage: ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
      cpuType: ec2.AmazonLinuxCpuType.ARM_64
    });

    this.securityGroup = new ec2.SecurityGroup(this, "S3FinderEC2SG", {
      vpc: props.vpc,
      description: "Security Group for Data Transfer Hub Fidner instance",
      allowAllOutbound: true
    });
    // For dev only
    // this.securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow ssh access');

    const cfnSG = this.securityGroup.node.defaultChild as ec2.CfnSecurityGroup;
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

    this.finderRole = new iam.Role(this, "FinderRole", {
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
            "logs:DescribeLogGroups",
            "autoscaling:UpdateAutoScalingGroup"
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

    this.finderRole.attachInlinePolicy(cwAgentPolicy);
    this.finderRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
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

    const instanceTypeTable = new CfnMapping(this, "InstanceTypeTable", {
      mapping: {
        "8": { instanceType: "m6g.large" },
        "16": { instanceType: "r6g.large" },
        "32": { instanceType: "r6g.xlarge" },
        "64": { instanceType: "r6g.2xlarge" },
        "128": { instanceType: "r6g.4xlarge" },
        "256": { instanceType: "r6g.8xlarge" },
        "384": { instanceType: "r6g.12xlarge" },
        "512": { instanceType: "r6g.16xlarge" },
      }
    });

    const instanceTypeName = instanceTypeTable.findInMap(
      props.ec2Memory,
      "instanceType"
    );

    const instanceType = new ec2.InstanceType(instanceTypeName);

    const finder_ud = ec2.UserData.forLinux();

    const finderLaunchTemplate = new ec2.LaunchTemplate(
      this,
      "FinderEC2LaunchTemplate",
      {
        instanceType: instanceType,
        machineImage: amznLinux,
        userData: finder_ud,
        role: this.finderRole,
        // keyName: 'ad-key',  // dev only
        securityGroup: this.securityGroup,
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

    const finderAsg = new asg.AutoScalingGroup(this, "S3RepFinderASG", {
      autoScalingGroupName: `${Aws.STACK_NAME}-Finder-ASG`,
      vpc: props.vpc,
      maxCapacity: 1,
      minCapacity: 0,
      desiredCapacity: 1,
      groupMetrics: [
        new asg.GroupMetrics(
          asg.GroupMetric.DESIRED_CAPACITY,
          asg.GroupMetric.IN_SERVICE_INSTANCES
        )
      ],
      cooldown: Duration.minutes(2),
      signals: asg.Signals.waitForMinCapacity(),
      launchTemplate: finderLaunchTemplate
    });

    NagSuppressions.addResourceSuppressions(finderAsg, [
      {
        id: "AwsSolutions-AS3",
        reason: "we do not need notification, this asg will change automated"
      }
    ]);

    Tags.of(finderAsg).add("Name", `${Aws.STACK_NAME}-Replication-Finder`, {});

    finderAsg.userData.addCommands(
      "yum update -y",
      "cd /home/ec2-user/",

      // Enable BBR
      'echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf',
      'echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf',
      "sysctl -p",
      "echo `sysctl net.ipv4.tcp_congestion_control` > finder.log",

      // Enable Cloudwatch Agent
      'echo "{\\"agent\\": {\\"metrics_collection_interval\\": 60,\\"run_as_user\\": \\"root\\"},\\"logs\\": {\\"logs_collected\\": {\\"files\\": {\\"collect_list\\": [{\\"file_path\\": \\"/home/ec2-user/finder.log\\",\\"log_group_name\\": \\"##log group##\\"}]}}}}" >> /home/ec2-user/cw_agent_config.json',
      "yum install -y amazon-cloudwatch-agent",
      `sed -i  -e "s/##log group##/${finderLG.logGroupName}/g" cw_agent_config.json`,
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
      `echo "export SRC_PREFIX_LIST=${props.env.SRC_PREFIX_LIST}" >> env.sh`,
      `echo "export SRC_PREFIX_LIST_BUCKET=${props.env.SRC_PREFIX_LIST_BUCKET}" >> env.sh`,
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

      // `echo "export MULTIPART_THRESHOLD=${props.env.MULTIPART_THRESHOLD}" >> env.sh`,
      // `echo "export CHUNK_SIZE=${props.env.CHUNK_SIZE}" >> env.sh`,
      `echo "export FINDER_DEPTH=${props.env.FINDER_DEPTH}" >> env.sh`,
      `echo "export SKIP_COMPARE=${props.env.SKIP_COMPARE}" >> env.sh`,
      `echo "export FINDER_NUMBER=${props.env.FINDER_NUMBER}" >> env.sh`,
      `echo "export finder_NUMBER=${props.env.finder_NUMBER}" >> env.sh`,
      `echo "export INCLUDE_METADATA=${props.env.INCLUDE_METADATA}" >> env.sh`,
      `echo "export AWS_DEFAULT_REGION=${Aws.REGION}" >> env.sh`,

      // Create the script
      'echo "source /home/ec2-user/env.sh" >> start-finder.sh',
      'echo "nohup ./dthcli run -t Finder |& tee -a /home/ec2-user/finder.log" >> start-finder.sh',
      "echo \"echo 'Exit Finder proccess, trying to set auto scaling group desiredCapacity to 0 to terminate instance after 60 seconds...' >> /home/ec2-user/finder.log\" >> start-finder.sh",
      `echo "sleep 61; mycount=0; while (( \\$mycount < 5 )); do aws autoscaling update-auto-scaling-group --region ${Aws.REGION} --auto-scaling-group-name ${Aws.STACK_NAME}-Finder-ASG --desired-capacity 0; sleep 10; ((mycount=\$mycount+1)); done;" >> start-finder.sh`, // change the asg desired-capacity to 0 to stop the finder task

      "chmod +x start-finder.sh",
      // Add to startup items
      'echo "@reboot /home/ec2-user/start-finder.sh" >> /var/spool/cron/root',
      // Run the script
      "./start-finder.sh"
    );

    const finderLauncherPolicy = new iam.Policy(this, "FinderLauncherPolicy", {
      statements: [
        new iam.PolicyStatement({
          actions: [
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:UpdateAutoScalingGroup"
          ],
          resources: ["*"]
        })
      ]
    });

    // Create the Finder Launch Lambda
    const finderLaunchFn = new lambda.Function(this, "FinderLaunchHelper", {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: "lambda_function.lambda_handler",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../lambda/plugin/s3/asg-helper")
      ),
      memorySize: 256,
      timeout: Duration.minutes(15),
      environment: {
        ASG_NAME: finderAsg.autoScalingGroupName
      }
    });
    finderLaunchFn.role!.attachInlinePolicy(finderLauncherPolicy);

    // Default Schedule CRON event to trigger JobSender per hour
    const enableFinderTrigger = new CfnCondition(this, "enableFinderTrigger", {
      expression: Fn.conditionEquals(props.ec2CronExpression, "")
    });

    // If props.ecsCronExpression is null, set CronExpression to 0/60 * * * ? 2000 to stop the schedule trigger
    const CronExpression = Fn.conditionIf(
      enableFinderTrigger.logicalId,
      "0/60 * * * ? 2000",
      props.ec2CronExpression
    );
    const trigger = new events.Rule(this, "DTHFinderSchedule", {
      schedule: events.Schedule.expression("cron(" + CronExpression + ")")
    });

    // Add target to cloudwatch rule.
    trigger.addTarget(new targets.LambdaFunction(finderLaunchFn));

    new CfnOutput(this, "FinderLogGroupName", {
      value: finderLG.logGroupName,
      description: "Finder Log Group Name"
    });
  }
}
