// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  Construct,
} from 'constructs';
import {  
  RemovalPolicy,
  Duration,
  Aws,
  aws_cloudfront as cloudfront,
  aws_s3 as s3,
  aws_s3_deployment as s3Deployment,
  aws_iam as iam,
  aws_lambda as lambda, 
  custom_resources as cr,
} from 'aws-cdk-lib';
import { CloudFrontToS3 } from '@aws-solutions-constructs/aws-cloudfront-s3';

import * as path from 'path'
import { AuthType, addCfnNagSuppressRules } from './constructs-stack';
import { NagSuppressions } from 'cdk-nag';

// const { BUCKET_NAME, SOLUTION_NAME, VERSION } = process.env


export interface PortalStackProps {
  auth_type: string,
  aws_oidc_customer_domain: string,
  aws_oidc_provider: string,
  aws_oidc_client_id: string,
  aws_user_pools_id: string,
  aws_user_pools_web_client_id: string,
  aws_appsync_graphqlEndpoint: string,
  taskCluster?: {
    ecsSubnets: string[]
    ecsVpcId: string,
    ecsClusterName: string
  }
}

export class PortalStack extends Construct {

  readonly websiteURL: string

  constructor(scope: Construct, id: string, props: PortalStackProps) {
    super(scope, id);

    const getDefaultBehavior = () => {
      if (props.auth_type === AuthType.COGNITO) {
        return {
          responseHeadersPolicy: new cloudfront.ResponseHeadersPolicy(
            this,
            'ResponseHeadersPolicy',
            {
              responseHeadersPolicyName: `SecHdr${Aws.REGION}${Aws.STACK_NAME}`,
              comment: 'Security Headers Policy',
              securityHeadersBehavior: {
                contentSecurityPolicy: {
                  contentSecurityPolicy: `default-src 'self'; upgrade-insecure-requests; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${props.aws_appsync_graphqlEndpoint} https://cognito-idp.${Aws.REGION}.amazonaws.com/`,
                  override: true,
                },
                contentTypeOptions: { override: true },
                frameOptions: {
                  frameOption: cloudfront.HeadersFrameOption.DENY,
                  override: true,
                },
                referrerPolicy: {
                  referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
                  override: true,
                },
                strictTransportSecurity: {
                  accessControlMaxAge: Duration.seconds(600),
                  includeSubdomains: true,
                  override: true,
                },
                xssProtection: {
                  protection: true,
                  modeBlock: true,
                  override: true,
                },
              },
            }
          ),
        };
      }
      return {};
    };

    const website = new CloudFrontToS3(this, 'Web', {
      bucketProps: {
        versioned: true,
        encryption: s3.BucketEncryption.S3_MANAGED,
        accessControl: s3.BucketAccessControl.PRIVATE,
        enforceSSL: true,
        removalPolicy: RemovalPolicy.RETAIN,
        autoDeleteObjects: false,
      },
      cloudFrontDistributionProps: {
        priceClass: cloudfront.PriceClass.PRICE_CLASS_ALL,
        minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
        enableIpv6: false,
        enableLogging: true,  //Enable access logging for the distribution.
        comment: `Data Transfer Hub Portal Distribution (${Aws.REGION})`,
        errorResponses: [
          {
            httpStatus: 403,
            responseHttpStatus: 200,
            responsePagePath: "/index.html",
          }
        ],
        defaultBehavior: getDefaultBehavior(),
      },
      insertHttpSecurityHeaders: false,
    });
    NagSuppressions.addResourceSuppressions(
      website.cloudFrontWebDistribution,
      [
        {
          id: 'AwsSolutions-CFR1',
          reason: 'Use case does not warrant CloudFront Geo restriction'
        }, {
          id: 'AwsSolutions-CFR2',
          reason: 'Use case does not warrant CloudFront integration with AWS WAF'
        }, {
          id: 'AwsSolutions-CFR4',
          reason: 'CloudFront automatically sets the security policy to TLSv1 when the distribution uses the CloudFront domain name'
        }, {
          id: 'AwsSolutions-CFR7',
          reason: 'OAI is managed by @aws-solutions-constructs/aws-cloudfront-s3 construct'
        }
      ],
    );

    const websiteBucket = website.s3Bucket as s3.Bucket;
    const websiteLoggingBucket = website.s3LoggingBucket as s3.Bucket;
    const websiteDist = website.cloudFrontWebDistribution.node.defaultChild as cloudfront.CfnDistribution

    if (props.auth_type === AuthType.OPENID) {
      // Currently, CachePolicy and Cloudfront Function is not available in Cloudfront in China Regions.
      // Need to override the default CachePolicy to use ForwardedValues to support both China regions and Global regions.
      // This should be updated in the future once the feature is landed in China regions.
      websiteDist.addPropertyOverride('DistributionConfig.DefaultCacheBehavior.CachePolicyId', undefined)
      websiteDist.addPropertyOverride('DistributionConfig.DefaultCacheBehavior.ForwardedValues', {
        "Cookies": {
          "Forward": "none"
        },
        "QueryString": false
      })
    } else {
      const cfFunction = new cloudfront.Function(this, "DataTransferHubSecurityHeader", {
        functionName: `DTHSecHdr${Aws.REGION}${Aws.STACK_NAME}`,
        code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
    var response = event.response;
    var headers = response.headers;
    headers['strict-transport-security'] = { value: 'max-age=63072000; includeSubdomains; preload' };
    headers['content-security-policy'] = { value: "default-src 'self'; upgrade-insecure-requests; frame-ancestors 'none'; frame-src 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${props.aws_appsync_graphqlEndpoint} https://cognito-idp.${Aws.REGION}.amazonaws.com/" };
    headers['x-content-type-options'] = { value: 'nosniff' };
    headers['x-frame-options'] = { value: 'DENY' };
    headers['x-xss-protection'] = { value: '1; mode=block' };

    // Set the cache-control header
    headers['cache-control'] = { value: 'public, max-age=604800;' };
    return response;
}`
        )


      });
      websiteDist.addPropertyOverride('DistributionConfig.DefaultCacheBehavior.FunctionAssociations', [
        {
          "EventType": "viewer-response",
          "FunctionARN": cfFunction.functionArn,
        }
      ])
    }

    // CustomResourceRole
    const customResourceRole = new iam.Role(this, 'CustomResourceRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      path: '/',
      // roleName: `${Aws.STACK_NAME}CustomResourceRole-${Aws.REGION}`
    })
    const cfnCustomResourceRole = customResourceRole.node.defaultChild as iam.CfnRole;
    cfnCustomResourceRole.overrideLogicalId('CustomResourceRole');

    // CustomResourcePolicy
    const customResourcePolicy = new iam.Policy(this, 'CustomResourcePolicy', {
      policyName: `${Aws.STACK_NAME}CustomResourcePolicy`,
      statements: [
        new iam.PolicyStatement({
          actions: [
            'logs:CreateLogStream',
            'logs:CreateLogGroup',
            'logs:PutLogEvents'
          ],
          resources: [
            `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:/aws/lambda/*`
          ]
        }),
        new iam.PolicyStatement({
          actions: [
            's3:GetObject',
            's3:PutObject',
            's3:ListBucket'
          ],
          resources: [
            `arn:${Aws.PARTITION}:s3:::*`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'cloudfront:GetInvalidation',
            'cloudfront:CreateInvalidation',
          ],
          resources: [
            `arn:${Aws.PARTITION}:cloudfront::${Aws.ACCOUNT_ID}:distribution/${website.cloudFrontWebDistribution.distributionId}`,
          ],
        })
      ]
    });
    customResourcePolicy.attachToRole(customResourceRole);
    const cfnCustomResourcePolicy = customResourcePolicy.node.defaultChild as iam.CfnPolicy;
    cfnCustomResourcePolicy.overrideLogicalId('CustomResourcePolicy');

    new s3Deployment.BucketDeployment(this, 'DeployWebsite', {
      sources: [s3Deployment.Source.asset(path.join(__dirname, '../../portal/build'))],
      destinationBucket: websiteBucket,
      // disable this, otherwise the aws-exports.json will be deleted
      prune: false,
    })

    this.websiteURL = website.cloudFrontWebDistribution.distributionDomainName

    const customResourceFunction = new lambda.Function(this, 'CustomHandler', {
      description: `${Aws.STACK_NAME} - - Custom resource`,
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'lambda_function.lambda_handler',
      timeout: Duration.seconds(30),
      memorySize: 512,
      role: customResourceRole,
      code: lambda.Code.fromAsset(path.join(__dirname, '../../custom-resource/')),
      environment: {
        WEB_BUCKET_NAME: websiteBucket.bucketName,
        SRC_PREFIX_LIST_BUCKET_NAME: websiteLoggingBucket.bucketName,
        API_ENDPOINT: props.aws_appsync_graphqlEndpoint,
        OIDC_PROVIDER: props.aws_oidc_provider,
        OIDC_CLIENT_ID: props.aws_oidc_client_id,
        OIDC_CUSTOMER_DOMAIN: props.aws_oidc_customer_domain,
        CLOUDFRONT_URL: this.websiteURL,
        CLOUDFRONT_DISTRIBUTION_ID: website.cloudFrontWebDistribution.distributionId,
        AUTHENTICATION_TYPE: props.auth_type === AuthType.OPENID ? 'OPENID_CONNECT' : 'AMAZON_COGNITO_USER_POOLS',
        USER_POOL_ID: props.aws_user_pools_id,
        USER_POOL_CLIENT_ID: props.aws_user_pools_web_client_id,
        SOLUTION_VERSION: process.env.VERSION || "v1.0.0",
        ECS_VPC_ID: props.taskCluster?.ecsVpcId || "",
        ECS_CLUSTER_NAME: props.taskCluster?.ecsClusterName || "",
        ECS_SUBNETS: props.taskCluster?.ecsSubnets.join(",") || ""
      }
    })

    const cfnCustomResourceFn = customResourceFunction.node.defaultChild as lambda.CfnFunction
    addCfnNagSuppressRules(cfnCustomResourceFn, [
      {
        id: 'W58',
        reason: 'Lambda function already has permission to write CloudWatch Logs'
      }
    ])

    const crLambda = new cr.AwsCustomResource(this, "CustomResourceConfig", {
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ["lambda:InvokeFunction"],
          effect: iam.Effect.ALLOW,
          resources: [customResourceFunction.functionArn],
        }),
      ]),
      timeout: Duration.minutes(15),
      onUpdate: {
        service: "Lambda",
        action: "invoke",
        parameters: {
          FunctionName: customResourceFunction.functionName,
          InvocationType: "Event",
        },
        physicalResourceId: cr.PhysicalResourceId.of(Date.now().toString()),
      },
    });
    crLambda.node.addDependency(customResourceFunction);
  }
}