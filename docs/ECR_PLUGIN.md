
[中文](./ECR_PLUGIN_CN.md)

# Data Transfer Hub - ECR Plugin

## Table of contents
* [Introduction](#introduction)
* [Architect](#architect)
* [Deployment](#deployment)
* [FAQ](#faq)
  * [How to debug](#how-to-debug)
  * [How to customize](#how-to-customize)
## Introduction

[Data Transfer Hub](https://github.com/awslabs/data-transfer-hub), a.k.a Data Replication Hub, is a solution for transferring data from different sources into AWS.  This project is for ECR transfer plugin. You can deploy and run this plugin independently without the UI. 

The following are the planned features of this plugin.

- Transfer Amazon ECR between AWS accounts or regions
- Transfer Amazon ECR between AWS Standard partition and AWS CN partition
- Transfer Public container image registry to AWS ECR
- Transfer all images or only selected Images
- Support One-time transfer
- Support Incremental transfer

This plugin uses [**skopeo**](https://github.com/containers/skopeo) as the tool to copy images to Aamazon ECR. If same layer already exists in target ECR, it will not be copied again.


## Architecture

![ECR Plugin Architecture](./en-base/images/s3-arch-global.png)
<!-- ![S3 Plugin Architecture](./en-base/images/s3-arch-global.png) -->

EventBridge Rule to trigger Step functions to execute on a regular basis. (By default, daily)

Step functions will invoke Lambda to get the list of images from source. 

Lambda will either list all the repositorys in the source ECR or get the stored selected image list from System Manager Parameter Store.

The transfer task will be run within Fargate in a max concurrency of 10. If a transfer task failed for some reason, it will automatically retry for 3 times.

Each task uses `skopeo copy` to copy the images into target ECR

Once copy is completed, the status (either success or failed) will be logged into DynamoDB for tracking purpose


## Deployment

Things to know about the deployment of this plugin:

- The deployment will automatically provision resources like lambda, dynamoDB table, ECS Task Definition in your AWS account, etc.
- The deployment will take approximately 3-5 minutes.
- Once the deployment is completed, the data transfer task will start right away.

Please follow the steps in the [Deployment Guide](./ECR_DEPLOYMENT_EN.md) to start the deployment.

> Note: You can simply delete the stack from CloudFormation console if the data transfer job is no longer required.

## FAQ
### How to debug

**Q**: There seems to be something wrong, how to debug?

**A**: When you deploy the stack, you will be asked to input the stack name (default is DTHECRStack), most of the resources will be created with name prefix as the stack name.  For example, Step Function name will be in a format of `<StackName>-ECRReplicationSM`.

There will be two main log groups created by this plugin.

- /aws/lambda/&lt;StackName&gt;-ListImagesFunction&lt;random suffix&gt;

This is the log group for listing Image Lambda Function. If there is no data transferred, you should check if something is wrong in the Lambda log. This is the first step.

- &lt;StackName&gt;-DTHECRContainerLogGroup&lt;random suffix&gt;

This is the log group for all ECS containers, detailed transfer log can be found here.

If you can't find anything helpful in the log group, please raise an issue in Github.

### How to customize

**Q**: I want to make some custom changes, how do I do?

If you want to make custom changes to this plugin, you can follow [custom build](CUSTOM_BUILD.md) guide.

> Note: More FAQ please refer to [Implementation Guide - FAQ](https://awslabs.github.io/data-transfer-hub/en/faq/).
