The Data Transfer Hub solution provides secure, scalable, and trackable data transfer for Amazon Simple Storage Service (Amazon S3) objects and Amazon Elastic Container Registry (Amazon ECR) images. This data transfer helps customers expand their businesses globally in and out of Amazon Web Services China Regions. 

The solution’s web console provides an interface for managing the following tasks:

- Transferring Amazon S3 objects between Amazon Web Services China Regions and Amazon Web Services Standard Regions
- Transferring data from other cloud providers’ object storage services (including Alibaba Cloud OSS, Tencent COS, and Qiniu Kodo) to Amazon S3
- Transferring objects from Amazon S3 compatible object storage service to Amazon S3
- Transferring Amazon ECR images between Amazon Web Services China Regions and Amazon Web Services Standard Regions
- Transferring container images from public container registries (for example, Docker Hub, Google gcr.io, Red Hat Quay.io) to Amazon ECR

!!! note "Note"

    If you need to transfer Amazon S3 objects between Amazon Web Services Standard Regions, we recommend that you use [Cross-Region Replication][crr]; if you want to transfer Amazon S3 objects within the same Amazon Web Services Standard Region, we recommend using [Same-Region Replication][srr].

This implementation guide describes architectural considerations and configuration steps for deploying Data Transfer Hub in the Amazon Web Services Cloud. It includes links to an Amazon [CloudFormation][cloudformation] template that launches and configures the Amazon services required to deploy this solution using Amazon Web Services best practices for security and availability.

The guide is intended for IT architects, developers, DevOps, data analysts, and marketing technology professionals who have practical experience architecting in the Amazon Web Services Cloud. 

[cloudformation]: https://aws.amazon.com/en/cloudformation/
[crr]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html#crr-scenario
[srr]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html#srr-scenario