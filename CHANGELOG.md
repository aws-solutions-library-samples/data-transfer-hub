# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.1] - 2024-04-11

### Fixed

- Fix the ECR transfer task creation issue #147
- Fix the S3 transfer task creation issue #141
- Fix the Gov Cloud S3 transfer task assets issue #140
- Fix the error s3 plugin address issue #145

## [2.6.0] - 2024-01-18 

### Added

- Implemented server-side encryption options for writing objects into the Amazon S3 destination bucket: 'AES256' for AES256 encryption, 'AWS_KMS' for AWS Key Management Service encryption, and 'None' for no encryption. #124
- Provided the optional Amazon S3 bucket to hold prefix list file. #125, #97

### Changed

- Expanded Finder memory options, now including increased capacities of 316GB & 512GB.
- Added the feature of deleting KMS Key automatically after the solution pipeline status turns to stopped. #135
- Added the feature that Finder Instance enables DTH-CLI automatically after external reboot.
- Add documentation of how to deploy the S3/ECR transfer task using CloudFormation. #128

## [2.5.0] - 2023-09-15

### Added

- Added support for transferring ECR assets without tags #118
- Users can now list stopped tasks and clone tasks from the stopped ones #117

### Changed

- Enhanced transfer performance by utilizing cluster capabilities to transfer large files through multipart upload in parallel #116
- Added automatic restart functionality for the Worker CLI #109
- Enabled IMDSv2 by default for Auto Scaling Groups (ASG)
- Switched to using Launch Templates instead of Launch Configurations to launch ASG instances #115
- Automatically create a CloudFormation invalidation after the upgrade #52

## [2.4.0] - 2023-04-28

### Added

- Support for requester pay mode in S3 transfer task.

## [2.3.1] - 2023-04-18

### Fixed

- Fix deployment failure due to S3 ACL changes.

## [2.3.0] - 2023-03-30

### Added

- Support embedded dashboard and logs
- Support S3 Access Key Rotation
- Enhance One Time Transfer Task monitoring

## [1.0.1] - 2022-09-07

### Fixed

- Upgrade lambda runtime to python v3.7.0
- Fix the list limit of secrets

## [1.0.0] - 2021-12-22

### Added

- All files, initial version
