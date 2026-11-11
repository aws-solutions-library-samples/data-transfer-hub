# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.8] - 2026-11-11

### Changed
- Lambda functions from `python3.9` to `python3.13`, ahead of the `python3.9` deprecation.
- `aws-cdk` / `aws-cdk-lib` from `2.1117.0` / `2.248.0` to `2.1148.0` / `2.276.0`.
- `uuid` from `9.0.0` to `14.0.3` and dropped the now-redundant `@types/uuid` stub.

### Security
- Resolved 150 of 206 `npm audit` findings in `source/portal` (4 critical, 26 high) via `npm audit fix`.
- Resolved 3 high-severity `npm audit` findings in `source/constructs` via the `aws-cdk-lib` bump above.

## [2.6.7] - 2026-04-09

EUSC support, dependency upgrades, bug fixes

## [2.6.6] - 2024-11-22

### Security
- `cross-spawn` to mitigate [CVE-2024-21538]

## [2.6.5] - 2024-11-4

### Security
- `http-proxy-middleware` to mitigate [CVE-2024-21536]


## [2.6.4] - 2024-10-10

### Security
- `rollup` to mitigate [CVE-2024-47068]
  		  

## [2.6.3] - 2024-09-12

### Changed
- `Alpine` base image to be sourced from Amazon ECR.

### Security
- `micromatch` to mitigate [CVE-2024-4067](https://github.com/advisories/GHSA-952p-6rrq-rcjv) 
- `webpack` to mitigate [CVE-2024-43788](https://github.com/advisories/GHSA-4vvj-4cpr-p986)
- `path-to-regexp` to mitigate [CVE-2024-45296](https://github.com/advisories/GHSA-9wv6-86v2-598j)
- `serve-static` to mitigate [CVE-2024-43800](https://github.com/advisories/GHSA-cm22-4g7w-348p)
- `body-parser` to mitigate [CVE-2024-45590](https://github.com/advisories/GHSA-qwcr-r2fm-qrc7)
- `express` to mitigate [CVE-2024-43796](https://github.com/advisories/GHSA-qw6h-vgh9-j6wx)
- `send` to mitigate [CVE-2024-43799](https://github.com/advisories/GHSA-m6fv-jmcg-4jfg)

## [2.6.2] - 2024-08-19

### Fixed
- Fix the ECR get image tags issue [#153](https://github.com/aws-solutions/data-transfer-hub/issues/153).

### Security
- `ip` to mitigate [CVE-2024-29415]
- `webpack-dev-middleware` to mitigate [CVE-2024-29180]
- `@babel/traverse` to mitigate [CVE-2023-45133]
- `ws` to mitigate [CVE-2024-37890]
- `axios` to mitigate [CVE-2024-39338]
- `braces` to mitigate [CVE-2024-4068]
- `fast-xml-parser` to mitigate [CVE-2024-41818]
- `ejs` to mitigate [CVE-2024-33883]
- `express` to mitigate [CVE-2024-29041]
- `tar` to mitigate [CVE-2024-28863]
- `follow-redirects` to mitigate [CVE-2024-28849]
- `postcss` to mitigate [CVE-2023-44270]

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
