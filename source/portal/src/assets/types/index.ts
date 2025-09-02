// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Task Type Icons
import ICON_S3 from "../images/icon-s3.png";
import ICON_ECR from "../images/icon-ecr.png";

import STATUS_PENDING from "@material-ui/icons/Schedule";
import STATUS_PROGRESS from "@material-ui/icons/RemoveCircleOutline";
import STATUS_ERROR from "@material-ui/icons/HighlightOff";
import STATUS_DONE from "@material-ui/icons/CheckCircleOutline";
import { AUTH_TYPE } from "aws-appsync-auth-link";

export enum AppSyncAuthType {
  OPEN_ID = AUTH_TYPE.OPENID_CONNECT,
  AMAZON_COGNITO_USER_POOLS = AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
}

export interface AmplifyConfigType {
  taskCluster: {
    ecsVpcId: string;
    ecsClusterName: string;
    ecsSubnets: string[];
  };
  aws_appsync_region: string;
  aws_appsync_authenticationType: AppSyncAuthType;
  aws_user_pools_id: string;
  aws_oidc_customer_domain: "";
  aws_project_region: string;
  aws_oidc_provider: string;
  aws_cognito_region: string;
  aws_oidc_client_id: string;
  aws_cloudfront_url: string;
  aws_appsync_graphqlEndpoint: string;
  aws_user_pools_web_client_id: string;
  src_prefix_list_bucket: string;
}

export interface AmplifyJSONType {
  taskCluster: {
    ecsVpcId: string;
    ecsClusterName: string;
    ecsSubnets: string[];
  };
  aws_appsync_region: string;
  aws_appsync_authenticationType: string;
  aws_user_pools_id: string;
  aws_oidc_customer_domain: string;
  aws_project_region: string;
  aws_oidc_provider: string;
  aws_cognito_region: string;
  aws_oidc_client_id: string;
  aws_cloudfront_url: string;
  aws_appsync_graphqlEndpoint: string;
  aws_user_pools_web_client_id: string;
}

// S3 ENGINE TYPE
export enum S3_ENGINE_TYPE {
  LAMBDA = "lambda",
  EC2 = "ec2",
}

export const S3_EDITION_LIST = [
  { name: "EC2 Graviton 2", value: S3_ENGINE_TYPE.EC2, recommened: true },
  { name: "Lambda", value: S3_ENGINE_TYPE.LAMBDA },
];

// Redux Action Type
export enum ACTION_TYPE {
  UPDATE_USER_EMAIL = "update user email",
  UPDATE_AMPLIFY_CONFIG = "update amplify config",
  OPEN_SIDE_BAR = "open side bar",
  CLOSE_SIDE_BAR = "close side bar",
  OPEN_INFO_BAR = "open info bar",
  CLOSE_INFO_BAR = "close info bar",
  UPDATE_TASK_INFO = "update task info",
  UPDATE_ECR_TASK_INFO = "update ecr task info",
  SET_CREATE_TASK_FLAG = "set create task flag",
  HIDE_CREATE_TASK_FLAG = "hide create task flag",
  SET_INFO_SPAN_TYPE = "set info span type",
  SET_AUTH0_LOGOUT_URL = "set Auth0 logout url",
}

// Task Tyep Enum
export enum EnumTaskType {
  S3_EC2 = "S3EC2",
  S3 = "S3",
  DynamoDB = "DynamoDB",
  ECR = "ECR",
  MongoDB = "MongoDB",
  MySQL = "MySQL",
}

export const S3_TASK_TYPE_MAP: any = {
  S3: { name: "Amazon S3 Transfer Plugin Lambda" },
  S3EC2: { name: "Amazon S3 Transfer Plugin Graviton2" },
};

// Task List
export const TYPE_LIST = [
  {
    id: 1,
    name: "Amazon S3",
    value: EnumTaskType.S3,
    imageSrc: ICON_S3,
    disabled: false,
  },
  // {
  //   id: 2,
  //   name: "Amazon Dynamo DB",
  //   value: EnumTaskType.DynamoDB,
  //   imageSrc: ICON_DYDB,
  //   disabled: true,
  // },
  {
    id: 3,
    name: "Amazon ECR",
    value: EnumTaskType.ECR,
    imageSrc: ICON_ECR,
    disabled: false,
  },
  // {
  //   id: 4,
  //   name: "Mongo DB",
  //   value: EnumTaskType.MongoDB,
  //   imageSrc: ICON_MONGO,
  //   disabled: true,
  // },
  // {
  //   id: 5,
  //   name: "MySQL",
  //   value: EnumTaskType.MySQL,
  //   imageSrc: ICON_MYSQL,
  //   disabled: true,
  // },
];

export enum EnumBucketType {
  Source = "Source",
  Destination = "Destination",
}

// Task Tyep Enum
export enum EnumSourceType {
  S3 = "Amazon_S3",
  S3_COMPATIBLE = "Amazon_S3_Compatible",
  Qiniu = "Qiniu_Kodo",
  AliOSS = "Aliyun_OSS",
  TencentCOS = "Tencent_COS",
  GoogleGCS = "Google_GCS",
}

// Task Tyep Enum
export enum ECREnumSourceType {
  ECR = "Amazon_ECR",
  PUBLIC = "Public",
}

// Docker Image Type
export enum EnumDockerImageType {
  ALL = "ALL",
  SELECTED = "SELECTED",
}

export enum EnumTaskStatus {
  STARTING = "STARTING",
  STOPPING = "STOPPING",
  ERROR = "ERROR",
  IN_PROGRESS = "IN_PROGRESS",
  DONE = "DONE",
  STOPPED = "STOPPED",
}

export const TASK_STATUS_MAP: any = {
  STARTING: { name: "Starting", src: STATUS_PENDING, class: "gray" },
  STOPPING: { name: "Stopping", src: STATUS_PENDING, class: "gray" },
  ERROR: { name: "Error", src: STATUS_ERROR, class: "error" },
  IN_PROGRESS: { name: "In Progress", src: STATUS_PROGRESS, class: "gray" },
  DONE: { name: "Completed", src: STATUS_DONE, class: "success" },
  STOPPED: { name: "Stopped", src: STATUS_PENDING, class: "gray" },
  UNKNOWN: { name: "Unknown", src: STATUS_PENDING, class: "gray" },
};

export interface ISouceType {
  id: string;
  en_name: string;
  zh_name: string;
  value: string;
  en_desc: string;
  zh_desc: string;
  [key: string]: string;
}

// ECR Task Source Type List
export const ECR_SOURCE_TYPE = [
  {
    id: "1",
    en_name: "Amazon ECR",
    zh_name: "Amazon ECR",
    value: ECREnumSourceType.ECR,
    en_desc: "Transfer Amazon ECR Images between Amazon Web Services regions.",
    zh_desc: "在 Amazon ECR 之间传输容器镜像.",
  },
  {
    id: "2",
    en_name: "Public Container Registry",
    zh_name: "公共容器仓库",
    value: ECREnumSourceType.PUBLIC,
    en_desc: "Transfer from a standard Public Container Registry..",
    zh_desc: "从标准公共容器仓库传输容器镜像到ECR.",
  },
];

// ECR Task Source Type List
export const DOCKER_IMAGE_TYPE = [
  {
    id: 1,
    en_name: "All",
    zh_name: "全部",
    value: EnumDockerImageType.ALL,
    en_desc: "Transfer all images in the source with tagged and untagged.",
    zh_desc: "传输源中带有标记和未标记的所有容器镜像",
  },
  {
    id: 2,
    en_name: "Selected Images",
    zh_name: "选择容器镜像",
    value: EnumDockerImageType.SELECTED,
    en_desc: "Transfer only selected Container Images.",
    zh_desc: "只传输所选择需要传输的容器镜像.",
  },
];
