import { EnumSourceType } from "../types/index";

export const GITHUB_LINK =
  "https://github.com/awslabs/aws-data-replication-hub";
// Home page links
export const WHAT_IS_LINK = GITHUB_LINK + "#readme";
export const COPY_BETWEEN_LINK =
  GITHUB_LINK + "/docs/tutortial-oregon-to-beijing-s3.md";
export const COPY_OSS_S3_LINK =
  GITHUB_LINK + "/docs/tutortial-migration-oss-to-s3.md";

export const DOCUMENT_LINK = GITHUB_LINK + "#readme";
export const FAQ_LINK = GITHUB_LINK + "#faq";
export const REPORT_ISSUE_LINK = GITHUB_LINK + "/issues/new";

// URL to be done
export const URL = "";
export const URL_FEEDBACK = GITHUB_LINK + "/issues/new";
export const SSM_LINK_MAP: any = {
  china: "https://console.amazonaws.cn/secretsmanager",
  global: "https://console.aws.amazon.com/secretsmanager",
};

export const CLOUD_WATCH_DASHBOARD_LINK_MAP: any = {
  china: "https://console.amazonaws.cn/cloudwatch/home",
  global: "https://console.aws.amazon.com/cloudwatch/home",
};

export const SSM_PARASTORE_HELP_LINK_MAP: any = {
  china:
    "https://docs.aws.amazon.com/zh_cn/secretsmanager/latest/userguide/manage_create-basic-secret.html",
  global:
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_create-basic-secret.html",
};

export const S3_BUCKET_PREFIX_LINK =
  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html";

export const S3_EVENT_LINK =
  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html";

export const METADATA_LINK =
  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html";

export const BBR_LINK = "https://github.com/google/bbr";

export const BBR_LEARN_MORE_LINK =
  "https://www.techrepublic.com/article/how-to-enable-tcp-bbr-to-improve-network-speed-on-linux/";

export const S3_BUCKET_URL = "https://s3.console.aws.amazon.com/s3/buckets/";

export const DEST_OBJECT_ACL_LINK =
  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl";

export const AUTO_SCALING_LINK =
  "https://docs.aws.amazon.com/autoscaling/ec2/userguide/what-is-amazon-ec2-auto-scaling.html";

export const CRON_HELP_LINK =
  "https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#CronExpressions";

export const CUR_SUPPORT_LANGS: string[] = ["zh", "en"];

export const GLOBAL_STR = "global";
export const CHINA_STR = "china";
export const DRH_REGION_TYPE_NAME = "DTH_REGION_TYPE";
export const DRH_CONFIG_JSON_NAME = "DTH_CONFIG_JSON";
export const DRH_REGION_NAME = "DTH_CUR_REGION";
export const AUTH_TYPE_NAME = "DTH_AUTH_TYPE";
export const AUTH_USER_EMAIL = "DTH_AUTH_USER_EMAIL";

export const MenuProps: any = {
  getContentAnchorEl: null,
  anchorOrigin: {
    vertical: "bottom",
    horizontal: "left",
  },
};

export interface IRegionType {
  name: string;
  value: string;
}

export const S3_PARAMS_LIST_MAP: any = {
  sourceType: {
    en_name: "Source Type",
    zh_name: "数据源类型",
  },
  srcType: {
    en_name: "Source Type",
    zh_name: "数据源类型",
  },
  srcEndpoint: {
    en_name: "Source Endpoint URL",
    zh_name: "源数据端点URL",
  },
  srcBucketName: {
    en_name: "Source Bucket Name",
    zh_name: "源数据桶名称",
  },
  srcBucket: {
    en_name: "Source Bucket Name",
    zh_name: "源数据桶名称",
  },
  srcBucketPrefix: {
    en_name: "Source Bucket Object Prefix",
    zh_name: "源数据桶对象前缀",
  },
  srcPrefix: {
    en_name: "Source Bucket Object Prefix",
    zh_name: "源数据桶对象前缀",
  },
  srcPrefixsListFile: {
    en_name: "Object Prefixes File",
    zh_name: "源数据桶多对象前缀文件",
  },
  enableS3Event: {
    en_name: "Enable S3 Event",
    zh_name: "启用S3事件",
  },
  srcEvent: {
    en_name: "Enable S3 Event",
    zh_name: "启用S3事件",
  },
  srcInCurrentAccount: {
    en_name: "Source in Current Account",
    zh_name: "源数据桶是否在当前账户",
  },
  srcRegion: {
    en_name: "Source Region",
    zh_name: "源数据区域名称",
  },
  srcCredentials: {
    en_name: "Source Secret Key for Credential in Secrets Manager",
    zh_name: "源数据凭证中的密钥名称名称",
  },
  destBucketName: {
    en_name: "Destination Bucket Name",
    zh_name: "目标数据桶名称",
  },
  destBucket: {
    en_name: "Destination Bucket Name",
    zh_name: "目标数据桶名称",
  },
  destBucketPrefix: {
    en_name: "Destination Bucket Object Prefix",
    zh_name: "目标数据桶对象前缀",
  },
  destPrefix: {
    en_name: "Destination Bucket Object Prefix",
    zh_name: "目标数据桶对象前缀",
  },
  destStorageClass: {
    en_name: "Destination Object Storage Class",
    zh_name: "目标S3存储类型",
  },
  destInCurrentAccount: {
    en_name: "Destination in Current Account",
    zh_name: "目标数据桶是否在当前账户",
  },
  regionName: {
    en_name: "Region Name",
    zh_name: "区域名称",
  },
  destRegion: {
    en_name: "Destination Region",
    zh_name: "目标区域名称",
  },
  credentialsParameterStore: {
    en_name: "Secret key for Credentials",
    zh_name: "密钥名称",
  },
  destCredentials: {
    en_name: "Destination Secret key for Credentials",
    zh_name: "目标区域的密钥名称",
  },
  includeMetadata: {
    en_name: "Include Metadata",
    zh_name: "是否包含元数据",
  },
  destAcl: {
    en_name: "Object ACL",
    zh_name: "目标对象ACL",
  },
  finderDepth: {
    en_name: "Finder Depth",
    zh_name: "查找器深度",
  },
  finderNumber: {
    en_name: "Finder Number",
    zh_name: "查找器数量",
  },
  ecsFargateMemory: {
    en_name: "Finder Memory",
    zh_name: "查找器内存大小",
  },
  workerNumber: {
    en_name: "Worker Number",
    zh_name: "工作线程数",
  },
  maxCapacity: {
    en_name: "Max Capacity",
    zh_name: "最大容量",
  },
  minCapacity: {
    en_name: "Min Capacity",
    zh_name: "最小容量",
  },
  desiredCapacity: {
    en_name: "Desired Capacity",
    zh_name: "所需容量",
  },
  ecsCronExpression: {
    en_name: "Cron Expression",
    zh_name: "Cron表达式",
  },
  srcSkipCompare: {
    en_name: "Need Data Comparison before Transfer",
    zh_name: "是否需要数据比对",
  },
  lambdaMemory: {
    en_name: "Lambda Memory",
    zh_name: "Lambda 内存",
  },
  multipartThreshold: {
    en_name: "Multipart Threshold",
    zh_name: "大文件分段阈值",
  },
  chunkSize: {
    en_name: "Chunk Size",
    zh_name: "分段大小",
  },
  maxThreads: {
    en_name: "Max Threads",
    zh_name: "最大线程数",
  },
  alarmEmail: {
    en_name: "Alarm Email",
    zh_name: "通知邮箱",
  },
};

export const ECR_PARAMS_LIST_MAP: any = {
  srcRegion: {
    en_name: "Source region",
    zh_name: "源仓库区域",
  },
  srcAccountId: {
    en_name: "Source Amazon Web Services Account ID",
    zh_name: "源Amazon Web Services账户ID",
  },
  srcList: {
    en_name: "Type of Source Image List",
    zh_name: "源容器镜像类型",
  },
  srcImageList: {
    en_name: "Source Image List",
    zh_name: "容器镜像列表",
  },
  srcCredential: {
    en_name: "Source Credential Parameter Name",
    zh_name: "源仓库凭证参数名称",
  },
  sourceInAccount: {
    en_name: "Source In Account?",
    zh_name: "数据源在当前账户吗？",
  },
  destRegion: {
    en_name: "Destination Amazon Web Services Region",
    zh_name: "目的仓库Amazon Web Services区域",
  },
  destInAccount: {
    en_name: "Destination In Account?",
    zh_name: "目的仓库在当前账户吗？",
  },
  destAccountId: {
    en_name: "Destination Amazon Web Services Account ID",
    zh_name: "目的仓库Amazon Web Services账户ID",
  },
  sourceType: {
    en_name: "Source Type",
    zh_name: "源仓库类型",
  },
  destPrefix: {
    en_name: "Destination Image Prefix",
    zh_name: "目标容器镜像前缀",
  },
  destCredential: {
    en_name: "Destination Credential Parameter Name",
    zh_name: "目的仓库凭证参数名称",
  },
  alarmEmail: {
    en_name: "Alarm Email",
    zh_name: "通知邮箱",
  },
};

export enum YES_NO {
  YES = "Yes",
  NO = "No",
}

export enum CRON_TYPE {
  ONE_TIME = "ONE_TIME",
  FIXED_RATE = "FIXED_RATE",
  CRON_EXPRESS = "CRON_EXPRESS",
}

export enum S3_EVENT_TYPE {
  NO = "No",
  CREATE_ONLY = "Create_Only",
  DELETE_ONLY = "Delete_Only",
  CREATE_AND_DELETE = "Create_And_Delete",
  CREATE_ONLY_EC2 = "Create",
  CREATE_AND_DELETE_EC2 = "CreateAndDelete",
}

export enum S3SourcePrefixType {
  FullBucket = "FullBucket",
  SinglePrefix = "SinglePrefix",
  MultiplePrefix = "MultiplePrefix",
}

export enum S3_STORAGE_CLASS_TYPE {
  STANDARD = "STANDARD",
  STANDARD_IA = "STANDARD_IA",
  ONEZONE_IA = "ONEZONE_IA",
  INTELLIGENT_TIERING = "INTELLIGENT_TIERING",
}

export enum CRON_FIX_UNIT {
  DAYS = "DAYS",
  MINUTES = "MINUTES",
  HOURS = "HOURS",
}

export const S3SourcePrefixTypeList = [
  {
    value: S3SourcePrefixType.FullBucket,
    name: "Full Bucket",
  },
  {
    value: S3SourcePrefixType.SinglePrefix,
    name: "Objects with a specific prefix",
  },
  {
    value: S3SourcePrefixType.MultiplePrefix,
    name: "Objects with defferent prefixes",
  },
];

export const AWS_REGION_LIST = [
  { value: "us-east-2", name: "Ohio(us-east-2)" },
  { value: "us-east-1", name: "N. Virginia(us-east-1)" },
  { value: "us-west-1", name: "N. California(us-west-1)" },
  { value: "us-west-2", name: "Oregon(us-west-2)" },
  { value: "af-south-1", name: "Cape Town(af-south-1)" },
  { value: "ap-east-1", name: "Hong Kong(ap-east-1)" },
  { value: "ap-south-1", name: "Mumbai(ap-south-1)" },
  { value: "ap-northeast-3", name: "Osaka-Local(ap-northeast-3)" },
  { value: "ap-northeast-2", name: "Seoul(ap-northeast-2)" },
  { value: "ap-southeast-1", name: "Singapore(ap-southeast-1)" },
  { value: "ap-southeast-2", name: "Sydney(ap-southeast-2)" },
  { value: "ap-northeast-1", name: "Tokyo(ap-northeast-1)" },
  { value: "ca-central-1", name: "Central(ca-central-1)" },
  { value: "cn-north-1", name: "Beijing(cn-north-1)" },
  { value: "cn-northwest-1", name: "Ningxia(cn-northwest-1)" },
  { value: "eu-central-1", name: "Frankfurt(eu-central-1)" },
  { value: "eu-west-1", name: "Ireland(eu-west-1)" },
  { value: "eu-west-2", name: "London(eu-west-2)" },
  { value: "eu-south-1", name: "Milan(eu-south-1)" },
  { value: "eu-west-3", name: "Paris(eu-west-3)" },
  { value: "eu-north-1", name: "Stockholm(eu-north-1)" },
  { value: "me-south-1", name: "Bahrain(me-south-1)" },
  { value: "sa-east-1", name: "São Paulo(sa-east-1)" },
  { value: "us-gov-west-1", name: "US-Gov-West(us-gov-west-1)" },
  { value: "us-gov-east-1", name: "US-Gov-East(us-gov-east-1)" },
];

export const ALICLOUD_REGION_LIST = [
  { value: "cn-qingdao", name: "Qingdao(cn-qingdao)" },
  { value: "cn-beijing", name: "Beijing(cn-beijing)" },
  { value: "cn-chengdu", name: "Chengdu(cn-chengdu)" },
  { value: "cn-hangzhou", name: "Hangzhou(cn-hangzhou)" },
  { value: "cn-shanghai", name: "Shanghai(cn-shanghai)" },
  { value: "cn-zhangjiakou", name: "Zhangjiakou(cn-zhangjiakou)" },
  { value: "cn-huhehaote", name: "Hohhot(cn-huhehaote)" },
  { value: "cn-shenzhen", name: "Shenzhen(cn-shenzhen)" },
  { value: "cn-heyuan", name: "Heyuan(cn-heyuan)" },
  { value: "cn-guangzhou", name: "Guangzhou(cn-guangzhou)" },
  { value: "cn-wulanchabu", name: "Ulanqab(cn-wulanchabu)" },
  { value: "cn-hongkong", name: "Hong Kong(cn-hongkong)" },
  { value: "ap-southeast-1", name: "Singapore(ap-southeast-1)" },
  { value: "ap-southeast-2", name: "Sydney(ap-southeast-2)" },
  { value: "ap-southeast-3", name: "Kuala Lumpur(ap-southeast-3)" },
  { value: "ap-southeast-5", name: "Jakarta(ap-southeast-5)" },
  { value: "ap-northeast-1", name: "Tokyo(ap-northeast-1)" },
  { value: "eu-west-1", name: "London(eu-west-1)" },
  { value: "eu-central-1", name: "Frankfurt(eu-central-1)" },
  { value: "us-west-1", name: "Silicon Valley(us-west-1)" },
  { value: "us-east-1", name: "Virginia(us-east-1)" },
  { value: "me-east-1", name: "Dubai(me-east-1)" },
  { value: "ap-south-1", name: "Mumbai(ap-south-1)" },
];

export const TENCENT_REGION_LIST = [
  { name: "Beijing(ap-beijing)", value: "ap-beijing" },
  { name: "Nanjing(ap-nanjing)", value: "ap-nanjing" },
  { name: "Shanghai(ap-shanghai)", value: "ap-shanghai" },
  { name: "Guangzhou(ap-guangzhou)", value: "ap-guangzhou" },
  { name: "Chengdu(ap-chengdu)", value: "ap-chengdu" },
  { name: "Chongqing(ap-chongqing)", value: "ap-chongqing" },
  { name: "Hong Kong(ap-hongkong)", value: "ap-hongkong" },
  { name: "Singapore(ap-singapore)", value: "ap-singapore" },
  { name: "Mumbai(ap-mumbai)", value: "ap-mumbai" },
  { name: "Seoul(ap-seoul)", value: "ap-seoul" },
  { name: "Bangkok(ap-bangkok)", value: "ap-bangkok" },
  { name: "Tokyo(ap-tokyo)", value: "ap-tokyo" },
  { name: "Silicon Valley(na-siliconvalley)", value: "na-siliconvalley" },
  { name: "Virginia(na-ashburn)", value: "na-ashburn" },
  { name: "Toronto(na-toronto)", value: "na-toronto" },
  { name: "Frankfurt(eu-frankfurt)", value: "eu-frankfurt" },
  { name: "Moscow(eu-moscowcom)", value: "eu-moscowcom" },
];

export const QINIU_REGION_LIST = [
  { name: "East China(cn-east-1)", value: "cn-east-1" },
  { name: "North China(cn-north-1)", value: "cn-north-1" },
  { name: "South China(cn-south-1)", value: "cn-south-1" },
  { name: "North America(us-north-1)", value: "us-north-1" },
  { name: "South East Asia(ap-southeast-1)", value: "ap-southeast-1" },
];

export const getRegionListBySourceType = (sourceType: string) => {
  let regionList: any = [];
  switch (sourceType) {
    case EnumSourceType.S3:
      regionList = AWS_REGION_LIST;
      break;
    case EnumSourceType.AliOSS:
      regionList = ALICLOUD_REGION_LIST;
      break;
    case EnumSourceType.TencentCOS:
      regionList = TENCENT_REGION_LIST;
      break;
    case EnumSourceType.Qiniu:
      regionList = QINIU_REGION_LIST;
      break;
    case EnumSourceType.GoogleGCS:
      regionList = [];
      break;
    default:
      regionList = [];
      break;
  }
  return regionList;
};

export const getRegionNameById = (id: string): any => {
  if (id && id !== "-") {
    return AWS_REGION_LIST.find((item) => item.value === id)?.name;
  } else {
    return "-";
  }
};

export const YES_NO_LIST = [
  { name: "Yes", value: YES_NO.YES },
  { name: "No", value: YES_NO.NO },
];

export const LAMBDA_OPTIONS = [
  { name: 128, value: 128 },
  { name: 256, value: 256 },
  { name: 512, value: 512 },
  { name: 1024, value: 1024 },
];

export const MUTLTIPART_OPTIONS = [
  { name: 10, value: 10 },
  { name: 15, value: 15 },
  { name: 20, value: 20 },
  { name: 50, value: 50 },
  { name: 100, value: 100 },
];

export const CHUNKSIZE_OPTIONS = [
  { name: 5, value: 5 },
  { name: 10, value: 10 },
];

export const MAXTHREADS_OPTIONS = [
  { name: 5, value: 5 },
  { name: 10, value: 10 },
  { name: 20, value: 20 },
  { name: 50, value: 50 },
];

export const ECS_FARGATE_MEMORY_LIST = [
  { name: "8G", value: "8192" },
  { name: "12G", value: "12288" },
  { name: "16G", value: "16384" },
  { name: "20G", value: "20480" },
  { name: "24G", value: "24576" },
  { name: "30G", value: "30720" },
];

export const CRON_TYPE_LIST = [
  { name: "One Time Transfer", value: CRON_TYPE.ONE_TIME },
  { name: "Fixed Rate", value: CRON_TYPE.FIXED_RATE },
  { name: "Cron Expression", value: CRON_TYPE.CRON_EXPRESS },
];

export const CRON_UNIT_LIST = [
  { name: "Days", value: CRON_FIX_UNIT.DAYS },
  { name: "Minutes", value: CRON_FIX_UNIT.MINUTES },
  { name: "Hours", value: CRON_FIX_UNIT.HOURS },
];

export const OBJECT_ACL_LIST = [
  { name: "bucket-owner-full-control", value: "bucket-owner-full-control" },
  { name: "private", value: "private" },
  { name: "public-read", value: "public-read" },
  { name: "public-read-write", value: "public-read-write" },
  { name: "authenticated-read", value: "authenticated-read" },
  { name: "aws-exec-read", value: "aws-exec-read" },
  { name: "bucket-owner-read", value: "bucket-owner-read" },
  // { name: "bucket-owner-full-control", value: "bucket-owner-full-control" },
];

export const S3_STORAGE_CLASS_OPTIONS = [
  { name: "Standard", value: S3_STORAGE_CLASS_TYPE.STANDARD },
  { name: "Standard-IA", value: S3_STORAGE_CLASS_TYPE.STANDARD_IA },
  { name: "One Zone-IA", value: S3_STORAGE_CLASS_TYPE.ONEZONE_IA },
  {
    name: "Intelligent-Tiering",
    value: S3_STORAGE_CLASS_TYPE.INTELLIGENT_TIERING,
  },
];

export const SOURCE_TYPE_OPTIONS_LAMBDA = [
  { name: "creation.sourceType.amazonS3Name", value: EnumSourceType.S3 },
  { name: "creation.sourceType.aliyunOSSName", value: EnumSourceType.AliOSS },
  { name: "creation.sourceType.qiniuKodoName", value: EnumSourceType.Qiniu },
  {
    name: "creation.sourceType.tencentCOSName",
    value: EnumSourceType.TencentCOS,
  },
  {
    name: "creation.sourceType.googleGCSName",
    value: EnumSourceType.GoogleGCS,
  },
];

export const SOURCE_TYPE_OPTIONS_EC2 = [
  { name: "creation.sourceType.amazonS3Name", value: EnumSourceType.S3 },
  { name: "creation.sourceType.aliyunOSSName", value: EnumSourceType.AliOSS },
  { name: "creation.sourceType.qiniuKodoName", value: EnumSourceType.Qiniu },
  {
    name: "creation.sourceType.tencentCOSName",
    value: EnumSourceType.TencentCOS,
  },
  {
    name: "creation.sourceType.compatibleName",
    value: EnumSourceType.S3_COMPATIBLE,
  },
];

export const S3_EVENT_OPTIONS = [
  { name: "No", value: S3_EVENT_TYPE.NO },
  { name: "Create Only", value: S3_EVENT_TYPE.CREATE_ONLY },
  { name: "Delete Only", value: S3_EVENT_TYPE.DELETE_ONLY },
  { name: "Create and Delete", value: S3_EVENT_TYPE.CREATE_AND_DELETE },
];

export const S3_EVENT_OPTIONS_EC2 = [
  { name: "No", value: S3_EVENT_TYPE.NO },
  { name: "Create", value: S3_EVENT_TYPE.CREATE_ONLY_EC2 },
  { name: "Create and Delete", value: S3_EVENT_TYPE.CREATE_AND_DELETE_EC2 },
];

// Clone task useless property
export const CREATE_USE_LESS_PROPERTY = [
  "id",
  "createdAt",
  "executionArn",
  "progress",
  "progressInfo",
  "stackId",
  "stackStatus",
  "stackStatusReason",
  "stoppedAt",
  "templateUrl",
  "__typename",
];

// export const fixedEncodeURIComponent = (str: string) => {
//   return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
//     return "%" + c.charCodeAt(0).toString(16);
//   });
// };

export const urlIsValid = (url: string): boolean => {
  const REG =
    /https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,}/;
  return REG.test(url);
};

export const emailIsValid = (email: string): boolean => {
  const re = /\w[-\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}/;
  return re.test(String(email).toLowerCase());
};

export const bucketNameIsValid = (bucketName: string): boolean => {
  // return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const REG1 = bucketName && /^[a-z\d.-]*$/.test(bucketName);
  const REG2 = bucketName && /^[a-z\d]/.test(bucketName);
  const REG3 = bucketName && !/-$/.test(bucketName);
  const REG4 = bucketName && !/\.+\./.test(bucketName);
  const REG5 = bucketName && !/-+\.$/.test(bucketName);
  const REG6 =
    bucketName &&
    !/^(?:(?:^|\.)(?:2(?:5[0-5]|[0-4]\d)|1?\d?\d)){4}$/.test(bucketName);
  const REG7 = bucketName && bucketName.length >= 3 && bucketName.length <= 63;

  console.info(
    "REG1 && REG2 && REG3 && REG4 && REG5 && REG6 && REG7:",
    REG1,
    REG2,
    REG3,
    REG4,
    REG5,
    REG6,
    REG7
  );

  if (REG1 && REG2 && REG3 && REG4 && REG5 && REG6 && REG7) {
    return true;
  }
  return false;
};
