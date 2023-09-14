// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useState } from "react";
import { useDispatch, useMappedState } from "redux-react-hook";
import { useNavigate, Link } from "react-router-dom";
import classNames from "classnames";
import { ThreeDots } from "react-loader-spinner";
import { useTranslation } from "react-i18next";
import Swal from "sweetalert2";

import Loading from "common/Loading";
import Breadcrumbs from "@material-ui/core/Breadcrumbs";
import NavigateNextIcon from "@material-ui/icons/NavigateNext";
import Typography from "@material-ui/core/Typography";
import MLink from "@material-ui/core/Link";
import RefreshIcon from "@material-ui/icons/Refresh";
import Snackbar, { SnackbarOrigin } from "@material-ui/core/Snackbar";
import Dialog from "@material-ui/core/Dialog";
import DialogActions from "@material-ui/core/DialogActions";
import DialogContent from "@material-ui/core/DialogContent";
import DialogContentText from "@material-ui/core/DialogContentText";
import DialogTitle from "@material-ui/core/DialogTitle";
import MuiAlert, { AlertProps } from "@material-ui/lab/Alert";
import { withStyles } from "@material-ui/core/styles";
import Menu, { MenuProps } from "@material-ui/core/Menu";
import MenuItem from "@material-ui/core/MenuItem";
import ListItemText from "@material-ui/core/ListItemText";
import ArrowDropDownIcon from "@material-ui/icons/ArrowDropDown";
import { listTasksV2 } from "graphql/queries";
import { stopTask } from "graphql/mutations";

import { IState } from "store/Store";

import LeftMenu from "common/LeftMenu";
import Bottom from "common/Bottom";
import InfoBar from "common/InfoBar";

import TaskStatusComp from "common/comp/TaskStatusComp";
import NormalButton from "common/comp/NormalButton";
import PrimaryButton from "common/comp/PrimaryButton";
import StopButtonLoading from "common/comp/PrimaryButtonLoading";

import "./TaskList.scss";

import STATUS_OK from "@material-ui/icons/CheckCircleOutline";

import {
  EnumTaskStatus,
  EnumTaskType,
  ECREnumSourceType,
  ACTION_TYPE,
  S3_ENGINE_TYPE,
  EnumSourceType,
} from "assets/types/index";
import {
  YES_NO,
  AWS_REGION_LIST,
  getRegionListBySourceType,
  S3SourcePrefixType,
  CRON_TYPE_LIST_WITH_ONE_TIME,
} from "assets/config/const";
import { Pagination } from "@material-ui/lab";
import {
  appSyncRequestMutation,
  appSyncRequestQuery,
} from "assets/utils/request";
import { formatLocalTime } from "assets/utils/utils";
import { ScheduleType } from "API";
import DTHSelect from "common/comp/select/select";

const StyledMenu = withStyles({
  paper: {
    border: "1px solid #d3d4d5",
  },
})((props: MenuProps) => (
  <Menu
    style={{ borderRadius: 0 }}
    elevation={0}
    getContentAnchorEl={null}
    anchorOrigin={{
      vertical: "bottom",
      horizontal: "left",
    }}
    transformOrigin={{
      vertical: "top",
      horizontal: "left",
    }}
    {...props}
  />
));

const StyledMenuItem = withStyles(() => ({
  root: {
    width: 130,
    "& .MuiTypography-body1": {
      fontSize: 14,
    },
  },
}))(MenuItem);

export interface State extends SnackbarOrigin {
  open: boolean;
}

function Alert(props: AlertProps) {
  return <MuiAlert elevation={6} variant="filled" {...props} />;
}

const mapState = (state: IState) => ({
  createTaskFlag: state.createTaskFlag,
});

const PAGE_SIZE = 20;

const List: React.FC = () => {
  const { t } = useTranslation();
  const dispatch = useDispatch();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleCloseMenu = () => {
    setAnchorEl(null);
  };

  const { createTaskFlag } = useMappedState(mapState);

  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(true);
  const [isStopLoading, setIsStopLoading] = useState(false);
  const [curPage, setCurPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [taskListData, setTaskListData] = useState<any>([]);
  const [curSelectTask, setCurSelectTask] = useState<any>(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [open, setOpen] = useState(false);
  const [messageOpen, setMessageOpen] = useState(false);
  const [filterStatus, setFilterStatus] = useState("");

  const getTaskList = async () => {
    try {
      setIsLoading(true);
      const resData: any = await appSyncRequestQuery(listTasksV2, {
        page: curPage,
        count: PAGE_SIZE,
        progress: filterStatus ? filterStatus : undefined,
      });
      console.info("resData:", resData);
      setIsLoading(false);
      if (
        resData &&
        resData.data &&
        resData.data.listTasksV2 &&
        resData.data.listTasksV2.items
      ) {
        const orderedList = resData.data.listTasksV2.items;
        setTaskListData(orderedList);
        setTotalCount(resData.data.listTasksV2.total);
      }
    } catch (error) {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    dispatch({ type: ACTION_TYPE.CLOSE_SIDE_BAR });
  }, []);

  useEffect(() => {
    getTaskList();
  }, [curPage]);

  useEffect(() => {
    if (curPage !== 1) {
      setCurPage(1);
    } else {
      getTaskList();
    }
  }, [filterStatus]);

  // Hide Create Flag in 3 seconds
  useEffect(() => {
    window.setTimeout(() => {
      dispatch({
        type: ACTION_TYPE.HIDE_CREATE_TASK_FLAG,
      });
    }, 4000);
  }, [dispatch]);

  const goToStepOne = () => {
    dispatch({ type: ACTION_TYPE.CLOSE_SIDE_BAR });
    navigate("/create/step1/S3/ec2");
  };

  const goToDetail = () => {
    let toPath = `/task/detail/${curSelectTask.type}/${curSelectTask.id}`;
    if (
      curSelectTask.type === EnumTaskType.S3 ||
      curSelectTask.type === EnumTaskType.S3_EC2
    ) {
      toPath = `/task/detail/s3/${curSelectTask.type}/${curSelectTask.id}`;
    }
    navigate(toPath);
  };

  async function stopTaskFunc(taskId: string) {
    try {
      setIsStopLoading(true);
      const stopResData = await appSyncRequestMutation(stopTask, {
        id: taskId,
      });
      console.info("stopResData:", stopResData);
      refreshData();
      setIsStopLoading(false);
      setOpen(false);
    } catch (error: any) {
      const errorMsg = error?.errors?.[0]?.message?.toString() || "Error";
      setIsStopLoading(false);
      setMessageOpen(true);
      setErrorMessage(errorMsg);
      showErrorMessage();
      Swal.fire("Oops...", error.message, "error");
    }
  }

  const stopCurTask = () => {
    setAnchorEl(null);
    setOpen(true);
  };

  const getIsSrcInAccount = (list: any) => {
    let tmpJobTypeObj: any = {};
    list.forEach((element: any) => {
      if (element.ParameterKey === "jobType") {
        tmpJobTypeObj = element;
      }
    });
    if (tmpJobTypeObj.ParameterValue === "PUT") {
      return true;
    } else {
      return false;
    }
  };

  const cloneCurTask = () => {
    setAnchorEl(null);
    console.info("curSelectTask:", curSelectTask);
    const tmpTaskInfo = curSelectTask;
    tmpTaskInfo.parametersObj = {};
    // when need to clone task type is S3 (Lambda Version)
    const isSrcInAccount = getIsSrcInAccount(curSelectTask.parameters);
    if (curSelectTask.type === EnumTaskType.S3) {
      // Clone Lambda Version Task
      if (curSelectTask.parameters && curSelectTask.parameters.length > 0) {
        curSelectTask.parameters.forEach((element: any) => {
          // Set All Properties
          tmpTaskInfo.parametersObj[element.ParameterKey] =
            element.ParameterValue;

          if (element.ParameterKey === "jobType") {
            if (element.ParameterValue === "PUT") {
              tmpTaskInfo.parametersObj.sourceInAccount = YES_NO.YES;
              tmpTaskInfo.parametersObj.destInAccount = YES_NO.NO;
            } else {
              tmpTaskInfo.parametersObj.sourceInAccount = YES_NO.NO;
              tmpTaskInfo.parametersObj.destInAccount = YES_NO.YES;
            }
          }
          // Set Credential
          if (element.ParameterKey === "credentialsParameterStore") {
            if (isSrcInAccount) {
              tmpTaskInfo.parametersObj.destCredentialsParameterStore =
                element.ParameterValue;
            } else {
              tmpTaskInfo.parametersObj.srcCredentialsParameterStore =
                element.ParameterValue;
            }
          }
          // Set Region
          if (element.ParameterKey === "regionName") {
            const sourceTypeName = getParamsValueByName(
              "sourceType",
              curSelectTask.parameters
            );
            const regionName = getParamsValueByName(
              "regionName",
              curSelectTask.parameters
            );
            const REGION_LIST = getRegionListBySourceType(sourceTypeName);
            const regionObj = REGION_LIST.find(
              (item: any) => item.value === regionName
            );
            if (isSrcInAccount) {
              // Set Dest Region Obj
              tmpTaskInfo.parametersObj.destRegionObj = regionObj;
            } else {
              // Set Source Region Obj
              tmpTaskInfo.parametersObj.srcRegionObj = regionObj;
            }
          }

          // Set Description
          tmpTaskInfo.parametersObj.description =
            tmpTaskInfo?.description || "";
        });
      }
    }

    // when need to clone task type is S3 (EC2 Version)
    if (curSelectTask.type === EnumTaskType.S3_EC2) {
      // Clone EC2 Version Task
      console.info("curSelectTask.parameters:", curSelectTask.parameters);
      if (curSelectTask.parameters && curSelectTask.parameters.length > 0) {
        // Set Default src prefix type
        tmpTaskInfo.parametersObj.srcPrefixType = S3SourcePrefixType.FullBucket;

        curSelectTask.parameters.forEach((element: any) => {
          // Set All Properties
          tmpTaskInfo.parametersObj[element.ParameterKey] =
            element.ParameterValue;

          if (element.ParameterKey === "srcType") {
            // set src type to Amazon_S3_Compatibale when endpointUrl not empty
            const srcEndpoint = getParamsValueByName(
              "srcEndpoint",
              curSelectTask.parameters
            );
            if (srcEndpoint) {
              tmpTaskInfo.parametersObj.sourceType =
                EnumSourceType.S3_COMPATIBLE;
            } else {
              tmpTaskInfo.parametersObj.sourceType = element.ParameterValue;
            }
          }
          if (element.ParameterKey === "srcBucket") {
            tmpTaskInfo.parametersObj.srcBucketName = element.ParameterValue;
          }
          if (element.ParameterKey === "srcPrefix") {
            tmpTaskInfo.parametersObj.srcBucketPrefix = element.ParameterValue;
          }
          if (element.ParameterKey === "srcEvent") {
            tmpTaskInfo.parametersObj.enableS3Event = element.ParameterValue;
          }

          // Set Source Region
          // Set Region
          if (element.ParameterKey === "srcRegion") {
            const sourceTypeName = getParamsValueByName(
              "srcType",
              curSelectTask.parameters
            );
            const srcRegionName = getParamsValueByName(
              "srcRegion",
              curSelectTask.parameters
            );
            const REGION_LIST = getRegionListBySourceType(sourceTypeName);
            const srcRegionObj = REGION_LIST.find(
              (item: any) => item.value === srcRegionName
            );
            tmpTaskInfo.parametersObj.srcRegionObj = srcRegionObj;
          }

          if (element.ParameterKey === "srcInCurrentAccount") {
            tmpTaskInfo.parametersObj.sourceInAccount =
              element.ParameterValue === "true" ? YES_NO.YES : YES_NO.NO;
          }

          if (element.ParameterKey === "isPayerRequest") {
            tmpTaskInfo.parametersObj.isPayerRequest =
              element.ParameterValue === "true" ? YES_NO.YES : YES_NO.NO;
          }

          if (element.ParameterKey === "srcCredentials") {
            tmpTaskInfo.parametersObj.srcCredentialsParameterStore =
              element.ParameterValue;
          }

          if (element.ParameterKey === "destBucket") {
            tmpTaskInfo.parametersObj.destBucketName = element.ParameterValue;
          }

          if (element.ParameterKey === "destPrefix") {
            tmpTaskInfo.parametersObj.destBucketPrefix = element.ParameterValue;
          }

          // Set Dest Region
          // Set Region
          if (element.ParameterKey === "destRegion") {
            const destRegionName = getParamsValueByName(
              "destRegion",
              curSelectTask.parameters
            );
            const REGION_LIST = AWS_REGION_LIST;
            const destRegionObj = REGION_LIST.find(
              (item: any) => item.value === destRegionName
            );
            tmpTaskInfo.parametersObj.destRegionObj = destRegionObj;
          }

          if (element.ParameterKey === "destInCurrentAccount") {
            tmpTaskInfo.parametersObj.destInAccount =
              element.ParameterValue === "true" ? YES_NO.YES : YES_NO.NO;
          }

          if (element.ParameterKey === "destCredentials") {
            tmpTaskInfo.parametersObj.destCredentialsParameterStore =
              element.ParameterValue;
          }

          if (element.ParameterKey === "includeMetadata") {
            tmpTaskInfo.parametersObj.includeMetadata =
              element.ParameterValue === "true" ? YES_NO.YES : YES_NO.NO;
          }

          // set srcPrefixType = MultiplePrefix when srcPrefixsListFile has value
          if (element.ParameterKey === "srcPrefixsListFile") {
            if (element.ParameterValue) {
              tmpTaskInfo.parametersObj.srcPrefixType =
                S3SourcePrefixType.MultiplePrefix;
            }
          }

          // set srcPrefixType = SinglePrefix when srcPrefixsListFile has value
          if (element.ParameterKey === "srcPrefix") {
            if (element.ParameterValue) {
              tmpTaskInfo.parametersObj.srcPrefixType =
                S3SourcePrefixType.SinglePrefix;
            }
          }

          // Set Skip Comparsion
          if (element.ParameterKey === "srcSkipCompare") {
            tmpTaskInfo.parametersObj.srcSkipCompare =
              element.ParameterValue === "true" ? YES_NO.NO : YES_NO.YES;
          }

          // Set Description
          tmpTaskInfo.parametersObj.description =
            tmpTaskInfo?.description || "";

          // Set scheduleType
          tmpTaskInfo.parametersObj.scheduleType =
            tmpTaskInfo?.scheduleType || ScheduleType.FIXED_RATE;
        });
      }
    }

    if (curSelectTask.type === EnumTaskType.ECR) {
      if (curSelectTask.parameters && curSelectTask.parameters.length > 0) {
        curSelectTask.parameters.forEach((element: any) => {
          // Set All Properties
          tmpTaskInfo.parametersObj[element.ParameterKey] =
            element.ParameterValue;

          if (element.ParameterKey === "srcAccountId") {
            if (element.ParameterValue === "") {
              tmpTaskInfo.parametersObj.sourceInAccount = YES_NO.YES;
            } else {
              tmpTaskInfo.parametersObj.sourceInAccount = YES_NO.NO;
            }
          }
          if (element.ParameterKey === "destAccountId") {
            if (element.ParameterValue === "") {
              tmpTaskInfo.parametersObj.destInAccount = YES_NO.YES;
            } else {
              tmpTaskInfo.parametersObj.destInAccount = YES_NO.NO;
            }
          }
          if (element.ParameterKey === "srcRegion") {
            const srcRegionName = AWS_REGION_LIST.find(
              (ele) => ele.value === element.ParameterValue
            )?.name;
            if (srcRegionName) {
              tmpTaskInfo.parametersObj.srcRegionObj = {
                name: srcRegionName,
                value: element.ParameterValue,
              };
            }
          }
          if (element.ParameterKey === "destRegion") {
            const destRegionName = AWS_REGION_LIST.find(
              (ele) => ele.value === element.ParameterValue
            )?.name;
            if (destRegionName) {
              tmpTaskInfo.parametersObj.destRegionObj = {
                name: destRegionName,
                value: element.ParameterValue,
              };
            }
          }
          // Set Description
          tmpTaskInfo.parametersObj.description =
            tmpTaskInfo?.description || "";
        });
      }
    }
    dispatch({
      type:
        curSelectTask.type === EnumTaskType.ECR
          ? ACTION_TYPE.UPDATE_ECR_TASK_INFO
          : ACTION_TYPE.UPDATE_TASK_INFO,
      taskInfo: tmpTaskInfo,
    });
    // Redirect to Create S3 Task Step two
    let toPath = `/create/step2/${curSelectTask.type}`;
    if (curSelectTask.type === EnumTaskType.S3) {
      toPath = `/create/step2/s3/${S3_ENGINE_TYPE.EC2}`;
    }
    if (curSelectTask.type === EnumTaskType.S3_EC2) {
      toPath = `/create/step2/s3/${S3_ENGINE_TYPE.EC2}`;
    }
    navigate(toPath);
  };

  const changeRadioSelect = (event: any) => {
    console.info("event:", event);
  };

  const clickTaskInfo = (taskInfo: any) => {
    setCurSelectTask(taskInfo);
  };

  const refreshData = () => {
    setCurSelectTask(null);
    if (curPage === 1) {
      getTaskList();
    } else {
      setCurPage(1);
    }
  };

  const [tipsOpen, setTipsOpen] = useState(false);
  const showErrorMessage = () => {
    setTipsOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const confirmStopTask = () => {
    stopTaskFunc(curSelectTask.id);
  };

  const handleCloseMessage = () => {
    setMessageOpen(false);
  };

  const handlePageChange = (event: any, value: number) => {
    console.info("event:", event);
    console.info("value:", value);
    setCurPage(value);
  };

  const getParamsValueByName = (name: string, paramList: any) => {
    return (
      paramList.find((item: any) => item.ParameterKey === name)
        ?.ParameterValue || ""
    );
  };

  const buildTaskSource = (item: any) => {
    if (item.type === EnumTaskType.S3_EC2) {
      if (getParamsValueByName("srcEndpoint", item.parameters)) {
        return (
          EnumSourceType.S3_COMPATIBLE +
          "/" +
          getParamsValueByName("srcBucket", item.parameters)
        );
      }
      return (
        getParamsValueByName("srcType", item.parameters) +
        "/" +
        getParamsValueByName("srcBucket", item.parameters)
      );
    }
    if (item.type === EnumTaskType.S3) {
      return (
        getParamsValueByName("sourceType", item.parameters) +
        "/" +
        getParamsValueByName("srcBucketName", item.parameters)
      );
    }
    if (item.type === EnumTaskType.ECR) {
      if (
        getParamsValueByName("sourceType", item.parameters) ===
        ECREnumSourceType.PUBLIC
      ) {
        return getParamsValueByName("sourceType", item.parameters);
      }
      if (
        getParamsValueByName("sourceType", item.parameters) ===
        ECREnumSourceType.ECR
      ) {
        return getParamsValueByName("srcRegion", item.parameters);
      }
    }
    return "";
  };

  const buildTaskDestination = (item: any) => {
    if (item.type === EnumTaskType.S3_EC2) {
      return getParamsValueByName("destBucket", item.parameters);
    }
    if (item.type === EnumTaskType.S3) {
      return getParamsValueByName("destBucketName", item.parameters);
    }
    if (item.type === EnumTaskType.ECR) {
      return getParamsValueByName("destRegion", item.parameters);
    }
    return "";
  };

  const buildTaskType = (item: any) => {
    if (item.type === EnumTaskType.S3_EC2) {
      return "S3 Plugin (Graviton2)";
    }
    if (item.type === EnumTaskType.S3) {
      return "S3 Plugin (Lambda)";
    }
    if (item.type === EnumTaskType.ECR) {
      return "ECR Plugin";
    }
    return "";
  };

  const buildScheduleType = (item: any) => {
    if (item.type === EnumTaskType.S3_EC2) {
      return CRON_TYPE_LIST_WITH_ONE_TIME.find(
        (element) => element.value === item.scheduleType
      )?.name;
    }
    if (item.type === EnumTaskType.ECR) {
      return "Fixed Rate";
    }
  };

  return (
    <div className="drh-page">
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">
          {t("taskList.stopTask")}
        </DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {t("taskList.tips.confimStop")}{" "}
            <b>{curSelectTask && curSelectTask.id}</b>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <div className="padding-15">
            <NormalButton onClick={handleClose} color="primary">
              {t("btn.cancel")}
            </NormalButton>
            {isStopLoading ? (
              <StopButtonLoading disabled={true}>
                <ThreeDots color="#ffffff" height={10} />
              </StopButtonLoading>
            ) : (
              <PrimaryButton
                onClick={confirmStopTask}
                color="primary"
                autoFocus
              >
                {t("btn.confirm")}
              </PrimaryButton>
            )}
          </div>
        </DialogActions>
      </Dialog>
      {tipsOpen && (
        <Snackbar
          anchorOrigin={{ horizontal: "center", vertical: "top" }}
          open={messageOpen}
          onClose={handleCloseMessage}
          autoHideDuration={1500}
        >
          <Alert severity="error">{errorMessage}</Alert>
        </Snackbar>
      )}
      <LeftMenu />
      <div className="right">
        <InfoBar />
        {createTaskFlag && (
          <div className="task-status">
            <div className="content">
              <STATUS_OK className="icon" />
              {t("taskList.tips.successMsg")}
            </div>
          </div>
        )}

        <div className="padding-right-40">
          <div className="page-breadcrumb">
            <Breadcrumbs
              separator={<NavigateNextIcon fontSize="small" />}
              aria-label="breadcrumb"
            >
              <MLink color="inherit" href="/">
                {t("breadCrumb.home")}
              </MLink>
              <Typography color="textPrimary">
                {t("breadCrumb.tasks")}
              </Typography>
            </Breadcrumbs>
          </div>
          <div className="table-data">
            <div className="box-shadow">
              <div className="title">
                <div className="options">
                  <div className="task-count">
                    {t("taskList.title")}
                    {/* <span className="info">(10)</span> */}
                  </div>
                  <div className="buttons">
                    <NormalButton onClick={refreshData}>
                      <RefreshIcon width="10" />
                    </NormalButton>

                    <DTHSelect
                      isI18N
                      allowEmpty
                      width={110}
                      value={filterStatus}
                      optionList={[
                        {
                          name: "taskList.activated",
                          value: "",
                        },
                        {
                          name: "taskList.deleted",
                          value: "STOPPED",
                        },
                      ]}
                      onChange={(e) => {
                        setFilterStatus(e.target.value);
                      }}
                    />

                    <NormalButton
                      disabled={curSelectTask === null}
                      aria-controls="customized-menu"
                      onClick={handleClick}
                      style={{ height: 37, display: "flex" }}
                    >
                      {t("btn.taskAction")}
                      <span
                        style={{
                          marginLeft: 3,
                          marginBottom: -8,
                          marginRight: -10,
                        }}
                      >
                        <ArrowDropDownIcon fontSize="medium" />
                      </span>
                    </NormalButton>
                    <NormalButton
                      disabled={
                        curSelectTask === null ||
                        curSelectTask.progress === EnumTaskStatus.STOPPING ||
                        curSelectTask.progress === EnumTaskStatus.STOPPED
                      }
                      onClick={stopCurTask}
                    >
                      {t("btn.deleteTask")}
                    </NormalButton>
                    <StyledMenu
                      id="customized-menu"
                      anchorEl={anchorEl}
                      keepMounted
                      open={Boolean(anchorEl)}
                      onClose={handleCloseMenu}
                    >
                      <StyledMenuItem>
                        <ListItemText
                          onClick={goToDetail}
                          primary={t("btn.viewDetail")}
                        />
                      </StyledMenuItem>
                      <StyledMenuItem>
                        <ListItemText
                          onClick={cloneCurTask}
                          primary={t("btn.cloneTask")}
                        />
                      </StyledMenuItem>
                    </StyledMenu>

                    <PrimaryButton onClick={goToStepOne}>
                      {t("btn.createTask")}
                    </PrimaryButton>
                  </div>
                </div>
                <div className="search">
                  <div className="search-input">
                    {/* <input type="text" placeholder="Find resources" /> */}
                  </div>
                  <div className="pagination">
                    <div>
                      <Pagination
                        count={Math.ceil(totalCount / PAGE_SIZE)}
                        page={curPage}
                        onChange={handlePageChange}
                        size="small"
                      />
                    </div>
                  </div>
                  <div className="setting-icon">
                    {/* <img alt="settings" width="20" src={SETTING_ICON} /> */}
                  </div>
                </div>
              </div>
              <div className="data-list">
                {isLoading ? (
                  <Loading />
                ) : (
                  <div className="table-wrap">
                    <div className="table-header">
                      <div className="table-item check-item">&nbsp;</div>
                      <div className="table-item item-id">
                        {t("taskList.table.taskId")}
                      </div>
                      <div className="table-item header-item">
                        {t("taskList.table.source")}
                      </div>
                      <div className="table-item header-item">
                        {t("taskList.table.destination")}
                      </div>
                      <div className="table-item header-item">
                        {t("taskList.table.engineType")}
                      </div>
                      <div className="table-item header-item">
                        {t("taskList.table.scheduleType")}
                      </div>
                      <div className="table-item header-item">
                        {t("taskList.table.status")}
                      </div>
                      <div className="table-item create-time">
                        {t("taskList.table.createdTime")}
                      </div>
                    </div>
                    {taskListData.map((element: any) => {
                      const rowClass = classNames({
                        "table-row": true,
                        active:
                          curSelectTask && curSelectTask.id === element.id,
                      });
                      return (
                        <div
                          onClick={() => {
                            clickTaskInfo(element);
                          }}
                          data-uuid={element.id}
                          key={element.id}
                          className={rowClass}
                        >
                          <div className="table-item check-item center">
                            <input
                              onChange={(event) => {
                                changeRadioSelect(event);
                              }}
                              checked={
                                curSelectTask
                                  ? curSelectTask.id === element.id
                                  : false
                              }
                              type="radio"
                              name="taskList"
                            />
                          </div>
                          <div className="table-item item-id">
                            {(element.type === EnumTaskType.S3 ||
                              element.type === EnumTaskType.S3_EC2) && (
                              <Link
                                to={`/task/detail/s3/${element.type}/${element.id}`}
                              >
                                {element.stackName || element.id}
                              </Link>
                            )}
                            {element.type !== EnumTaskType.S3 &&
                              element.type !== EnumTaskType.S3_EC2 && (
                                <Link
                                  to={`/task/detail/${element.type}/${element.id}`}
                                >
                                  {element.stackName || element.id}
                                </Link>
                              )}
                          </div>
                          <div
                            className="table-item body-item"
                            title={buildTaskSource(element)}
                          >
                            {buildTaskSource(element)}
                          </div>
                          <div
                            className="table-item body-item"
                            title={buildTaskDestination(element)}
                          >
                            {buildTaskDestination(element)}
                          </div>
                          <div
                            className="table-item body-item"
                            title={buildTaskType(element)}
                          >
                            {buildTaskType(element)}
                          </div>
                          <div className="table-item body-item">
                            {buildScheduleType(element)}
                          </div>
                          <div className="table-item body-item task-list-status">
                            <TaskStatusComp
                              showLink
                              taskId={element.id}
                              cfnId={element.stackName}
                              progress={element.progress}
                            />
                          </div>
                          <div className="table-item create-time">
                            {formatLocalTime(element.createdAt)}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
        <div className="bottom">
          <Bottom />
        </div>
      </div>
    </div>
  );
};

export default List;
