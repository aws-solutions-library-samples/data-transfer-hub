import React, { useState, useEffect } from "react";
import { useHistory } from "react-router-dom";
import { useDispatch, useMappedState } from "redux-react-hook";
import Loader from "react-loader-spinner";
import { useTranslation } from "react-i18next";
import Swal from "sweetalert2";

import Breadcrumbs from "@material-ui/core/Breadcrumbs";
import NavigateNextIcon from "@material-ui/icons/NavigateNext";
import Typography from "@material-ui/core/Typography";
import MLink from "@material-ui/core/Link";

// import { API } from "aws-amplify";
import { createTask as createTaskMutaion } from "graphql/mutations";
import gql from "graphql-tag";
import ClientContext from "common/context/ClientContext";
import { IState } from "store/Store";

import InfoBar from "common/InfoBar";
import LeftMenu from "common/LeftMenu";
import Bottom from "common/Bottom";
import Step from "../comps/Step";
import CreateButtonLoading from "common/comp/PrimaryButtonLoading";
import NextButton from "common/comp/PrimaryButton";
import NormalButton from "common/comp/NormalButton";
import TextButton from "common/comp/TextButton";

// import IMG_STATUS from "assets/images/status.svg";

import "../Creation.scss";
import "react-loader-spinner/dist/loader/css/react-spinner-loader.css";
import {
  ECR_PARAMS_LIST_MAP,
  CUR_SUPPORT_LANGS,
  CREATE_USE_LESS_PROPERTY,
  getRegionNameById,
  DRH_CONFIG_JSON_NAME,
} from "assets/config/const";
import { ACTION_TYPE } from "assets/types";

const mapState = (state: IState) => ({
  tmpTaskInfo: state.tmpTaskInfo,
});

const JOB_TYPE_MAP: any = {
  PUT: "Source",
  GET: "Destination",
};

const StepThreeECR: React.FC = () => {
  const { t, i18n } = useTranslation();
  const [nameStr, setNameStr] = useState("en_name");
  const client: any = React.useContext(ClientContext);

  useEffect(() => {
    if (CUR_SUPPORT_LANGS.indexOf(i18n.language) >= 0) {
      setNameStr(i18n.language + "_name");
    }
  }, [i18n.language]);

  const { tmpTaskInfo } = useMappedState(mapState);
  const [paramsList, setParamList] = useState<any>([]);
  const [createTaskGQL, setCreateTaskGQL] = useState<any>();
  const [isCreating, setIsCreating] = useState(false);

  const dispatch = useDispatch();

  const history = useHistory();

  useEffect(() => {
    // if the taskInfo has no taskType, redirect to Step one
    if (!tmpTaskInfo.hasOwnProperty("type")) {
      const toPath = "/create/step1/ECR";
      history.push({
        pathname: toPath,
      });
    }
  }, [history, tmpTaskInfo]);

  const buildECRParams = (parametersObj: any) => {
    const taskParamArr: any = [];
    console.info("parametersObj:", parametersObj);
    if (!parametersObj) {
      return [];
    }

    taskParamArr.push({
      ParameterKey: "sourceType",
      ParameterValue: parametersObj.sourceType,
    });
    taskParamArr.push({
      ParameterKey: "srcRegion",
      ParameterValue: parametersObj.srcRegion || "",
    });
    taskParamArr.push({
      ParameterKey: "srcAccountId",
      ParameterValue: parametersObj.srcAccountId,
    });
    taskParamArr.push({
      ParameterKey: "srcList",
      ParameterValue: parametersObj.srcList,
    });
    taskParamArr.push({
      ParameterKey: "srcImageList",
      ParameterValue: parametersObj.srcImageList,
    });
    taskParamArr.push({
      ParameterKey: "srcCredential",
      ParameterValue: parametersObj.srcCredential,
    });
    taskParamArr.push({
      ParameterKey: "destAccountId",
      ParameterValue: parametersObj.destAccountId,
    });
    taskParamArr.push({
      ParameterKey: "destRegion",
      ParameterValue: parametersObj.destRegion || "",
    });
    taskParamArr.push({
      ParameterKey: "destCredential",
      ParameterValue: parametersObj.destCredential,
    });
    taskParamArr.push({
      ParameterKey: "destPrefix",
      ParameterValue: parametersObj.destPrefix,
    });

    taskParamArr.push({
      ParameterKey: "alarmEmail",
      ParameterValue: parametersObj.alarmEmail,
    });

    return taskParamArr;
  };

  // Build  Task  Info  Data
  useEffect(() => {
    const { parametersObj, ...createTaskInfo } = tmpTaskInfo;

    // Set Description
    if (createTaskInfo) {
      createTaskInfo.description = parametersObj?.description || "";
    }

    const taskParamArr: any = buildECRParams(parametersObj);

    setParamList(taskParamArr);

    // Add New Params to Creat Task
    const configJson: any = JSON.parse(
      localStorage.getItem(DRH_CONFIG_JSON_NAME) as string
    );
    const clusterData = configJson.taskCluster;
    for (const key in clusterData) {
      if (key === "ecsSubnets") {
        taskParamArr.push({
          ParameterKey: "ecsSubnetA",
          ParameterValue: clusterData[key][0],
        });
        taskParamArr.push({
          ParameterKey: "ecsSubnetB",
          ParameterValue: clusterData[key][1],
        });
      } else {
        taskParamArr.push({
          ParameterKey: key,
          ParameterValue: clusterData[key],
        });
      }
    }

    // Remove uesless property when clone task
    for (const key in createTaskInfo) {
      if (CREATE_USE_LESS_PROPERTY.indexOf(key) > -1) {
        delete createTaskInfo[key];
      }
    }
    createTaskInfo.parameters = taskParamArr;
    setCreateTaskGQL(createTaskInfo);
  }, [tmpTaskInfo]);

  async function createTask() {
    setIsCreating(true);
    try {
      console.info("createTaskGQL:", createTaskGQL);
      const createTask = gql(createTaskMutaion);
      const createTaskData: any = await client?.mutate({
        fetchPolicy: "no-cache",
        mutation: createTask,
        variables: { input: createTaskGQL },
      });
      console.info("createTaskData:", createTaskData);
      dispatch({
        type: ACTION_TYPE.SET_CREATE_TASK_FLAG,
      });
      // Redirect to task list page
      const toPath = "/task/list";
      history.push({
        pathname: toPath,
      });
    } catch (error: any) {
      setIsCreating(false);
      Swal.fire("Oops...", error.message, "error");
    }
  }

  const goToHomePage = () => {
    const toPath = "/";
    history.push({
      pathname: toPath,
    });
  };

  const goToStepTwo = () => {
    const toPath = "/create/step2/ECR";
    history.push({
      pathname: toPath,
    });
  };

  const goToTaskList = () => {
    createTask();
  };

  const buildParamValue = (key: string, value: string) => {
    if (key === "jobType") {
      return JOB_TYPE_MAP[key];
    } else if (key === "srcImageList") {
      const imageArr: Array<string> = value.split(",");
      if (imageArr.length > 3) {
        return `${imageArr[0]} and other ${imageArr.length - 1} images.`;
      }
      return value;
    } else if (key === "srcRegion") {
      return getRegionNameById(value);
    } else if (key === "destRegion") {
      return getRegionNameById(value);
    } else {
      return value || "-";
    }
  };

  return (
    <div className="drh-page">
      <LeftMenu />
      <div className="right">
        <InfoBar />
        <div className="padding-left-40">
          <div className="page-breadcrumb">
            <Breadcrumbs
              separator={<NavigateNextIcon fontSize="small" />}
              aria-label="breadcrumb"
            >
              <MLink color="inherit" href="/#/">
                {t("breadCrumb.home")}
              </MLink>
              <Typography color="textPrimary">
                {t("breadCrumb.create")}
              </Typography>
            </Breadcrumbs>
          </div>
          <div className="creation-content">
            <div className="creation-step">
              <Step curStep="three" />
            </div>
            <div className="creation-info">
              <div className="creation-title">
                {t("creation.step3.reviewTitle")}
              </div>
              <div className="creation-title">
                {t("creation.step3.step1Title")}
              </div>
              <div className="box-shadow card-list">
                <div className="option">
                  <div className="option-title">
                    {t("creation.step3.step1Engine")}{" "}
                  </div>
                  <div className="option-content">
                    <div className="step3-title">
                      {t("creation.step3.step1EngineSubEngine")}
                    </div>
                    <div className="step3-desc">
                      {t("creation.step3.step1EngineSubEngineECRDesc")}
                    </div>
                  </div>
                </div>
              </div>

              <div className="creation-title">
                {t("creation.step3.step2Detail")}
              </div>
              <div className="box-shadow card-list">
                <div className="option">
                  <div className="option-title">
                    {t("creation.step3.step2TaskParams")}{" "}
                    <span>({paramsList.length - 4})</span>
                  </div>
                  <div className="option-content padding0">
                    <div className="table-wrap">
                      <div>
                        <div className="preview-row preview-header">
                          <div className="table-th key">
                            {t("creation.step3.step2Params")}
                          </div>
                          <div className="table-th value">
                            {t("creation.step3.step2Value")}
                          </div>
                        </div>
                        {paramsList.map((element: any, index: any) => {
                          return (
                            ECR_PARAMS_LIST_MAP[element.ParameterKey] && (
                              <div
                                className="preview-row preview-data"
                                key={index}
                              >
                                <div className="table-td key">
                                  {ECR_PARAMS_LIST_MAP[element.ParameterKey] &&
                                    ECR_PARAMS_LIST_MAP[element.ParameterKey][
                                      nameStr
                                    ]}
                                </div>
                                <div className="table-td value">
                                  {buildParamValue(
                                    element.ParameterKey,
                                    element.ParameterValue
                                  )}
                                </div>
                              </div>
                            )
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="buttons">
                <TextButton onClick={goToHomePage}>
                  {t("btn.cancel")}
                </TextButton>
                <NormalButton onClick={goToStepTwo}>
                  {t("btn.prev")}
                </NormalButton>
                {isCreating ? (
                  <CreateButtonLoading disabled={true}>
                    <Loader type="ThreeDots" color="#ffffff" height={10} />
                  </CreateButtonLoading>
                ) : (
                  <NextButton onClick={goToTaskList}>
                    {t("btn.createTask")}
                  </NextButton>
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

export default StepThreeECR;
