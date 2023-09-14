// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import React, { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useDispatch } from "redux-react-hook";
import classNames from "classnames";
import { useTranslation } from "react-i18next";

import Breadcrumbs from "@material-ui/core/Breadcrumbs";
import NavigateNextIcon from "@material-ui/icons/NavigateNext";
import Typography from "@material-ui/core/Typography";
import MLink from "@material-ui/core/Link";

import LeftMenu from "common/LeftMenu";
import InfoBar from "common/InfoBar";

import Bottom from "common/Bottom";
import Step from "./comps/Step";
import NextButton from "common/comp/PrimaryButton";
import TextButton from "common/comp/TextButton";
import StepOneS3Tips from "./s3/StepOneS3Tips";
import StepOneECRTips from "./ecr/StepOneECRTips";

import "./Creation.scss";

import {
  TYPE_LIST,
  EnumTaskType,
  ACTION_TYPE,
  S3_ENGINE_TYPE,
} from "assets/types/index";

const StepOne: React.FC = () => {
  const { t } = useTranslation();
  const { engine, type } = useParams();

  const [taskType, setTaskType] = useState(type);
  const [editionType, setEditionType] = useState(engine);

  const dispatch = useDispatch();
  const updateTmpTaskInfo = React.useCallback(() => {
    let tmpTaskType = taskType;
    if (editionType === S3_ENGINE_TYPE.EC2) {
      tmpTaskType = EnumTaskType.S3_EC2;
      dispatch({
        type: ACTION_TYPE.UPDATE_TASK_INFO,
        taskInfo: { type: tmpTaskType },
      });
    }
    if (editionType === S3_ENGINE_TYPE.LAMBDA) {
      tmpTaskType = EnumTaskType.S3;
      dispatch({
        type: ACTION_TYPE.UPDATE_TASK_INFO,
        taskInfo: { type: tmpTaskType },
      });
    }
    if (taskType === EnumTaskType.ECR) {
      tmpTaskType = EnumTaskType.ECR;
      dispatch({
        type: ACTION_TYPE.UPDATE_ECR_TASK_INFO,
        taskInfo: { type: tmpTaskType },
      });
    }
  }, [dispatch, editionType, taskType]);

  // TaskType 变化时变化tmptaskinfo
  useEffect(() => {
    updateTmpTaskInfo();
  }, [taskType, updateTmpTaskInfo]);

  const navigate = useNavigate();
  const goToHomePage = () => {
    navigate("/");
  };
  const goToStepTwo = () => {
    let toPath = `/create/step2/${taskType}`;
    if (taskType === EnumTaskType.S3) {
      toPath = `/create/step2/${taskType}/${editionType}`;
    }
    navigate(toPath);
  };

  const changeDataType = (event: any) => {
    console.info("taskType:", taskType);
    console.info("EnumTaskType.S3:", EnumTaskType.S3);
    console.info("editionType:", editionType);
    if (!editionType) {
      setEditionType(S3_ENGINE_TYPE.EC2);
    }
    if (event.target.value === EnumTaskType.S3) {
      window.history.pushState(
        {},
        "",
        `/create/step1/${event.target.value}/${editionType}`
      );
    } else {
      window.history.pushState({}, "", "/create/step1/" + event.target.value);
    }

    setTaskType(event.target.value);
  };

  useEffect(() => {
    if (taskType === EnumTaskType.S3) {
      window.history.pushState(
        {},
        "",
        `/create/step1/${taskType}/${editionType}`
      );
    }
  }, [taskType, editionType]);

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
              <MLink color="inherit" href="/">
                {t("breadCrumb.home")}
              </MLink>
              <Typography color="textPrimary">
                {t("breadCrumb.create")}
              </Typography>
            </Breadcrumbs>
          </div>
          <div className="creation-content">
            <div className="creation-step">
              <Step curStep="one" />
            </div>
            <div className="creation-info">
              <div className="creation-title">
                {t("creation.step1.engineType")}
              </div>
              <div className="box-shadow">
                <div className="option">
                  <div className="option-title">
                    {t("creation.step1.engineOptions")}
                  </div>
                  <div className="option-list">
                    {TYPE_LIST.map((item) => {
                      const optionClass = classNames({
                        "option-list-item": true,
                        "hand-point": !item.disabled,
                        active: taskType === item.value,
                      });
                      return (
                        <div key={item.value} className={optionClass}>
                          <label>
                            <div>
                              <input
                                disabled={item.disabled}
                                onChange={changeDataType}
                                value={item.value}
                                checked={taskType === item.value}
                                name="option-type"
                                type="radio"
                              />
                              &nbsp;{item.name}
                            </div>
                            <div className="imgs">
                              <img alt={item.name} src={item.imageSrc} />
                            </div>
                          </label>
                        </div>
                      );
                    })}
                  </div>
                  <div>{taskType === EnumTaskType.S3 && <StepOneS3Tips />}</div>
                  <div>
                    {taskType === EnumTaskType.ECR && <StepOneECRTips />}
                  </div>
                </div>
              </div>
              <div className="buttons">
                <TextButton onClick={goToHomePage}>
                  {t("btn.cancel")}
                </TextButton>
                <NextButton onClick={goToStepTwo}>{t("btn.next")}</NextButton>
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

export default StepOne;
