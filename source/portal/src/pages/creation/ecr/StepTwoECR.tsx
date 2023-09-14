// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch, useMappedState } from "redux-react-hook";
import { useTranslation } from "react-i18next";
import classNames from "classnames";

import Breadcrumbs from "@material-ui/core/Breadcrumbs";
import NavigateNextIcon from "@material-ui/icons/NavigateNext";
import Typography from "@material-ui/core/Typography";
import MLink from "@material-ui/core/Link";

import InfoBar from "common/InfoBar";
import LeftMenu from "common/LeftMenu";
import Bottom from "common/Bottom";
import Step from "../comps/Step";
import NextButton from "common/comp/PrimaryButton";
import NormalButton from "common/comp/NormalButton";
import TextButton from "common/comp/TextButton";

// DRH Comp
import DrhInput from "common/comp/form/DrhInput";
import DrhSelect from "common/comp/form/DrhSelect";
import DrhCredential from "common/comp/form/DrhCredential";
import DrhRegion from "common/comp/form/DrhRegion";

import { IState } from "store/Store";

import {
  AWS_REGION_LIST,
  YES_NO_LIST,
  IRegionType,
  YES_NO,
  CUR_SUPPORT_LANGS,
  emailIsValid,
} from "assets/config/const";
import {
  ECR_SOURCE_TYPE,
  DOCKER_IMAGE_TYPE,
  ECREnumSourceType,
  EnumDockerImageType,
  EnumTaskType,
} from "assets/types/index";

import "../Creation.scss";

const mapState = (state: IState) => ({
  tmpECRTaskInfo: state.tmpECRTaskInfo,
});

const MAX_LENGTH = 4096;

const ACCOUNT_REGEX = /^\d{12}$/;

const defaultTxtValue =
  "ubuntu:14.04,\namazon-linux:latest,\nmysql,\npublic.ecr.aws/amaonlinux/amazonlinux:latest";
const defaultTxtValueSourceECR =
  "my-ecr-repo:ALL_TAGS,\nmy-oci-repo,\nubuntu:14.04,\namazon-linux:latest,\nmysql";

const StepTwoECR: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const { tmpECRTaskInfo } = useMappedState(mapState);
  const { t, i18n } = useTranslation();

  const [titleStr, setTitleStr] = useState("en_name");
  const [descStr, setDescStr] = useState("en_desc");

  const [sourceType, setSourceType] = useState(
    tmpECRTaskInfo?.parametersObj?.sourceType || ECREnumSourceType.ECR
  );

  const [destRegionRequiredError, setDestRegionRequiredError] = useState(false);
  const [alramEmailRequireError, setAlramEmailRequireError] = useState(false);
  const [alarmEmailFormatError, setAlarmEmailFormatError] = useState(false);

  const [sourceRegionRequiredError, setSourceRegionRequiredError] =
    useState(false);
  const [sourceAccountRequiredError, setSourceAccountRequiredError] =
    useState(false);
  const [sourceAccountInvalidError, setSourceAccountInvalidError] =
    useState(false);

  const [destAccountRequiredError, setDestAccountRequiredError] =
    useState(false);
  const [destAccountInvalidError, setDestAccountInvalidError] = useState(false);

  const [classSourceRegion, setClassSourceRegion] = useState("form-items");
  const [classIsSourceInAccount, setClassIsSourceAccount] =
    useState("form-items");
  const [classSrcAccountId, setClassSrcAccountId] = useState("form-items");
  const [classSrcCredential, setClassSrcCredential] = useState("form-items");
  const [classDockerImage, setClassDockerImage] = useState("form-items");
  const [classImageList, setClassImageList] = useState("form-items");
  const [classDestAccountId, setClassDestAccountId] = useState("form-items");
  const [classDestCredential, setClassDestCredential] = useState("form-items");
  const [curLength, setCurLength] = useState(0);
  const [srcECRandSelectedImgs, setSrcECRandSelectedImgs] = useState(false);

  const [srcRegionObj, setSrcRegionObj] = useState<IRegionType | null>(
    tmpECRTaskInfo?.parametersObj?.srcRegionObj || null
  );
  const [sourceInAccount, setSourceInAccount] = useState<string>(
    tmpECRTaskInfo?.parametersObj?.sourceInAccount || YES_NO.NO
  );
  const [srcAccountId, setSrcAccountId] = useState(
    tmpECRTaskInfo?.parametersObj?.srcAccountId || ""
  );
  const [srcCredential, setSrcCredential] = useState(
    tmpECRTaskInfo?.parametersObj?.srcCredential || ""
  );
  const [srcList, setSrcList] = useState(
    tmpECRTaskInfo?.parametersObj?.srcList || EnumDockerImageType.ALL
  );
  const [srcImageList, setSrcImageList] = useState(
    tmpECRTaskInfo?.parametersObj?.srcImageList || ""
  );
  const [destRegionObj, setDestRegionObj] = useState<IRegionType | null>(
    tmpECRTaskInfo?.parametersObj?.destRegionObj || null
  );
  const [destInAccount, setDestInAccount] = useState<string>(
    tmpECRTaskInfo?.parametersObj?.destInAccount || YES_NO.NO
  );
  const [destAccountId, setDestAccountId] = useState(
    tmpECRTaskInfo?.parametersObj?.destAccountId || ""
  );
  const [destCredential, setDestCredential] = useState(
    tmpECRTaskInfo?.parametersObj?.destCredential || ""
  );
  const [destPrefix, setDestPrefix] = useState(
    tmpECRTaskInfo?.parametersObj?.destPrefix || ""
  );
  const [includeUntagged, setIncludeUntagged] = useState(
    tmpECRTaskInfo?.parametersObj?.includeUntagged ?? "true"
  );
  const [description, setDescription] = useState(
    tmpECRTaskInfo?.parametersObj?.description
      ? decodeURIComponent(tmpECRTaskInfo?.parametersObj?.description)
      : ""
  );
  const [alarmEmail, setAlarmEmail] = useState(
    tmpECRTaskInfo?.parametersObj?.alarmEmail || ""
  );

  useEffect(() => {
    if (CUR_SUPPORT_LANGS.indexOf(i18n.language) >= 0) {
      setTitleStr(i18n.language + "_name");
      setDescStr(i18n.language + "_desc");
    }
  }, [i18n.language]);

  // Redirect Step One if task type is null
  useEffect(() => {
    // if the taskInfo has no taskType, redirect to Step one
    // eslint-disable-next-line no-prototype-builtins
    if (!tmpECRTaskInfo?.hasOwnProperty("type")) {
      navigate("/create/step1/ECR");
    }
  }, [history, tmpECRTaskInfo]);

  const validateInput = () => {
    const paramsObj = tmpECRTaskInfo?.parametersObj;
    // Source Bucket Not Can Be Empty
    let errorCount = 0;

    if (paramsObj) {
      // if the source type is ECR
      if (paramsObj.sourceType === ECREnumSourceType.ECR) {
        // Check Source Region Required
        if (!paramsObj.srcRegion) {
          errorCount++;
          setSourceRegionRequiredError(true);
        }

        // Check Source Account ID Required
        if (
          paramsObj.sourceInAccount === YES_NO.NO &&
          !paramsObj.srcAccountId
        ) {
          errorCount++;
          setSourceAccountRequiredError(true);
        }

        // Check Source Account ID Valid
        if (
          paramsObj.sourceInAccount === YES_NO.NO &&
          paramsObj.srcAccountId &&
          !ACCOUNT_REGEX.test(paramsObj.srcAccountId)
        ) {
          errorCount++;
          setSourceAccountInvalidError(true);
        }
      }

      // Check Destination Account ID Required
      if (paramsObj.destInAccount === YES_NO.NO && !paramsObj.destAccountId) {
        errorCount++;
        setDestAccountRequiredError(true);
      }

      // Check Destination Account ID Valid
      if (
        paramsObj.destInAccount === YES_NO.NO &&
        paramsObj.destAccountId &&
        !ACCOUNT_REGEX.test(paramsObj.destAccountId)
      ) {
        errorCount++;
        setDestAccountInvalidError(true);
      }

      // Check Destination Region
      if (!paramsObj.destRegion) {
        errorCount++;
        setDestRegionRequiredError(true);
      }
      // Alarm Email Not Can Be Empty
      if (!paramsObj.alarmEmail || paramsObj.alarmEmail.trim() === "") {
        errorCount++;
        setAlramEmailRequireError(true);
      } else if (!emailIsValid(paramsObj.alarmEmail)) {
        // Alarm Email Not valid
        errorCount++;
        setAlarmEmailFormatError(true);
      }
    }

    if (errorCount > 0) {
      return false;
    }
    return true;
  };

  // Monitor Page Item Change
  useEffect(() => {
    if (sourceType === ECREnumSourceType.ECR) {
      setClassSourceRegion("form-items");
      setClassIsSourceAccount("form-items");
      setClassSrcAccountId("form-items");
      setClassSrcCredential("form-items");
      setClassDockerImage("form-items");
      if (sourceInAccount === YES_NO.YES) {
        setClassSrcAccountId("hidden");
        setClassSrcCredential("hidden");
      }
      if (sourceInAccount === YES_NO.NO) {
        setClassSrcAccountId("form-items");
        setClassSrcCredential("form-items");
      }
      if (srcList === EnumDockerImageType.ALL) {
        setClassImageList("hidden");
      }
      if (srcList === EnumDockerImageType.SELECTED) {
        setClassImageList("form-items");
        setSrcECRandSelectedImgs(true);
      } else {
        setSrcECRandSelectedImgs(false);
      }
    }
    if (sourceType === ECREnumSourceType.PUBLIC) {
      setSrcECRandSelectedImgs(false);
      setSrcList(EnumDockerImageType.SELECTED);
      setClassSourceRegion("hidden");
      setClassIsSourceAccount("hidden");
      setClassSrcAccountId("hidden");
      setClassSrcCredential("hidden");
      setClassDockerImage("hidden");
      setClassImageList("form-items");
    }
    if (destInAccount === YES_NO.YES) {
      setClassDestAccountId("hidden");
      setClassDestCredential("hidden");
    }
    if (destInAccount === YES_NO.NO) {
      setClassDestAccountId("form-items");
      setClassDestCredential("form-items");
    }
  }, [sourceType, sourceInAccount, destInAccount, srcList]);

  const changeSrcImageList = (event: any) => {
    setCurLength(event.target.value.length);
    if (event.target.value.length >= MAX_LENGTH) {
      setSrcImageList(event.target.value.substr(0, MAX_LENGTH - 1));
    } else {
      setSrcImageList(event.target.value);
    }
  };

  const goToHomePage = () => {
    navigate("/");
  };

  const goToStepOne = () => {
    navigate("/create/step1/ECR");
  };

  const goToStepThree = () => {
    if (validateInput()) {
      navigate("/create/step3/ECR");
    }
  };

  const updatetmpECRTaskInfo = (key: string, value: any) => {
    const param: any = { ...tmpECRTaskInfo?.parametersObj };
    param[key] = value;
    if (tmpECRTaskInfo) {
      dispatch({
        type: EnumTaskType.ECR,
        taskInfo: Object.assign(tmpECRTaskInfo, {
          parametersObj: param,
        }),
      });
    }
  };

  // Monitor Data Change

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("sourceType", sourceType);
  }, [sourceType]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("srcRegionObj", srcRegionObj);
    updatetmpECRTaskInfo("srcRegion", srcRegionObj?.value);
  }, [srcRegionObj]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("sourceInAccount", sourceInAccount);
  }, [sourceInAccount]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("srcAccountId", srcAccountId);
  }, [srcAccountId]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("srcCredential", srcCredential);
  }, [srcCredential]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("srcList", srcList);
  }, [srcList]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("srcImageList", srcImageList);
  }, [srcImageList]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("destRegionObj", destRegionObj);
    updatetmpECRTaskInfo("destRegion", destRegionObj?.value);
  }, [destRegionObj]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("destInAccount", destInAccount);
  }, [destInAccount]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("destCredential", destCredential);
  }, [destCredential]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("destAccountId", destAccountId);
  }, [destAccountId]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("destPrefix", destPrefix);
  }, [destPrefix]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("includeUntagged", includeUntagged);
  }, [includeUntagged]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("description", encodeURIComponent(description));
  }, [description]);

  useEffect(() => {
    // Update tmpECRTaskInfo
    updatetmpECRTaskInfo("alarmEmail", alarmEmail);
  }, [alarmEmail]);

  return (
    <div className="drh-page">
      <LeftMenu />
      <div className="right">
        <InfoBar page="ECR" />
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
              <Step curStep="two" />
            </div>
            <div className="creation-info">
              <div className="creation-title">
                {t("creation.step2ECR.taskDetail")}
              </div>
              <div className="box-shadow card-list">
                <div className="option">
                  <div className="option-title">
                    {t("creation.step2ECR.sourceType")}
                  </div>
                  <div className="option-content">
                    <div> {t("creation.step2ECR.selectContainerType")}</div>
                    <div className="select">
                      {ECR_SOURCE_TYPE.map((item: any) => {
                        const stClass = classNames({
                          "st-item": true,
                          active: sourceType === item.value,
                        });
                        return (
                          <div key={item.value} className={stClass}>
                            <label>
                              <div>
                                <input
                                  onChange={(event: any) => {
                                    setSourceType(event.target.value);
                                  }}
                                  value={item.value}
                                  checked={sourceType === item.value}
                                  name="option-type"
                                  type="radio"
                                />
                                {item[titleStr]}
                              </div>
                              <div className="desc">{item[descStr]}</div>
                            </label>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>

              <form>
                <div className="box-shadow card-list">
                  <div className="option">
                    <div className="option-title">
                      {t("creation.step2ECR.settings.source.title")}
                    </div>
                    <div className="option-content">
                      <div className={classSourceRegion}>
                        <DrhRegion
                          regionValue={srcRegionObj}
                          optionList={AWS_REGION_LIST}
                          optionTitle={t(
                            "creation.step2ECR.settings.source.sourceRegion"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.source.sourceRegionDesc"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>,
                            data: IRegionType
                          ) => {
                            setSourceRegionRequiredError(false);
                            setSrcRegionObj(data);
                          }}
                          showRequiredError={sourceRegionRequiredError}
                          requiredErrorMsg={t(
                            "creation.step2ECR.valid.srcRegionRequired"
                          )}
                        />
                      </div>

                      <div className={classIsSourceInAccount}>
                        <DrhSelect
                          isI18n={true}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setSourceInAccount(event.target.value);
                          }}
                          optionTitle={t(
                            "creation.step2ECR.settings.source.sourceInAccount"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.source.sourceInAccountDesc"
                          )}
                          selectValue={sourceInAccount}
                          optionList={YES_NO_LIST}
                        />
                      </div>

                      <div className={classSrcAccountId}>
                        <DrhInput
                          optionTitle={t(
                            "creation.step2ECR.settings.source.accountId"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.source.accountIdTips"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setSourceAccountRequiredError(false);
                            setSourceAccountInvalidError(false);
                            setSrcAccountId(event.target.value);
                          }}
                          inputType="number"
                          inputName="srcAccountId"
                          inputValue={srcAccountId}
                          placeholder="123456789012"
                          showRequiredError={sourceAccountRequiredError}
                          requiredErrorMsg={t(
                            "creation.step2ECR.valid.accountRequired"
                          )}
                          showFormatError={sourceAccountInvalidError}
                          formatErrorMsg={t(
                            "creation.step2ECR.valid.accountFormatInvalid"
                          )}
                        />
                      </div>

                      <div className={classSrcCredential}>
                        <DrhCredential
                          hideBucket={true}
                          credentialValue={srcCredential}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setSrcCredential(event.target.value);
                          }}
                        />
                      </div>

                      <div className={classDockerImage}>
                        <div className="title">
                          {t("creation.step2ECR.settings.source.dockerImages")}
                        </div>
                        <div className="desc">
                          {t(
                            "creation.step2ECR.settings.source.dockerImagesDesc"
                          )}
                        </div>
                        <div className="select">
                          {DOCKER_IMAGE_TYPE.map((item: any) => {
                            const stClass = classNames({
                              "st-item": true,
                              active: srcList === item.value,
                            });
                            return (
                              <div key={item.value} className={stClass}>
                                <label>
                                  <div>
                                    <input
                                      onChange={(event: any) => {
                                        setSrcList(event.target.value);
                                      }}
                                      value={item.value}
                                      checked={srcList === item.value}
                                      name="option-type"
                                      type="radio"
                                    />
                                    {item[titleStr]}
                                  </div>
                                  <div className="desc">{item[descStr]}</div>
                                </label>
                              </div>
                            );
                          })}
                        </div>
                        {tmpECRTaskInfo?.parametersObj?.sourceType ===
                          ECREnumSourceType.ECR &&
                          tmpECRTaskInfo?.parametersObj?.srcList ===
                            EnumDockerImageType.ALL && (
                            <div className="mt-10">
                              <label>
                                <input
                                  type="checkbox"
                                  checked={includeUntagged === "false"}
                                  onChange={(
                                    event: React.ChangeEvent<HTMLInputElement>
                                  ) => {
                                    setIncludeUntagged(
                                      event.target.checked ? "false" : "true"
                                    );
                                  }}
                                />{" "}
                                {t("creation.step2ECR.onlyTag")}
                              </label>
                            </div>
                          )}
                      </div>

                      <div className={classImageList}>
                        <div>
                          <div className="title">
                            {t("creation.step2ECR.settings.source.imageList")}
                          </div>
                          <div className="desc">
                            {t("creation.step2ECR.settings.source.image1")}
                            &lt;{t("creation.step2ECR.settings.source.image2")}
                            &gt;:&lt;
                            {t("creation.step2ECR.settings.source.image3")}&gt;,
                            {t("creation.step2ECR.settings.source.image4")}
                            {srcECRandSelectedImgs
                              ? t("creation.step2ECR.settings.source.image5")
                              : ""}
                          </div>
                          <div>
                            <textarea
                              className="option-textarea"
                              name="srcImageList"
                              value={srcImageList}
                              onChange={changeSrcImageList}
                              placeholder={
                                srcECRandSelectedImgs
                                  ? defaultTxtValueSourceECR
                                  : defaultTxtValue
                              }
                              rows={7}
                            ></textarea>
                            <div className="flex-center">
                              <div>
                                <label>
                                  <input
                                    type="checkbox"
                                    checked={includeUntagged === "false"}
                                    onChange={(
                                      event: React.ChangeEvent<HTMLInputElement>
                                    ) => {
                                      setIncludeUntagged(
                                        event.target.checked ? "false" : "true"
                                      );
                                    }}
                                  />{" "}
                                  {t("creation.step2ECR.onlyTag")}
                                </label>
                              </div>
                              <div className="max-tips">{`${curLength}/${MAX_LENGTH}`}</div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="box-shadow card-list">
                  <div className="option">
                    <div className="option-title">
                      {t("creation.step2ECR.settings.dest.title")}
                    </div>
                    <div className="option-content">
                      <div className="form-items">
                        <DrhRegion
                          regionValue={destRegionObj}
                          optionList={AWS_REGION_LIST}
                          optionTitle={t(
                            "creation.step2ECR.settings.dest.destinationRegion"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.dest.destinationRegionDesc"
                          )}
                          showRequiredError={destRegionRequiredError}
                          requiredErrorMsg={t(
                            "creation.step2ECR.settings.dest.regionRequired"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>,
                            data: IRegionType
                          ) => {
                            setDestRegionRequiredError(false);
                            setDestRegionObj(data);
                          }}
                        />
                      </div>

                      <div className="form-items">
                        <DrhSelect
                          isI18n={true}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setDestInAccount(event.target.value);
                          }}
                          optionTitle={t(
                            "creation.step2ECR.settings.dest.destInAccount"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.dest.destInAccountDesc"
                          )}
                          selectValue={destInAccount}
                          optionList={YES_NO_LIST}
                        />
                      </div>

                      <div className={classDestAccountId}>
                        <DrhInput
                          optionTitle={t(
                            "creation.step2ECR.settings.source.accountId"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.source.accountIdTips"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setDestAccountRequiredError(false);
                            setDestAccountInvalidError(false);
                            setDestAccountId(event.target.value);
                          }}
                          inputType="number"
                          inputName="destAccountId"
                          inputValue={destAccountId}
                          placeholder="123456789012"
                          showRequiredError={destAccountRequiredError}
                          requiredErrorMsg={t(
                            "creation.step2ECR.valid.accountRequired"
                          )}
                          showFormatError={destAccountInvalidError}
                          formatErrorMsg={t(
                            "creation.step2ECR.valid.accountFormatInvalid"
                          )}
                        />
                      </div>

                      <div className={classDestCredential}>
                        <DrhCredential
                          hideBucket={true}
                          credentialValue={destCredential}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setDestCredential(event.target.value);
                          }}
                        />
                      </div>

                      <div className="form-items">
                        <DrhInput
                          optionTitle={t(
                            "creation.step2ECR.settings.dest.prefix"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.dest.prefixDesc"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setDestPrefix(event.target.value);
                          }}
                          isOptional={true}
                          inputName="destPrefix"
                          inputValue={destPrefix}
                          placeholder="Prefix"
                        />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="box-shadow card-list">
                  <div className="option">
                    <div className="option-title">
                      {t("creation.step2ECR.settings.more.title")}
                    </div>
                    <div className="option-content">
                      <div className="form-items">
                        <DrhInput
                          optionTitle={t(
                            "creation.step2ECR.settings.more.description"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.more.descriptionDesc"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setDescription(event.target.value);
                          }}
                          isOptional={true}
                          inputName="description"
                          inputValue={description}
                          placeholder={t(
                            "creation.step2ECR.settings.more.description"
                          )}
                        />
                      </div>

                      <div className="form-items">
                        <DrhInput
                          optionTitle={t(
                            "creation.step2ECR.settings.more.email"
                          )}
                          optionDesc={t(
                            "creation.step2ECR.settings.more.emailDesc"
                          )}
                          onChange={(
                            event: React.ChangeEvent<HTMLInputElement>
                          ) => {
                            setAlramEmailRequireError(false);
                            setAlarmEmailFormatError(false);
                            setAlarmEmail(event.target.value);
                          }}
                          isOptional={true}
                          inputName="alarmEmail"
                          inputValue={alarmEmail}
                          placeholder="abc@example.com"
                          showRequiredError={alramEmailRequireError}
                          requiredErrorMsg={t("tips.error.emailRequired")}
                          showFormatError={alarmEmailFormatError}
                          formatErrorMsg={t("tips.error.emailValidate")}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="buttons">
                  <TextButton onClick={goToHomePage}>
                    {t("btn.cancel")}
                  </TextButton>
                  <NormalButton onClick={goToStepOne}>
                    {t("btn.prev")}
                  </NormalButton>
                  <NextButton onClick={goToStepThree}>
                    {t("btn.next")}
                  </NextButton>
                </div>
              </form>
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

export default StepTwoECR;
