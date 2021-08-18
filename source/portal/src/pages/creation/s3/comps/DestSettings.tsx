import React, { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useDispatch, useMappedState } from "redux-react-hook";

import ArrowRightSharpIcon from "@material-ui/icons/ArrowRightSharp";
import ArrowDropDownSharpIcon from "@material-ui/icons/ArrowDropDownSharp";

// DRH Comp
import DrhInput from "common/comp/form/DrhInput";
import DrhSelect from "common/comp/form/DrhSelect";
import DrhCredential from "common/comp/form/DrhCredential";
import DrhRegion from "common/comp/form/DrhRegion";
import DescLink from "common/comp/DescLink";
import { EnumSpanType } from "common/InfoBar";

import {
  IRegionType,
  S3_STORAGE_CLASS_TYPE,
  S3_STORAGE_CLASS_OPTIONS,
  YES_NO,
  YES_NO_LIST,
  AWS_REGION_LIST,
  DEST_OBJECT_ACL_LINK,
  OBJECT_ACL_LIST,
} from "assets/config/const";

import { ACTION_TYPE, S3_ENGINE_TYPE } from "assets/types/index";

import { IState } from "store/Store";
const mapState = (state: IState) => ({
  tmpTaskInfo: state.tmpTaskInfo,
});

interface DestPropType {
  engineType: string;
  destShowBucketRequiredError: boolean;
  destShowBucketValidError: boolean;
  destShowRegionRequiredError: boolean;
  destShowPrefixFormatError: boolean;
}

const DestSettings: React.FC<DestPropType> = (props) => {
  const { t } = useTranslation();
  const { tmpTaskInfo } = useMappedState(mapState);
  const dispatch = useDispatch();
  const {
    engineType,
    destShowBucketRequiredError,
    destShowBucketValidError,
    destShowRegionRequiredError,
    destShowPrefixFormatError,
  } = props;
  // Refs
  const destBucketRef = useRef<any>(null);
  const destRegionRef = useRef<any>(null);

  const destInAccountClass = "form-items";

  const [professionShow, setProfessionShow] = useState(false);

  const [showDestCredential, setShowDestCredential] = useState(false);
  const [showDestRegion, setShowDestRegion] = useState(false);
  const [showDestInAccount, setShowDestInAccount] = useState(true);

  const [destInAccount, setDestInAccount] = useState<string>(
    tmpTaskInfo.parametersObj?.destInAccount || YES_NO.YES
  );

  const [destBucketRequiredError, setDestBucketRequiredError] = useState(false);
  const [destBucketFormatError, setDestBucketFormatError] = useState(false);
  const [destRegionReqiredError, setDestRegionReqiredError] = useState(false);

  const [destPrefixFormatError, setDestPrefixFormatError] = useState(false);

  const [destBucketName, setDestBucketName] = useState(
    tmpTaskInfo.parametersObj?.destBucketName || ""
  );

  const [destBucketPrefix, setDestBucketPrefix] = useState(
    tmpTaskInfo.parametersObj?.destBucketPrefix
      ? decodeURIComponent(tmpTaskInfo.parametersObj.destBucketPrefix)
      : ""
  );

  const [destStorageClass, setDestStorageClass] = useState(
    tmpTaskInfo.parametersObj?.destStorageClass ||
      S3_STORAGE_CLASS_TYPE.STANDARD
  );

  const [destAcl, setDestAcl] = useState(
    tmpTaskInfo.parametersObj?.destAcl || "bucket-owner-full-control"
  );

  const [destCredentialsParameterStore, setDestCredentialsParameterStore] =
    useState(tmpTaskInfo.parametersObj?.destCredentialsParameterStore || "");

  const [destRegionObj, setDestRegionObj] = useState<IRegionType | null>(
    tmpTaskInfo.parametersObj?.destRegionObj || null
  );

  // Show Error
  useEffect(() => {
    console.info("destShowBucketRequiredError:", destShowBucketRequiredError);
    setDestBucketRequiredError(destShowBucketRequiredError);
    setDestBucketFormatError(destShowBucketValidError);
    if (destShowBucketRequiredError || destShowBucketValidError) {
      destBucketRef?.current?.scrollIntoView();
    }
  }, [destShowBucketRequiredError, destShowBucketValidError]);

  // Show destPrefix format Error
  useEffect(() => {
    if (destShowPrefixFormatError) {
      setProfessionShow(true);
    }
    setDestPrefixFormatError(destShowPrefixFormatError);
  }, [destShowPrefixFormatError]);

  // Show destRegionRequiredError
  useEffect(() => {
    console.info("destRegionRequiredError:", destShowRegionRequiredError);
    if (destShowRegionRequiredError) {
      setDestRegionReqiredError(destShowRegionRequiredError);
    }
    if (destShowRegionRequiredError) {
      destBucketRef?.current?.scrollIntoView();
    }
  }, [destShowRegionRequiredError]);

  useEffect(() => {
    updateTmpTaskInfo("destInAccount", destInAccount);
    if (destInAccount === YES_NO.NO) {
      setShowDestCredential(true);
      setShowDestRegion(true);
    } else {
      setShowDestCredential(false);
      setShowDestRegion(false);
    }
    if (engineType === S3_ENGINE_TYPE.EC2) {
      // If engine type is EC2 always show region
      setShowDestRegion(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destInAccount]);

  const updateTmpTaskInfo = (key: string, value: any) => {
    const param: any = { ...tmpTaskInfo.parametersObj };
    param[key] = value;
    dispatch({
      type: ACTION_TYPE.UPDATE_TASK_INFO,
      taskInfo: Object.assign(tmpTaskInfo, {
        parametersObj: param,
      }),
    });
  };

  // Monitor Data Change
  useEffect(() => {
    updateTmpTaskInfo("destBucketName", destBucketName);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destBucketName]);

  useEffect(() => {
    updateTmpTaskInfo("destBucketPrefix", encodeURIComponent(destBucketPrefix));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destBucketPrefix]);

  useEffect(() => {
    updateTmpTaskInfo("destStorageClass", destStorageClass);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destStorageClass]);

  useEffect(() => {
    updateTmpTaskInfo("destAcl", destAcl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destAcl]);

  useEffect(() => {
    updateTmpTaskInfo(
      "destCredentialsParameterStore",
      destCredentialsParameterStore
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destCredentialsParameterStore]);

  useEffect(() => {
    updateTmpTaskInfo("destRegionObj", destRegionObj);
    updateTmpTaskInfo("destRegionName", destRegionObj?.value || "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [destRegionObj]);

  // Monitor SourceInAccount When Lambda Engine
  useEffect(() => {
    const srcInAccount =
      tmpTaskInfo?.parametersObj?.sourceInAccount === YES_NO.YES ? true : false;
    if (engineType === S3_ENGINE_TYPE.LAMBDA) {
      // engine type is lambda
      // show dest credential and dest region when src in account is true, else hide
      if (srcInAccount) {
        setShowDestInAccount(false);
        setShowDestCredential(true);
        setShowDestRegion(true);
      } else {
        // Set Destination is Not In Account
        setDestInAccount(YES_NO.NO);
        // Show Dest In Account Option, Credential and Region
        setShowDestInAccount(true);
        setShowDestCredential(false);
        setShowDestRegion(false);
      }
    }
    if (engineType === S3_ENGINE_TYPE.EC2) {
      // engine type is EC2
      // show dest credential and dest region when src in account is true, else hide
      if (srcInAccount) {
        setShowDestInAccount(false);
        // Set Destination is Not In Account
        setDestInAccount(YES_NO.NO);
      } else {
        setShowDestInAccount(true);
      }
      // Set Dest Region Show
      setShowDestRegion(true);
    }
  }, [engineType, tmpTaskInfo?.parametersObj?.sourceInAccount]);

  useEffect(() => {
    setDestBucketRequiredError(false);
    setDestBucketFormatError(false);
    setDestRegionReqiredError(false);
    setDestPrefixFormatError(false);
  }, [tmpTaskInfo?.parametersObj?.sourceType]);

  return (
    <div className="box-shadow card-list">
      <div className="option">
        <div className="option-title">
          {t("creation.step2.settings.dest.title")}
        </div>
        <div className="option-content">
          <div className="form-items" ref={destBucketRef}>
            <DrhInput
              optionTitle={t("creation.step2.settings.dest.bucketName")}
              optionDesc={t("creation.step2.settings.dest.bucketDesc")}
              onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                setDestBucketRequiredError(false);
                setDestBucketFormatError(false);
                setDestBucketName(event.target.value);
              }}
              inputName="destBucketName"
              inputValue={destBucketName}
              placeholder="bucket-name"
              showRequiredError={destBucketRequiredError}
              requiredErrorMsg={t("tips.error.destBucketRequired")}
              showFormatError={destBucketFormatError}
              formatErrorMsg={t("tips.error.destBucketNameInvalid")}
            />
          </div>

          <div className={destInAccountClass}>
            {engineType === S3_ENGINE_TYPE.EC2 && showDestInAccount && (
              <DrhSelect
                onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                  setDestInAccount(event.target.value);
                }}
                optionTitle={t("creation.step2.settings.dest.destInAccount")}
                optionDesc={t("creation.step2.settings.dest.destInAccountDesc")}
                selectValue={destInAccount}
                optionList={YES_NO_LIST}
              />
            )}
          </div>

          {showDestCredential && (
            <div className="form-items">
              <DrhCredential
                credentialValue={destCredentialsParameterStore}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                  setDestCredentialsParameterStore(event.target.value);
                }}
              />
            </div>
          )}

          {showDestRegion && (
            <div className="form-items" ref={destRegionRef}>
              <DrhRegion
                regionValue={destRegionObj}
                optionList={AWS_REGION_LIST}
                optionTitle={t("creation.step2.settings.dest.destRegionName")}
                optionDesc={t(
                  "creation.step2.settings.dest.destRegionNameDesc"
                )}
                showRequiredError={destRegionReqiredError}
                requiredErrorMsg={t("tips.error.destRegionRequired")}
                onChange={(
                  event: React.ChangeEvent<HTMLInputElement>,
                  data: IRegionType
                ) => {
                  setDestRegionReqiredError(false);
                  setDestRegionObj(data);
                }}
              />
            </div>
          )}

          <div className="profession-title padding-left">
            {!professionShow && (
              <ArrowRightSharpIcon
                onClick={() => {
                  setProfessionShow(true);
                }}
                className="option-profession-icon"
                fontSize="large"
              />
            )}
            {professionShow && (
              <ArrowDropDownSharpIcon
                onClick={() => {
                  setProfessionShow(false);
                }}
                className="option-profession-icon"
                fontSize="large"
              />
            )}
            {t("creation.step2.settings.advance.professionTitle")}
          </div>

          {professionShow && (
            <div>
              <div className="form-items">
                <DrhInput
                  showInfo={true}
                  infoType={EnumSpanType.S3_BUCKET_DEST_PREFIX}
                  optionTitle={t("creation.step2.settings.dest.objectPrefix")}
                  optionDesc={t("creation.step2.settings.dest.prefixDesc")}
                  onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                    setDestPrefixFormatError(false);
                    setDestBucketPrefix(event.target.value);
                  }}
                  showFormatError={destPrefixFormatError}
                  formatErrorMsg={t("tips.error.destPrefixInvalid")}
                  isOptional={true}
                  inputName="destBucketPrefix"
                  inputValue={destBucketPrefix}
                  placeholder="prefix"
                />
              </div>

              <div className="form-items">
                <DrhSelect
                  optionTitle={t("creation.step2.settings.dest.storageClass")}
                  optionDesc={t(
                    "creation.step2.settings.dest.storageClassDesc"
                  )}
                  onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                    setDestStorageClass(event.target.value);
                  }}
                  selectValue={destStorageClass}
                  optionList={S3_STORAGE_CLASS_OPTIONS}
                />
              </div>

              {engineType === S3_ENGINE_TYPE.EC2 && (
                <div className="form-items">
                  <DrhSelect
                    onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                      setDestAcl(event.target.value);
                    }}
                    optionTitle={t("creation.step2.settings.source.objectACL")}
                    optionDesc=""
                    optionDescHtml={[
                      t("creation.step2.settings.source.objectACLDesc1"),
                      <DescLink
                        title={t(
                          "creation.step2.settings.source.objectACLDesc2"
                        )}
                        link={DEST_OBJECT_ACL_LINK}
                      />,
                      t("creation.step2.settings.source.objectACLDesc3"),
                    ]}
                    selectValue={destAcl}
                    optionList={OBJECT_ACL_LIST}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DestSettings;
