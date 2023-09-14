// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import React from "react";
import { useTranslation } from "react-i18next";

import "./info.scss";

interface Page {
  name: string | undefined;
}

const S3BucketDestPrefix: React.FC<Page> = () => {
  const { t } = useTranslation();
  return (
    <div className="credential">
      <div className="top-tips">{t("comps.s3BucketDestPrefix.tips1")}</div>

      <div className="top-tips">
        {t("comps.s3BucketDestPrefix.tips2")}
        <code>{t("comps.s3BucketDestPrefix.codeTips0")}</code>
        {t("comps.s3BucketDestPrefix.tips2_1")}
        <code>{t("comps.s3BucketDestPrefix.codeTips1")}</code>
        {t("comps.s3BucketDestPrefix.tips3")}
        <code>{t("comps.s3BucketDestPrefix.codeTips2")}</code>
      </div>

      <div className="top-tips">
        {t("comps.s3BucketDestPrefix.tips4")}
        <code>{t("comps.s3BucketDestPrefix.codeTips3")}</code>
        {t("comps.s3BucketDestPrefix.tips5")}
      </div>
    </div>
  );
};

export default S3BucketDestPrefix;
