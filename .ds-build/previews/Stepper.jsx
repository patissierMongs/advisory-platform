import React from "react";
import { Stepper, Card } from "./ds";

export const meta = { group: "Navigation", width: 680, height: 130, subtitle: "numbered flow with connectors" };

export default function Preview() {
  const steps = [
    { label: "PDF 업로드" },
    { label: "CVE 추출·조회" },
    { label: "자산 매칭" },
    { label: "발송 검토" },
  ];
  return (
    <div className="ads-root" style={{ padding: 24 }}>
      <Card padding="16px 22px">
        <Stepper steps={steps} current={1} />
      </Card>
    </div>
  );
}
