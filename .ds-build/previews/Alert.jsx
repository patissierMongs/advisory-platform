import React from "react";
import { Alert, Button } from "./ds";

export const meta = { group: "Feedback", width: 620, height: 260, subtitle: "info / success / warning / danger" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 24, display: "flex", flexDirection: "column", gap: 12 }}>
      <Alert tone="info" title="자산대장 자동 매칭 완료 —">
        CVE DB에서 조회된 제품·버전과 일치하는 자산을 찾았습니다.
      </Alert>
      <Alert
        tone="warning"
        title="DB 미등록 CVE 3건 —"
        action={<Button size="sm" variant="warning">CVE 데이터베이스 →</Button>}
      >
        로컬 CVE DB에 해당 코드가 없습니다. 최신 피드 파일을 반입하면 자동으로 조회됩니다.
      </Alert>
      <Alert tone="danger" title="발송 직전 최종 검토 —">
        부서별 메시지와 채널을 확인한 뒤 발송하세요. 발송 후에는 회수할 수 없습니다.
      </Alert>
    </div>
  );
}
