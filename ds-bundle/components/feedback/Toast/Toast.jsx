import { Toast, Button } from "advisory-platform-ds";


const okIcon = <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="var(--ds-color-primary)" strokeWidth="1.6" /><path d="M8.5 12l2.4 2.4 4.6-4.8" stroke="var(--ds-color-primary)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>;
const warnIcon = <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 3 2 20h20L12 3Z" stroke="var(--ds-color-warning)" strokeWidth="1.6" strokeLinejoin="round" /><path d="M12 10v4m0 3h.01" stroke="var(--ds-color-warning)" strokeWidth="1.8" strokeLinecap="round" /></svg>;

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 24, display: "flex", flexDirection: "column", gap: 16, background: "var(--ds-color-bg)" }}>
      <Toast inline tone="primary" icon={okIcon} title="발송 완료" onClose={() => {}}>
        4개 부서에 권고문이 발송되었습니다. 발송이력에 기록됩니다.
      </Toast>
      <Toast
        inline
        tone="warning"
        icon={warnIcon}
        title="권고문 재확인 필요"
        actions={
          <>
            <Button size="sm" variant="warning">예, 다시 읽기</Button>
            <Button size="sm" variant="secondary">아니오</Button>
          </>
        }
      >
        새 CVE가 추가되었습니다. PDF를 다시 분석할까요?
      </Toast>
    </div>
  );
}
