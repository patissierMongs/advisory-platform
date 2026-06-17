import { Modal, Button } from "advisory-platform-ds";


export default function Preview() {
  const pdfIcon = (
    <div style={{ width: 30, height: 36, borderRadius: 5, background: "var(--ds-color-danger-tint)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
      <span style={{ fontSize: 8, fontWeight: 800, color: "var(--ds-color-danger)" }}>PDF</span>
    </div>
  );
  return (
    <div className="ads-root" style={{ position: "relative", height: 460, background: "var(--ds-color-bg)" }}>
      <Modal
        open
        title="2026년 상반기 보안권고문"
        subtitle="NIS-2026-0142"
        icon={pdfIcon}
        footer={<Button variant="primary" size="sm">닫기</Button>}
      >
        <div style={{ background: "#fff", border: "1px solid #e6eaf0", borderRadius: 8, padding: "26px 30px", fontSize: 12.5, lineHeight: 1.95, color: "var(--ds-color-text-body)", boxShadow: "var(--ds-shadow-card)" }}>
          <div style={{ fontWeight: 700, marginBottom: 8 }}>보안권고문 — 긴급 취약점 조치 요청</div>
          <div>1. 대상 제품: Microsoft Outlook, Windows TCP/IP</div>
          <div>2. 관련 CVE: CVE-2024-21413, CVE-2024-38063</div>
          <div>3. 조치 기한: 2026. 6. 26.</div>
        </div>
      </Modal>
    </div>
  );
}
