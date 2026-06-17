import { StatCard } from "advisory-platform-ds";


export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 24, display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
      <StatCard label="추출 CVE" value="12" unit="건" />
      <StatCard label="DB 조회완료" value="9" unit="건" valueColor="var(--ds-color-primary)" />
      <StatCard label="DB 미등록" value="3" unit="건" valueColor="var(--ds-color-warning)" />
    </div>
  );
}
