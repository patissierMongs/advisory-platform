import { ProgressBar, Card } from "advisory-platform-ds";


export default function Preview() {
  const rows = [
    { dept: "재무팀", pct: 92, color: "var(--ds-color-primary)" },
    { dept: "인사팀", pct: 74, color: "var(--ds-color-primary)" },
    { dept: "영업본부", pct: 58, color: "var(--ds-color-warning)" },
    { dept: "생산관리", pct: 33, color: "var(--ds-color-warning)" },
    { dept: "연구소", pct: 12, color: "var(--ds-color-danger)" },
  ];
  return (
    <div className="ads-root" style={{ padding: 24 }}>
      <Card padding="20px">
        <h3 style={{ margin: "0 0 14px", fontSize: 14, fontWeight: 700, color: "var(--ds-color-text)" }}>부서별 조치 진척</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {rows.map((r) => (
            <ProgressBar key={r.dept} label={r.dept} value={r.pct} color={r.color} />
          ))}
        </div>
      </Card>
    </div>
  );
}
