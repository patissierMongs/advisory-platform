(() => {
  // react-shim.js
  var R = typeof window !== "undefined" && window.React || globalThis.React;
  if (!R) throw new Error("AdvisoryDS bundle: window.React not found \u2014 load React before the bundle.");
  var react_shim_default = R;
  var createElement = R.createElement;
  var Fragment = R.Fragment;
  var useState = R.useState;
  var useEffect = R.useEffect;
  var useRef = R.useRef;
  var useMemo = R.useMemo;
  var useCallback = R.useCallback;
  var forwardRef = R.forwardRef;

  // previews/ds.ts
  var DS = globalThis.AdvisoryDS;
  if (!DS) throw new Error("AdvisoryDS bundle not loaded before previews");
  var {
    Card,
    Button,
    Badge,
    Chip,
    SeverityBadge,
    StatCard,
    Alert,
    DataTable,
    Sidebar,
    NavItem,
    Topbar,
    Stepper,
    Dropzone,
    ProgressBar,
    Avatar,
    Modal,
    Toast
  } = DS;

  // previews/Alert.jsx
  function Preview() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24, display: "flex", flexDirection: "column", gap: 12 } }, /* @__PURE__ */ react_shim_default.createElement(Alert, { tone: "info", title: "\uC790\uC0B0\uB300\uC7A5 \uC790\uB3D9 \uB9E4\uCE6D \uC644\uB8CC \u2014" }, "CVE DB\uC5D0\uC11C \uC870\uD68C\uB41C \uC81C\uD488\xB7\uBC84\uC804\uACFC \uC77C\uCE58\uD558\uB294 \uC790\uC0B0\uC744 \uCC3E\uC558\uC2B5\uB2C8\uB2E4."), /* @__PURE__ */ react_shim_default.createElement(
      Alert,
      {
        tone: "warning",
        title: "DB \uBBF8\uB4F1\uB85D CVE 3\uAC74 \u2014",
        action: /* @__PURE__ */ react_shim_default.createElement(Button, { size: "sm", variant: "warning" }, "CVE \uB370\uC774\uD130\uBCA0\uC774\uC2A4 \u2192")
      },
      "\uB85C\uCEEC CVE DB\uC5D0 \uD574\uB2F9 \uCF54\uB4DC\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4. \uCD5C\uC2E0 \uD53C\uB4DC \uD30C\uC77C\uC744 \uBC18\uC785\uD558\uBA74 \uC790\uB3D9\uC73C\uB85C \uC870\uD68C\uB429\uB2C8\uB2E4."
    ), /* @__PURE__ */ react_shim_default.createElement(Alert, { tone: "danger", title: "\uBC1C\uC1A1 \uC9C1\uC804 \uCD5C\uC885 \uAC80\uD1A0 \u2014" }, "\uBD80\uC11C\uBCC4 \uBA54\uC2DC\uC9C0\uC640 \uCC44\uB110\uC744 \uD655\uC778\uD55C \uB4A4 \uBC1C\uC1A1\uD558\uC138\uC694. \uBC1C\uC1A1 \uD6C4\uC5D0\uB294 \uD68C\uC218\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4."));
  }

  // previews/Avatar.jsx
  function Preview2() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 28, display: "flex", gap: 26, alignItems: "center" } }, /* @__PURE__ */ react_shim_default.createElement(Avatar, { initials: "\uAD00\uC81C" }), /* @__PURE__ */ react_shim_default.createElement(Avatar, { initials: "JS", size: 40, background: "var(--ds-color-navy)" }), /* @__PURE__ */ react_shim_default.createElement(Avatar, { initials: "\uAD00\uC81C", name: "\uC815\uBCF4\uBCF4\uD638\uD300 \xB7 \uAD00\uC81C", role: "\uBCF4\uC548\uAD00\uC81C \uB2F4\uB2F9" }));
  }

  // previews/Badge.jsx
  function Preview3() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 28, display: "flex", flexDirection: "column", gap: 14 } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", gap: 8, flexWrap: "wrap" } }, /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "primary" }, "\uCC98\uB9AC\uC911"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "danger" }, "\uAE34\uAE09"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "warning" }, "DB \uBBF8\uB4F1\uB85D"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "info" }, "NVD"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "success" }, "\uC644\uB8CC"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "purple" }, "KISA \uACF5\uC9C0"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "neutral" }, "\uB300\uAE30")), /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", gap: 8, flexWrap: "wrap" } }, /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "primary", variant: "solid" }, "NEW"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "danger", variant: "solid" }, "9\uAC74"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "primary", dot: true }, "\uB85C\uCEEC \uCC98\uB9AC"), /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "neutral", dot: true }, "\uC624\uD504\uB77C\uC778")));
  }

  // previews/Button.jsx
  function Preview4() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 28, display: "flex", flexDirection: "column", gap: 16 } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" } }, /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "primary" }, "\uD30C\uC77C \uC120\uD0DD"), /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "dark" }, "\uC804\uCCB4 \uBD80\uC11C \uC77C\uAD04 \uBC1C\uC1A1"), /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "danger" }, "\uBC1C\uC1A1"), /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "secondary" }, "\u2190 \uC774\uC804"), /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "ghost" }, "+ \uCD94\uAC00")), /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", gap: 10, alignItems: "center" } }, /* @__PURE__ */ react_shim_default.createElement(Button, { size: "sm", variant: "primary" }, "\uC791\uAC8C"), /* @__PURE__ */ react_shim_default.createElement(Button, { size: "sm", variant: "secondary" }, "\uCDE8\uC18C"), /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "primary", disabled: true }, "\uBE44\uD65C\uC131")));
  }

  // previews/Card.jsx
  function Preview5() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 18, padding: 24 } }, /* @__PURE__ */ react_shim_default.createElement(Card, null, /* @__PURE__ */ react_shim_default.createElement("h2", { style: { margin: "0 0 4px", fontSize: 15, fontWeight: 700, color: "var(--ds-color-text)" } }, "\uBCF4\uC548\uAD8C\uACE0\uBB38 PDF \uC5C5\uB85C\uB4DC"), /* @__PURE__ */ react_shim_default.createElement("p", { style: { margin: 0, fontSize: 13, color: "var(--ds-color-text-soft)" } }, "PDF\uC5D0\uC11C CVE \uCF54\uB4DC\uB9CC \uC790\uB3D9 \uCD94\uCD9C\uD569\uB2C8\uB2E4. \uC81C\uD488\xB7\uBC84\uC804 \uC815\uBCF4\uB294 \uB85C\uCEEC CVE DB\uC5D0\uC11C \uC870\uD68C\uD569\uB2C8\uB2E4.")), /* @__PURE__ */ react_shim_default.createElement(Card, { padding: "22px" }, /* @__PURE__ */ react_shim_default.createElement("h3", { style: { margin: "0 0 6px", fontSize: 13.5, fontWeight: 700, color: "var(--ds-color-text)" } }, "\uB370\uC774\uD130\uBCA0\uC774\uC2A4 \uC0C1\uD0DC"), /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 12.5, color: "var(--ds-color-text-soft)" } }, "\uB4F1\uB85D CVE 1,284\uAC74 \xB7 \uB9C8\uC9C0\uB9C9 \uAC31\uC2E0 06:00")));
  }

  // previews/Chip.jsx
  function Preview6() {
    const codes = ["CVE-2024-21413", "CVE-2024-38063", "CVE-2023-44487", "CVE-2024-3094"];
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 28 } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" } }, /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 11, color: "var(--ds-color-text-faint)", fontWeight: 600 } }, "\uCD94\uCD9C\uB41C CVE"), codes.map((c) => /* @__PURE__ */ react_shim_default.createElement(Chip, { key: c, mono: true, onRemove: () => {
    } }, c))));
  }

  // previews/DataTable.jsx
  function Preview7() {
    const rows = [
      { id: "CVE-2024-21413", product: "Microsoft Outlook", ver: "\u2264 16.0.17", sev: "critical", status: "\uC870\uD68C\uC644\uB8CC" },
      { id: "CVE-2024-38063", product: "Windows TCP/IP", ver: "10 / 11", sev: "high", status: "\uC870\uD68C\uC644\uB8CC" },
      { id: "CVE-2023-44487", product: "HTTP/2 (nginx)", ver: "< 1.25.3", sev: "medium", status: "\uC870\uD68C\uC644\uB8CC" },
      { id: "CVE-2024-3094", product: "xz-utils", ver: "5.6.0\u20135.6.1", sev: "low", status: "\uBBF8\uB4F1\uB85D" }
    ];
    const columns = [
      { key: "id", header: "CVE", width: "150px", render: (r) => /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontFamily: "var(--ds-font-mono)", fontWeight: 600, color: "var(--ds-color-primary-strong)" } }, r.id) },
      { key: "product", header: "\uC81C\uD488 / OS", width: "1fr", render: (r) => /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontWeight: 600, color: "var(--ds-color-text-strong)" } }, r.product) },
      { key: "ver", header: "\uC601\uD5A5 \uBC84\uC804", width: "120px" },
      { key: "sev", header: "\uC2EC\uAC01\uB3C4", width: "90px", align: "center", render: (r) => /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: r.sev }) },
      { key: "status", header: "\uC0C1\uD0DC", width: "90px", align: "right", render: (r) => /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: r.status === "\uBBF8\uB4F1\uB85D" ? "warning" : "success" }, r.status) }
    ];
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24 } }, /* @__PURE__ */ react_shim_default.createElement(DataTable, { columns, data: rows, getRowKey: (r) => r.id }));
  }

  // previews/Dropzone.jsx
  function Preview8() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24 } }, /* @__PURE__ */ react_shim_default.createElement(Card, { padding: "24px" }, /* @__PURE__ */ react_shim_default.createElement(
      Dropzone,
      {
        title: "PDF \uD30C\uC77C\uC744 \uC5EC\uAE30\uB85C \uB04C\uC5B4\uB2E4 \uB193\uC73C\uC138\uC694",
        hint: "\uB610\uB294 \uD074\uB9AD\uD558\uC5EC \uD30C\uC77C \uC120\uD0DD \xB7 \uCD5C\uB300 30MB \xB7 \uB2E4\uC911 \uC5C5\uB85C\uB4DC \uC9C0\uC6D0",
        buttonLabel: "\uD30C\uC77C \uC120\uD0DD"
      }
    )));
  }

  // previews/Modal.jsx
  function Preview9() {
    const pdfIcon = /* @__PURE__ */ react_shim_default.createElement("div", { style: { width: 30, height: 36, borderRadius: 5, background: "var(--ds-color-danger-tint)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 } }, /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 8, fontWeight: 800, color: "var(--ds-color-danger)" } }, "PDF"));
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { position: "relative", height: 460, background: "var(--ds-color-bg)" } }, /* @__PURE__ */ react_shim_default.createElement(
      Modal,
      {
        open: true,
        title: "2026\uB144 \uC0C1\uBC18\uAE30 \uBCF4\uC548\uAD8C\uACE0\uBB38",
        subtitle: "NIS-2026-0142",
        icon: pdfIcon,
        footer: /* @__PURE__ */ react_shim_default.createElement(Button, { variant: "primary", size: "sm" }, "\uB2EB\uAE30")
      },
      /* @__PURE__ */ react_shim_default.createElement("div", { style: { background: "#fff", border: "1px solid #e6eaf0", borderRadius: 8, padding: "26px 30px", fontSize: 12.5, lineHeight: 1.95, color: "var(--ds-color-text-body)", boxShadow: "var(--ds-shadow-card)" } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontWeight: 700, marginBottom: 8 } }, "\uBCF4\uC548\uAD8C\uACE0\uBB38 \u2014 \uAE34\uAE09 \uCDE8\uC57D\uC810 \uC870\uCE58 \uC694\uCCAD"), /* @__PURE__ */ react_shim_default.createElement("div", null, "1. \uB300\uC0C1 \uC81C\uD488: Microsoft Outlook, Windows TCP/IP"), /* @__PURE__ */ react_shim_default.createElement("div", null, "2. \uAD00\uB828 CVE: CVE-2024-21413, CVE-2024-38063"), /* @__PURE__ */ react_shim_default.createElement("div", null, "3. \uC870\uCE58 \uAE30\uD55C: 2026. 6. 26."))
    ));
  }

  // previews/ProgressBar.jsx
  function Preview10() {
    const rows = [
      { dept: "\uC7AC\uBB34\uD300", pct: 92, color: "var(--ds-color-primary)" },
      { dept: "\uC778\uC0AC\uD300", pct: 74, color: "var(--ds-color-primary)" },
      { dept: "\uC601\uC5C5\uBCF8\uBD80", pct: 58, color: "var(--ds-color-warning)" },
      { dept: "\uC0DD\uC0B0\uAD00\uB9AC", pct: 33, color: "var(--ds-color-warning)" },
      { dept: "\uC5F0\uAD6C\uC18C", pct: 12, color: "var(--ds-color-danger)" }
    ];
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24 } }, /* @__PURE__ */ react_shim_default.createElement(Card, { padding: "20px" }, /* @__PURE__ */ react_shim_default.createElement("h3", { style: { margin: "0 0 14px", fontSize: 14, fontWeight: 700, color: "var(--ds-color-text)" } }, "\uBD80\uC11C\uBCC4 \uC870\uCE58 \uC9C4\uCC99"), /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } }, rows.map((r) => /* @__PURE__ */ react_shim_default.createElement(ProgressBar, { key: r.dept, label: r.dept, value: r.pct, color: r.color })))));
  }

  // previews/SeverityBadge.jsx
  function Preview11() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 28, display: "flex", gap: 12, alignItems: "center" } }, /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: "critical" }), /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: "high" }), /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: "medium" }), /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: "low" }), /* @__PURE__ */ react_shim_default.createElement(SeverityBadge, { level: "critical", label: "CRITICAL" }));
  }

  // previews/Sidebar.jsx
  var ic = (d) => /* @__PURE__ */ react_shim_default.createElement("svg", { width: "17", height: "17", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d, stroke: "currentColor", strokeWidth: "1.7", strokeLinecap: "round", strokeLinejoin: "round" }));
  function Preview12() {
    const brand = {
      icon: /* @__PURE__ */ react_shim_default.createElement("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 2 4 5v6c0 4.5 3.2 8.5 8 10 4.8-1.5 8-5.5 8-10V5l-8-3Z", stroke: "#fff", strokeWidth: "1.7", strokeLinejoin: "round" }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "m8.5 12 2.4 2.4 4.6-4.8", stroke: "#fff", strokeWidth: "1.7", strokeLinecap: "round", strokeLinejoin: "round" })),
      title: "\uBCF4\uC548\uAD8C\uACE0\uBB38 \uCC98\uB9AC",
      subtitle: "\uCDE8\uC57D\uC810 \uB300\uC751 \uC6CC\uD06C\uD50C\uB85C\uC6B0"
    };
    const items = [
      { label: "\uAD8C\uACE0\uBB38 \uCC98\uB9AC", icon: ic("M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2"), active: true, badge: "3" },
      { label: "CVE \uB370\uC774\uD130\uBCA0\uC774\uC2A4", icon: ic("M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7") },
      { label: "\uC790\uC0B0\uB300\uC7A5", icon: ic("M3 9h18M9 21V9M3 5h18v14H3z") },
      { label: "\uBC1C\uC1A1 \uC774\uB825", icon: ic("M22 2 11 13M22 2l-7 20-4-9-9-4 20-7Z") },
      { label: "\uB300\uC2DC\uBCF4\uB4DC", icon: ic("M3 3h8v8H3zM13 3h8v5h-8zM13 12h8v9h-8zM3 15h8v6H3z") }
    ];
    const footer = /* @__PURE__ */ react_shim_default.createElement("div", null, /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 11, color: "#7d93ad", marginBottom: 7 } }, "\uD3C9\uAC00 \uB300\uC751 \uB9C8\uAC10"), /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "baseline", gap: 7 } }, /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 22, fontWeight: 800, color: "var(--ds-color-primary-accent)" } }, "D-12"), /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 12, color: "#9fb1c6" } }, "2026. 6. 26.")));
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { height: 460 } }, /* @__PURE__ */ react_shim_default.createElement(Sidebar, { brand, items, footer }));
  }

  // previews/StatCard.jsx
  function Preview13() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24, display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 } }, /* @__PURE__ */ react_shim_default.createElement(StatCard, { label: "\uCD94\uCD9C CVE", value: "12", unit: "\uAC74" }), /* @__PURE__ */ react_shim_default.createElement(StatCard, { label: "DB \uC870\uD68C\uC644\uB8CC", value: "9", unit: "\uAC74", valueColor: "var(--ds-color-primary)" }), /* @__PURE__ */ react_shim_default.createElement(StatCard, { label: "DB \uBBF8\uB4F1\uB85D", value: "3", unit: "\uAC74", valueColor: "var(--ds-color-warning)" }));
  }

  // previews/Stepper.jsx
  function Preview14() {
    const steps = [
      { label: "PDF \uC5C5\uB85C\uB4DC" },
      { label: "CVE \uCD94\uCD9C\xB7\uC870\uD68C" },
      { label: "\uC790\uC0B0 \uB9E4\uCE6D" },
      { label: "\uBC1C\uC1A1 \uAC80\uD1A0" }
    ];
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24 } }, /* @__PURE__ */ react_shim_default.createElement(Card, { padding: "16px 22px" }, /* @__PURE__ */ react_shim_default.createElement(Stepper, { steps, current: 1 })));
  }

  // previews/Toast.jsx
  var okIcon = /* @__PURE__ */ react_shim_default.createElement("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("circle", { cx: "12", cy: "12", r: "9", stroke: "var(--ds-color-primary)", strokeWidth: "1.6" }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "M8.5 12l2.4 2.4 4.6-4.8", stroke: "var(--ds-color-primary)", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round" }));
  var warnIcon = /* @__PURE__ */ react_shim_default.createElement("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 3 2 20h20L12 3Z", stroke: "var(--ds-color-warning)", strokeWidth: "1.6", strokeLinejoin: "round" }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 10v4m0 3h.01", stroke: "var(--ds-color-warning)", strokeWidth: "1.8", strokeLinecap: "round" }));
  function Preview15() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 24, display: "flex", flexDirection: "column", gap: 16, background: "var(--ds-color-bg)" } }, /* @__PURE__ */ react_shim_default.createElement(Toast, { inline: true, tone: "primary", icon: okIcon, title: "\uBC1C\uC1A1 \uC644\uB8CC", onClose: () => {
    } }, "4\uAC1C \uBD80\uC11C\uC5D0 \uAD8C\uACE0\uBB38\uC774 \uBC1C\uC1A1\uB418\uC5C8\uC2B5\uB2C8\uB2E4. \uBC1C\uC1A1\uC774\uB825\uC5D0 \uAE30\uB85D\uB429\uB2C8\uB2E4."), /* @__PURE__ */ react_shim_default.createElement(
      Toast,
      {
        inline: true,
        tone: "warning",
        icon: warnIcon,
        title: "\uAD8C\uACE0\uBB38 \uC7AC\uD655\uC778 \uD544\uC694",
        actions: /* @__PURE__ */ react_shim_default.createElement(react_shim_default.Fragment, null, /* @__PURE__ */ react_shim_default.createElement(Button, { size: "sm", variant: "warning" }, "\uC608, \uB2E4\uC2DC \uC77D\uAE30"), /* @__PURE__ */ react_shim_default.createElement(Button, { size: "sm", variant: "secondary" }, "\uC544\uB2C8\uC624"))
      },
      "\uC0C8 CVE\uAC00 \uCD94\uAC00\uB418\uC5C8\uC2B5\uB2C8\uB2E4. PDF\uB97C \uB2E4\uC2DC \uBD84\uC11D\uD560\uAE4C\uC694?"
    ));
  }

  // previews/Topbar.jsx
  function Preview16() {
    return /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-root", style: { padding: 16, background: "var(--ds-color-bg)" } }, /* @__PURE__ */ react_shim_default.createElement(
      Topbar,
      {
        title: "\uAD8C\uACE0\uBB38 \uCC98\uB9AC",
        subtitle: "CVE \uCD94\uCD9C \xB7 \uC870\uD68C",
        actions: /* @__PURE__ */ react_shim_default.createElement(react_shim_default.Fragment, null, /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "primary", dot: true, style: { background: "var(--ds-color-surface-alt)", border: "1px solid var(--ds-color-border)", color: "var(--ds-color-text-body)", padding: "6px 11px" } }, "\uB85C\uCEEC \uCC98\uB9AC \xB7 \uC624\uD504\uB77C\uC778"), /* @__PURE__ */ react_shim_default.createElement(Avatar, { initials: "\uAD00\uC81C", name: "\uC815\uBCF4\uBCF4\uD638\uD300 \xB7 \uAD00\uC81C", role: "\uBCF4\uC548\uAD00\uC81C \uB2F4\uB2F9" }))
      }
    ));
  }

  // previews/_runtime.generated.jsx
  var REG = { Alert: Preview, Avatar: Preview2, Badge: Preview3, Button: Preview4, Card: Preview5, Chip: Preview6, DataTable: Preview7, Dropzone: Preview8, Modal: Preview9, ProgressBar: Preview10, SeverityBadge: Preview11, Sidebar: Preview12, StatCard: Preview13, Stepper: Preview14, Toast: Preview15, Topbar: Preview16 };
  function render(name, elId) {
    const el = document.getElementById(elId);
    const node = react_shim_default.createElement(REG[name]);
    const RD = window.ReactDOM;
    if (RD.createRoot) RD.createRoot(el).render(node);
    else RD.render(node, el);
  }
  globalThis.AdvisoryPreviews = { render, list: () => Object.keys(REG) };
})();
