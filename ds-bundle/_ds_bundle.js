// @ds-bundle AdvisoryDS — generated from web/app.dc.html patterns. Do not edit by hand.
var AdvisoryDS = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/index.ts
  var index_exports = {};
  __export(index_exports, {
    Alert: () => Alert,
    Avatar: () => Avatar,
    BADGE_TONES: () => BADGE_TONES,
    Badge: () => Badge,
    Button: () => Button,
    Card: () => Card,
    Chip: () => Chip,
    DataTable: () => DataTable,
    Dropzone: () => Dropzone,
    Modal: () => Modal,
    NavItem: () => NavItem,
    ProgressBar: () => ProgressBar,
    SeverityBadge: () => SeverityBadge,
    Sidebar: () => Sidebar,
    StatCard: () => StatCard,
    Stepper: () => Stepper,
    Toast: () => Toast,
    Topbar: () => Topbar
  });

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

  // src/components/Card.tsx
  function Card({ padding = 20, flush = false, style, children, ...rest }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        ...rest,
        style: {
          background: "var(--ds-color-surface)",
          border: flush ? "none" : "1px solid var(--ds-color-border)",
          borderRadius: flush ? 0 : "var(--ds-radius-xl)",
          padding,
          ...style
        }
      },
      children
    );
  }

  // src/components/Button.tsx
  var VARIANTS = {
    primary: { background: "var(--ds-color-primary)", color: "#fff", border: "none" },
    dark: { background: "var(--ds-color-navy)", color: "#fff", border: "none" },
    danger: { background: "var(--ds-color-danger)", color: "#fff", border: "none" },
    warning: { background: "var(--ds-color-warning)", color: "#fff", border: "none" },
    secondary: { background: "#fff", color: "var(--ds-color-text-muted)", border: "1px solid var(--ds-color-border-field)" },
    ghost: { background: "#fff", color: "var(--ds-color-primary-strong)", border: "1px solid var(--ds-color-primary-border)" }
  };
  var SIZES = {
    sm: { padding: "6px 13px", fontSize: 11.5 },
    md: { padding: "10px 22px", fontSize: 13 }
  };
  function Button({
    variant = "primary",
    size = "md",
    leftIcon,
    style,
    className,
    children,
    ...rest
  }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "button",
      {
        ...rest,
        className: ["ads-btn", className].filter(Boolean).join(" "),
        style: {
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 6,
          borderRadius: "var(--ds-radius-md)",
          fontWeight: 600,
          fontFamily: "inherit",
          cursor: "pointer",
          whiteSpace: "nowrap",
          ...SIZES[size],
          ...VARIANTS[variant],
          ...style
        }
      },
      leftIcon,
      children
    );
  }

  // src/components/Badge.tsx
  var BADGE_TONES = {
    primary: { fg: "var(--ds-color-primary)", bg: "var(--ds-color-primary-tint)", border: "var(--ds-color-primary-border)" },
    danger: { fg: "var(--ds-color-danger)", bg: "var(--ds-color-danger-tint)", border: "var(--ds-color-danger-border)" },
    warning: { fg: "var(--ds-color-warning-text)", bg: "var(--ds-color-warning-tint-2)", border: "var(--ds-color-warning-border)" },
    info: { fg: "var(--ds-color-info)", bg: "var(--ds-color-info-tint)", border: "var(--ds-color-info-border)" },
    success: { fg: "var(--ds-color-primary)", bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)" },
    purple: { fg: "var(--ds-color-purple)", bg: "var(--ds-color-purple-tint)", border: "var(--ds-color-purple-border)" },
    neutral: { fg: "var(--ds-color-text-muted)", bg: "var(--ds-color-surface-alt)", border: "var(--ds-color-border-field)" }
  };
  function Badge({ tone = "neutral", variant = "soft", dot = false, style, children, ...rest }) {
    const c = BADGE_TONES[tone];
    const solid = variant === "solid";
    return /* @__PURE__ */ react_shim_default.createElement(
      "span",
      {
        ...rest,
        style: {
          display: "inline-flex",
          alignItems: "center",
          gap: 5,
          fontSize: 11,
          fontWeight: 600,
          lineHeight: 1.4,
          padding: "3px 9px",
          borderRadius: "var(--ds-radius-sm)",
          color: solid ? "#fff" : c.fg,
          background: solid ? c.fg : c.bg,
          border: solid ? "none" : `1px solid ${c.border}`,
          whiteSpace: "nowrap",
          ...style
        }
      },
      dot && /* @__PURE__ */ react_shim_default.createElement(
        "span",
        {
          style: {
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: solid ? "#fff" : c.fg,
            flexShrink: 0
          }
        }
      ),
      children
    );
  }

  // src/components/Chip.tsx
  function Chip({ children, onRemove, mono = false }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "span",
      {
        style: {
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          fontSize: 11.5,
          fontWeight: 600,
          fontFamily: mono ? "var(--ds-font-mono)" : "inherit",
          color: "var(--ds-color-primary-strong)",
          background: "var(--ds-color-primary-tint)",
          border: "1px solid var(--ds-color-primary-border)",
          borderRadius: "var(--ds-radius-sm)",
          padding: "4px 9px"
        }
      },
      children,
      onRemove && /* @__PURE__ */ react_shim_default.createElement(
        "button",
        {
          type: "button",
          onClick: onRemove,
          "aria-label": "remove",
          style: {
            background: "none",
            border: "none",
            cursor: "pointer",
            padding: 0,
            display: "flex",
            color: "inherit",
            opacity: 0.55
          }
        },
        /* @__PURE__ */ react_shim_default.createElement("svg", { width: "11", height: "11", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M6 6l12 12M18 6L6 18", stroke: "currentColor", strokeWidth: "2.4", strokeLinecap: "round" }))
      )
    );
  }

  // src/components/SeverityBadge.tsx
  var SEVERITY_TONE = {
    critical: "danger",
    high: "warning",
    medium: "info",
    low: "neutral"
  };
  var SEVERITY_LABEL = {
    critical: "\uAE34\uAE09",
    high: "\uB192\uC74C",
    medium: "\uBCF4\uD1B5",
    low: "\uB0AE\uC74C"
  };
  function SeverityBadge({ level, label }) {
    return /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: SEVERITY_TONE[level], variant: "soft", style: { justifyContent: "center", minWidth: 42 } }, label != null ? label : SEVERITY_LABEL[level]);
  }

  // src/components/StatCard.tsx
  function StatCard({ label, value, unit, valueColor = "var(--ds-color-text)", bare = false }) {
    const body = /* @__PURE__ */ react_shim_default.createElement(react_shim_default.Fragment, null, /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 12, color: "var(--ds-color-text-soft)", fontWeight: 600 } }, label), /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "baseline", gap: 6, marginTop: bare ? 2 : 8 } }, /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: bare ? 17 : 28, fontWeight: 800, color: valueColor, letterSpacing: "-.5px" } }, value), unit && /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 13, color: "var(--ds-color-text-faint)" } }, unit)));
    if (bare) return /* @__PURE__ */ react_shim_default.createElement("div", null, body);
    return /* @__PURE__ */ react_shim_default.createElement(Card, { padding: "18px 20px" }, body);
  }

  // src/components/Alert.tsx
  var stroke = (color) => ({ stroke: color, strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round", fill: "none" });
  function infoIcon(c) {
    return /* @__PURE__ */ react_shim_default.createElement("svg", { width: "20", height: "20", viewBox: "0 0 24 24" }, /* @__PURE__ */ react_shim_default.createElement("circle", { cx: "12", cy: "12", r: "9", ...stroke(c) }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 8v5m0 3h.01", ...stroke(c) }));
  }
  function warnIcon(c) {
    return /* @__PURE__ */ react_shim_default.createElement("svg", { width: "20", height: "20", viewBox: "0 0 24 24" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 3 2 20h20L12 3Z", ...stroke(c) }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 10v4m0 3h.01", ...stroke(c) }));
  }
  function checkIcon(c) {
    return /* @__PURE__ */ react_shim_default.createElement("svg", { width: "20", height: "20", viewBox: "0 0 24 24" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M20 6 9 17l-5-5", ...stroke(c) }));
  }
  var TONES = {
    info: { bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)", fg: "var(--ds-color-primary-strong)", icon: infoIcon("var(--ds-color-primary)") },
    success: { bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)", fg: "var(--ds-color-primary-strong)", icon: checkIcon("var(--ds-color-primary)") },
    warning: { bg: "var(--ds-color-warning-tint)", border: "var(--ds-color-warning-border)", leftBar: "var(--ds-color-warning-accent)", fg: "var(--ds-color-warning-strong)", icon: warnIcon("var(--ds-color-warning)") },
    danger: { bg: "var(--ds-color-danger-tint)", border: "var(--ds-color-danger-border)", leftBar: "var(--ds-color-danger)", fg: "var(--ds-color-danger-text)", icon: warnIcon("var(--ds-color-danger)") }
  };
  function Alert({ tone = "info", title, children, action }) {
    const t = TONES[tone];
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        style: {
          display: "flex",
          alignItems: "center",
          gap: 12,
          background: t.bg,
          border: `1px solid ${t.border}`,
          borderLeft: t.leftBar ? `3px solid ${t.leftBar}` : `1px solid ${t.border}`,
          borderRadius: "var(--ds-radius-lg)",
          padding: "13px 18px"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement("span", { style: { flexShrink: 0, display: "flex" } }, t.icon),
      /* @__PURE__ */ react_shim_default.createElement("div", { style: { flex: 1, fontSize: 13, lineHeight: 1.55, color: t.fg } }, title && /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontWeight: 700 } }, title, " "), children),
      action && /* @__PURE__ */ react_shim_default.createElement("span", { style: { flexShrink: 0 } }, action)
    );
  }

  // src/components/DataTable.tsx
  function DataTable({
    columns,
    data,
    getRowKey,
    bordered = true
  }) {
    const template = columns.map((c) => {
      var _a;
      return (_a = c.width) != null ? _a : "1fr";
    }).join(" ");
    const cell = (c) => {
      var _a;
      return {
        textAlign: (_a = c.align) != null ? _a : "left",
        justifyContent: c.align === "center" ? "center" : c.align === "right" ? "flex-end" : "flex-start"
      };
    };
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        style: {
          background: "var(--ds-color-surface)",
          border: bordered ? "1px solid var(--ds-color-border)" : "none",
          borderRadius: bordered ? "var(--ds-radius-xl)" : 0,
          overflow: "hidden"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement(
        "div",
        {
          style: {
            display: "grid",
            gridTemplateColumns: template,
            padding: "10px 20px",
            background: "var(--ds-color-surface-subtle)",
            borderBottom: "1px solid var(--ds-color-border-soft)",
            fontSize: 11,
            fontWeight: 700,
            color: "var(--ds-color-text-faint)"
          }
        },
        columns.map((c) => /* @__PURE__ */ react_shim_default.createElement("span", { key: c.key, style: cell(c) }, c.header))
      ),
      data.map((row, i) => /* @__PURE__ */ react_shim_default.createElement(
        "div",
        {
          key: getRowKey ? getRowKey(row, i) : i,
          className: "ads-row",
          style: {
            display: "grid",
            gridTemplateColumns: template,
            alignItems: "center",
            padding: "11px 20px",
            borderBottom: i === data.length - 1 ? "none" : "1px solid var(--ds-color-border-faint)",
            fontSize: 12.5,
            color: "var(--ds-color-text-body)"
          }
        },
        columns.map((c) => /* @__PURE__ */ react_shim_default.createElement("span", { key: c.key, style: { display: "flex", ...cell(c) } }, c.render ? c.render(row, i) : row[c.key]))
      ))
    );
  }

  // src/components/Sidebar.tsx
  function NavItem({ label, icon, badge, active = false, onClick }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "button",
      {
        type: "button",
        onClick,
        className: "ads-navitem",
        style: {
          display: "flex",
          alignItems: "center",
          gap: 11,
          width: "100%",
          padding: "10px 12px",
          borderRadius: "var(--ds-radius-md)",
          border: "none",
          cursor: "pointer",
          fontSize: 13,
          fontFamily: "inherit",
          fontWeight: active ? 700 : 500,
          textAlign: "left",
          background: active ? "rgba(95,208,196,.12)" : "transparent",
          color: active ? "#fff" : "#cdd8e6"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement("span", { style: { display: "flex", width: 20, justifyContent: "center", flexShrink: 0 } }, icon),
      /* @__PURE__ */ react_shim_default.createElement("span", { style: { flex: 1 } }, label),
      badge != null && /* @__PURE__ */ react_shim_default.createElement(Badge, { tone: "primary", variant: "solid" }, badge)
    );
  }
  function Sidebar({ brand, items, footer, width = 248, children }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "aside",
      {
        style: {
          width,
          flexShrink: 0,
          background: "var(--ds-color-navy)",
          color: "#cdd8e6",
          display: "flex",
          flexDirection: "column",
          height: "100%"
        }
      },
      brand && /* @__PURE__ */ react_shim_default.createElement(
        "div",
        {
          style: {
            padding: "20px 20px 18px",
            borderBottom: "1px solid rgba(255,255,255,.08)",
            display: "flex",
            alignItems: "center",
            gap: 11
          }
        },
        brand.icon && /* @__PURE__ */ react_shim_default.createElement(
          "div",
          {
            style: {
              width: 34,
              height: 34,
              borderRadius: "var(--ds-radius-md)",
              background: "var(--ds-color-primary)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0
            }
          },
          brand.icon
        ),
        /* @__PURE__ */ react_shim_default.createElement("div", null, /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 14, fontWeight: 700, color: "#fff", letterSpacing: "-.2px" } }, brand.title), brand.subtitle && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 11, color: "#7d93ad", marginTop: 1 } }, brand.subtitle))
      ),
      /* @__PURE__ */ react_shim_default.createElement("nav", { style: { padding: 12, display: "flex", flexDirection: "column", gap: 3, flex: 1 } }, items == null ? void 0 : items.map((it, i) => /* @__PURE__ */ react_shim_default.createElement(NavItem, { key: i, ...it })), children),
      footer && /* @__PURE__ */ react_shim_default.createElement("div", { style: { padding: 16, borderTop: "1px solid rgba(255,255,255,.08)" } }, footer)
    );
  }

  // src/components/Topbar.tsx
  function Topbar({ title, subtitle, actions, children }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "header",
      {
        style: {
          height: 60,
          flexShrink: 0,
          background: "var(--ds-color-surface)",
          borderBottom: "1px solid var(--ds-color-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 26px"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", gap: 11 } }, /* @__PURE__ */ react_shim_default.createElement("h1", { style: { margin: 0, fontSize: 17, fontWeight: 700, color: "var(--ds-color-text)", letterSpacing: "-.3px" } }, title), subtitle && /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 12, color: "var(--ds-color-text-soft)", fontWeight: 500 } }, subtitle)),
      /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", gap: 14 } }, actions, children)
    );
  }

  // src/components/Stepper.tsx
  function Stepper({ steps, current, onStepClick }) {
    return /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", width: "100%" } }, steps.map((st, i) => {
      const done = i < current;
      const active = i === current;
      const reached = done || active;
      const num = i + 1;
      return /* @__PURE__ */ react_shim_default.createElement("div", { key: i, style: { display: "flex", alignItems: "center", flex: 1 } }, /* @__PURE__ */ react_shim_default.createElement(
        "button",
        {
          type: "button",
          onClick: onStepClick ? () => onStepClick(i) : void 0,
          style: {
            display: "flex",
            alignItems: "center",
            gap: 11,
            background: "none",
            border: "none",
            padding: 0,
            cursor: onStepClick ? "pointer" : "default",
            fontFamily: "inherit"
          }
        },
        /* @__PURE__ */ react_shim_default.createElement(
          "span",
          {
            style: {
              width: 30,
              height: 30,
              borderRadius: "50%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 13,
              fontWeight: 700,
              flexShrink: 0,
              color: reached ? "#fff" : "var(--ds-color-text-faint)",
              background: reached ? "var(--ds-color-primary)" : "var(--ds-color-bg)",
              border: reached ? "none" : "1px solid var(--ds-color-border-field)"
            }
          },
          done ? /* @__PURE__ */ react_shim_default.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M20 6 9 17l-5-5", stroke: "#fff", strokeWidth: "2.4", strokeLinecap: "round", strokeLinejoin: "round" })) : num
        ),
        /* @__PURE__ */ react_shim_default.createElement("span", { style: { display: "flex", flexDirection: "column", alignItems: "flex-start", lineHeight: 1.2 } }, /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 10.5, color: "var(--ds-color-text-faint)", fontWeight: 600 } }, "STEP ", num), /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 13, fontWeight: active ? 700 : 600, color: active ? "var(--ds-color-text)" : "var(--ds-color-text-muted)" } }, st.label))
      ), i < steps.length - 1 && /* @__PURE__ */ react_shim_default.createElement(
        "span",
        {
          style: {
            flex: 1,
            height: 2,
            margin: "0 14px",
            background: i < current ? "var(--ds-color-primary)" : "var(--ds-color-border)",
            borderRadius: 2
          }
        }
      ));
    }));
  }

  // src/components/Dropzone.tsx
  var defaultIcon = /* @__PURE__ */ react_shim_default.createElement("svg", { width: "26", height: "26", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M12 16V4m0 0L7 9m5-5 5 5", stroke: "var(--ds-color-primary)", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round" }), /* @__PURE__ */ react_shim_default.createElement("path", { d: "M4 17v2a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-2", stroke: "var(--ds-color-primary)", strokeWidth: "1.8", strokeLinecap: "round" }));
  function Dropzone({ icon = defaultIcon, title, hint, buttonLabel, onPick, onDragOver, onDrop, compact = false }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        onDragOver,
        onDrop,
        style: {
          border: "2px dashed #c4d0de",
          borderRadius: "var(--ds-radius-xl)",
          background: "var(--ds-color-surface-muted)",
          padding: compact ? "30px 20px" : "46px 20px",
          textAlign: "center"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement(
        "div",
        {
          style: {
            width: compact ? 48 : 54,
            height: compact ? 48 : 54,
            margin: "0 auto 12px",
            borderRadius: "var(--ds-radius-2xl)",
            background: "var(--ds-color-primary-tint)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center"
          }
        },
        icon
      ),
      title && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: compact ? 13 : 14, fontWeight: 600, color: "var(--ds-color-text-body)" } }, title),
      hint && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 11.5, color: "var(--ds-color-text-faint)", marginTop: 5 } }, hint),
      buttonLabel && /* @__PURE__ */ react_shim_default.createElement(
        "button",
        {
          type: "button",
          onClick: onPick,
          className: "ads-btn",
          style: {
            marginTop: 16,
            background: "var(--ds-color-primary)",
            color: "#fff",
            border: "none",
            borderRadius: "var(--ds-radius-md)",
            padding: "10px 22px",
            fontSize: 13,
            fontWeight: 600,
            cursor: "pointer",
            fontFamily: "inherit"
          }
        },
        buttonLabel
      )
    );
  }

  // src/components/ProgressBar.tsx
  function ProgressBar({ value, color = "var(--ds-color-primary)", label, showValue = true, height = 7 }) {
    const pct = Math.max(0, Math.min(100, value));
    return /* @__PURE__ */ react_shim_default.createElement("div", null, (label != null || showValue) && /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: 5 } }, label != null && /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 12.5, color: "var(--ds-color-text-body)", fontWeight: 600 } }, label), showValue && /* @__PURE__ */ react_shim_default.createElement("span", { style: { fontSize: 12, color: "var(--ds-color-text-faint)" } }, pct, "%")), /* @__PURE__ */ react_shim_default.createElement("div", { style: { height, background: "var(--ds-color-border-soft)", borderRadius: 4, overflow: "hidden" } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { width: `${pct}%`, height: "100%", background: color, borderRadius: 4 } })));
  }

  // src/components/Avatar.tsx
  function Avatar({ initials, size = 32, background = "var(--ds-color-primary)", name, role }) {
    const circle = /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        style: {
          width: size,
          height: size,
          borderRadius: "50%",
          background,
          color: "#fff",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: Math.round(size * 0.375),
          fontWeight: 700,
          flexShrink: 0
        }
      },
      initials
    );
    if (name == null && role == null) return circle;
    return /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", gap: 9 } }, circle, /* @__PURE__ */ react_shim_default.createElement("div", { style: { lineHeight: 1.25 } }, name != null && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 12.5, fontWeight: 600, color: "var(--ds-color-text-strong)" } }, name), role != null && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 11, color: "var(--ds-color-text-faint)" } }, role)));
  }

  // src/components/Modal.tsx
  function Modal({ open, onClose, title, subtitle, icon, footer, width = 600, children }) {
    if (!open) return null;
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        className: "ads-modal-overlay",
        onClick: onClose,
        style: {
          position: "fixed",
          inset: 0,
          background: "rgba(15,29,46,.55)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 80,
          padding: 40
        }
      },
      /* @__PURE__ */ react_shim_default.createElement(
        "div",
        {
          onClick: (e) => e.stopPropagation(),
          style: {
            width,
            maxWidth: "100%",
            maxHeight: "84vh",
            background: "var(--ds-color-surface)",
            borderRadius: "var(--ds-radius-2xl)",
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            boxShadow: "var(--ds-shadow-modal)"
          }
        },
        (title || icon) && /* @__PURE__ */ react_shim_default.createElement(
          "div",
          {
            style: {
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "15px 20px",
              borderBottom: "1px solid var(--ds-color-border-soft)",
              background: "var(--ds-color-surface-subtle)"
            }
          },
          /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "center", gap: 11, minWidth: 0 } }, icon, /* @__PURE__ */ react_shim_default.createElement("div", { style: { minWidth: 0 } }, title && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 13.5, fontWeight: 700, color: "var(--ds-color-text)" } }, title), subtitle && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 11, color: "var(--ds-color-text-faint)", fontFamily: "var(--ds-font-mono)" } }, subtitle))),
          onClose && /* @__PURE__ */ react_shim_default.createElement(
            "button",
            {
              type: "button",
              onClick: onClose,
              "aria-label": "close",
              style: {
                width: 30,
                height: 30,
                borderRadius: "var(--ds-radius-sm)",
                background: "#fff",
                border: "1px solid var(--ds-color-border)",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0
              }
            },
            /* @__PURE__ */ react_shim_default.createElement("svg", { width: "15", height: "15", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M6 6l12 12M18 6L6 18", stroke: "var(--ds-color-text-muted)", strokeWidth: "1.8", strokeLinecap: "round" }))
          )
        ),
        /* @__PURE__ */ react_shim_default.createElement("div", { className: "ads-scroll", style: { padding: "24px 28px", overflowY: "auto", flex: 1 } }, children),
        footer && /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", justifyContent: "flex-end", gap: 10, padding: "13px 20px", borderTop: "1px solid var(--ds-color-border-soft)" } }, footer)
      )
    );
  }

  // src/components/Toast.tsx
  var ACCENT = {
    primary: "var(--ds-color-primary)",
    success: "var(--ds-color-primary)",
    danger: "var(--ds-color-danger)",
    warning: "var(--ds-color-warning)",
    info: "var(--ds-color-info)"
  };
  function Toast({ title, children, tone = "primary", icon, onClose, actions, inline = false }) {
    return /* @__PURE__ */ react_shim_default.createElement(
      "div",
      {
        className: "ads-toast",
        style: {
          ...inline ? { position: "relative" } : { position: "fixed", right: 24, bottom: 24, zIndex: 90 },
          width: 360,
          background: "var(--ds-color-surface)",
          border: "1px solid var(--ds-color-border)",
          borderLeft: `4px solid ${ACCENT[tone]}`,
          borderRadius: "var(--ds-radius-lg)",
          boxShadow: "var(--ds-shadow-pop)",
          padding: "15px 17px"
        }
      },
      /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", alignItems: "flex-start", gap: 11 } }, icon && /* @__PURE__ */ react_shim_default.createElement("span", { style: { flexShrink: 0, marginTop: 1 } }, icon), /* @__PURE__ */ react_shim_default.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 13, fontWeight: 700, color: "var(--ds-color-text)" } }, title), children && /* @__PURE__ */ react_shim_default.createElement("div", { style: { fontSize: 12, color: "var(--ds-color-text-muted)", marginTop: 3, lineHeight: 1.5 } }, children), actions && /* @__PURE__ */ react_shim_default.createElement("div", { style: { display: "flex", gap: 8, marginTop: 12 } }, actions)), onClose && /* @__PURE__ */ react_shim_default.createElement(
        "button",
        {
          type: "button",
          onClick: onClose,
          "aria-label": "close",
          style: { background: "none", border: "none", cursor: "pointer", padding: 2, flexShrink: 0, display: "flex" }
        },
        /* @__PURE__ */ react_shim_default.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none" }, /* @__PURE__ */ react_shim_default.createElement("path", { d: "M6 6l12 12M18 6L6 18", stroke: "#aab4c2", strokeWidth: "1.8", strokeLinecap: "round" }))
      ))
    );
  }
  return __toCommonJS(index_exports);
})();
