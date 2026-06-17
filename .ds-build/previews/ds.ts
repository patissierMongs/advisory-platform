// Previews consume the SHIPPED bundle (window.AdvisoryDS), not the source,
// so what we screenshot is exactly what designs will render.
const DS = (globalThis as any).AdvisoryDS;
if (!DS) throw new Error("AdvisoryDS bundle not loaded before previews");
export const {
  Card, Button, Badge, Chip, SeverityBadge, StatCard, Alert, DataTable,
  Sidebar, NavItem, Topbar, Stepper, Dropzone, ProgressBar, Avatar, Modal, Toast,
} = DS;
