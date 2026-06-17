// Maps bare `react` imports onto the global React the host app provides
// (claude.ai/design loads React on window before the bundle). No bundled copy.
const R = (typeof window !== "undefined" && window.React) || globalThis.React;
if (!R) throw new Error("AdvisoryDS bundle: window.React not found — load React before the bundle.");
export default R;
export const createElement = R.createElement;
export const Fragment = R.Fragment;
export const useState = R.useState;
export const useEffect = R.useEffect;
export const useRef = R.useRef;
export const useMemo = R.useMemo;
export const useCallback = R.useCallback;
export const forwardRef = R.forwardRef;
