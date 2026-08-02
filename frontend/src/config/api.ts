export const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/$/, "");
export const WS_BASE = (import.meta.env.VITE_WS_URL || API_BASE.replace(/^http/, "ws")).replace(/\/$/, "");
