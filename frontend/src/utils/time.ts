/**
 * Time utility for SentinelAI SOC Platform
 * Ensures all UTC timestamps from SQLite/FastAPI are properly converted to the user's
 * local machine timezone, matching real-time alerts.
 */

export function parseUtcDate(dateInput: string | Date | number | null | undefined): Date {
  if (!dateInput) return new Date();
  if (dateInput instanceof Date) return dateInput;
  if (typeof dateInput === "number") return new Date(dateInput);

  let str = String(dateInput).trim();
  if (!str) return new Date();

  // Replace SQLite space separator with 'T' (e.g., "2026-10-27 15:36:07" -> "2026-10-27T15:36:07")
  str = str.replace(" ", "T");

  // If the ISO string lacks timezone information (no trailing Z or ±HH:MM offset),
  // explicitly append 'Z' so JavaScript interprets it as UTC instead of local time.
  if (!str.endsWith("Z") && !/[+-]\d{2}(?::?\d{2})?$/.test(str)) {
    str += "Z";
  }

  const d = new Date(str);
  return isNaN(d.getTime()) ? new Date() : d;
}

/**
 * Returns formatted local time string: "HH:MM:SS" (24-hour format)
 */
export function formatTime(dateInput: string | Date | number | null | undefined): string {
  if (!dateInput) return "--:--:--";
  const d = parseUtcDate(dateInput);
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
}

/**
 * Returns formatted local date string: "YYYY-MM-DD"
 */
export function formatDate(dateInput: string | Date | number | null | undefined): string {
  if (!dateInput) return "----/--/--";
  const d = parseUtcDate(dateInput);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

/**
 * Returns formatted local timestamp: "YYYY-MM-DD HH:MM:SS"
 */
export function formatDateTime(dateInput: string | Date | number | null | undefined): string {
  if (!dateInput) return "----/--/-- --:--:--";
  const d = parseUtcDate(dateInput);
  const dateStr = formatDate(d);
  const timeStr = formatTime(d);
  return `${dateStr} ${timeStr}`;
}
