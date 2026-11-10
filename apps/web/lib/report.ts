/**
 * Engagement report export helpers (DECISIONS.md D-049).
 *
 * Kept free of imports (and of non-erasable TypeScript syntax) so the Node test
 * runner can import it directly via type stripping, like lib/findings.ts.
 *
 * Backend contract: GET /engagements/{id}/report?format=md|json, served by
 * apps/api/routers/reports.py from the pure builder in services/report. The
 * browser only fetches and saves the bytes; it never builds or edits a report.
 */

export type ReportFormat = "md" | "json";

export const REPORT_FORMATS: readonly ReportFormat[] = ["md", "json"];

export function isReportFormat(value: unknown): value is ReportFormat {
  return value === "md" || value === "json";
}

/** Path and query for the report endpoint, with the engagement id URL-encoded. */
export function reportPath(engagementId: string, format: ReportFormat): string {
  return `/engagements/${encodeURIComponent(engagementId)}/report?format=${format}`;
}

/**
 * The download name the server sends in Content-Disposition. Mirrors
 * `_filename` in apps/api/routers/reports.py: runs of characters outside
 * [A-Za-z0-9._-] become "_", and leading/trailing dots and underscores go.
 */
export function reportFilename(engagementId: string, format: ReportFormat): string {
  const safe =
    engagementId.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "") ||
    "engagement";
  return `seekthreat-report-${safe}.${format}`;
}

/**
 * The filename from a Content-Disposition header, or null when it has none.
 * Handles the quoted and the bare `filename=` forms; anything with a path
 * separator is refused so a hostile header cannot pick a directory.
 */
export function filenameFromDisposition(header: string | null): string | null {
  if (!header) return null;
  const match = /filename\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(header);
  const name = match ? (match[1] ?? match[2] ?? "").trim() : "";
  if (!name || /[\\/]/.test(name) || name === "." || name === "..") return null;
  return name;
}
