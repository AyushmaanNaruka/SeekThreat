/**
 * SeekThreat API Client
 * Type-safe communication with the backend FastAPI service.
 */

import { normalizeEnrichedFinding } from "./findings";
import type { EnrichedFindingItem } from "./findings";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export interface EngagementItem {
  engagement_id: string;
  name: string;
  authorized_by: string;
  allowlist: string[];
  granted_at: string;
  expires_at: string;
  created_at: string;
}

export interface CreateEngagementPayload {
  engagement_id: string;
  name: string;
  authorized_by: string;
  allowlist: string[];
  granted_at: string;
  expires_at: string;
}

export interface ScanItem {
  scan_id: string;
  engagement_id: string;
  scanner: "nmap" | "nuclei" | "nikto" | "ssh-audit" | string;
  target: string;
  status: "pending" | "running" | "completed" | "failed";
  options: Record<string, unknown>;
  observation_count: number;
  artifact_id: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface CreateScanPayload {
  engagement_id: string;
  scanner: string;
  target: string;
  options?: Record<string, unknown>;
}

/** Body shared by POST /scans/plan and POST /scans/batch. */
export interface BatchScanPayload {
  engagement_id: string;
  scanner: "nmap" | "nuclei" | "nikto" | "ssh-audit";
  /** Raw user strings; the server splits each on commas/whitespace/semicolons. */
  targets: string[];
  /** Shared scanner options. Per-target port/scheme are derived server side. */
  options: Record<string, unknown>;
}

export interface ScanPlanItem {
  input: string;
  target: string;
  options: Record<string, unknown>;
  kind: "host" | "network";
  note: string | null;
}

export interface ScanRejection {
  input: string;
  target: string | null;
  reason: string;
}

export interface ScanPlanResponse {
  planned: ScanPlanItem[];
  rejected: ScanRejection[];
  total_planned: number;
  max_scans: number;
}

export interface BatchScanResponse {
  accepted: ScanItem[];
  rejected: ScanRejection[];
}

export interface ObservationProvenance {
  source: string;
  confidence: string;
  retrieved_at: string;
}

export interface ObservationItem {
  observation_id: string;
  engagement_id: string;
  scanner: string;
  kind: string;
  subject: string;
  attributes: Record<string, unknown>;
  artifact_id: string;
  observed_at: string;
  provenance: ObservationProvenance | null;
}

export interface ObservationListResponse {
  items: ObservationItem[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Enriched Findings & ERS (Level 5 Interfaces)
// Types and normalization live in ./findings so they can be unit tested.
// ---------------------------------------------------------------------------

export { normalizeEnrichedFinding };
export type {
  AttributedValue,
  ConfidenceLevel,
  EnrichedFindingItem,
  ERSInfo,
  ProvenanceInfo,
  ProvenanceSource,
  ScoreComponentInfo,
} from "./findings";

export interface EnrichedFindingListResponse {
  items: EnrichedFindingItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface BatchEnrichResult {
  status: string;
  count: number;
  finding_ids?: string[];
  items?: EnrichedFindingItem[];
}

export class ApiError extends Error {
  status: number;
  /**
   * Per-target rejections when the server refused a whole batch (422 from
   * POST /scans/batch with `detail: { message, rejected }`). Empty otherwise.
   */
  rejected: ScanRejection[];
  constructor(message: string, status: number, rejected: ScanRejection[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.rejected = rejected;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `Request failed with status ${res.status}`;
    let rejected: ScanRejection[] = [];
    try {
      const body = await res.json();
      if (body && body.detail) {
        const detail = body.detail;
        if (typeof detail === "string") {
          errorDetail = detail;
        } else if (
          detail &&
          typeof detail === "object" &&
          !Array.isArray(detail) &&
          typeof detail.message === "string"
        ) {
          errorDetail = detail.message;
          if (Array.isArray(detail.rejected)) rejected = detail.rejected;
        } else {
          errorDetail = JSON.stringify(detail);
        }
      }
    } catch {
      // not JSON
    }
    throw new ApiError(errorDetail, res.status, rejected);
  }
  return res.json();
}

export const api = {
  async getHealth(): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE_URL}/health`);
    return handleResponse<{ status: string }>(res);
  },

  async getEngagements(): Promise<EngagementItem[]> {
    const res = await fetch(`${API_BASE_URL}/engagements`);
    return handleResponse<EngagementItem[]>(res);
  },

  async getEngagement(id: string): Promise<EngagementItem> {
    const res = await fetch(`${API_BASE_URL}/engagements/${encodeURIComponent(id)}`);
    return handleResponse<EngagementItem>(res);
  },

  async createEngagement(data: CreateEngagementPayload): Promise<EngagementItem> {
    const res = await fetch(`${API_BASE_URL}/engagements`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse<EngagementItem>(res);
  },

  async getScans(engagementId?: string): Promise<ScanItem[]> {
    const url = engagementId
      ? `${API_BASE_URL}/scans?engagement_id=${encodeURIComponent(engagementId)}`
      : `${API_BASE_URL}/scans`;
    const res = await fetch(url);
    return handleResponse<ScanItem[]>(res);
  },

  async getScan(id: string): Promise<ScanItem> {
    const res = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(id)}`);
    return handleResponse<ScanItem>(res);
  },

  async launchScan(data: CreateScanPayload): Promise<ScanItem> {
    const res = await fetch(`${API_BASE_URL}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse<ScanItem>(res);
  },

  /** POST /scans/plan: dry run. Expands and scope-checks targets, dispatches nothing. */
  async planScans(data: BatchScanPayload, signal?: AbortSignal): Promise<ScanPlanResponse> {
    const res = await fetch(`${API_BASE_URL}/scans/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      signal,
    });
    return handleResponse<ScanPlanResponse>(res);
  },

  /**
   * POST /scans/batch: dispatches every in-scope target. A 422 where nothing
   * was accepted throws an ApiError whose `rejected` holds the reasons.
   */
  async launchScanBatch(data: BatchScanPayload): Promise<BatchScanResponse> {
    const res = await fetch(`${API_BASE_URL}/scans/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse<BatchScanResponse>(res);
  },

  async getScanObservations(
    scanId: string,
    limit = 50,
    offset = 0
  ): Promise<ObservationListResponse> {
    const res = await fetch(
      `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/observations?limit=${limit}&offset=${offset}`
    );
    return handleResponse<ObservationListResponse>(res);
  },

  // -------------------------------------------------------------------------
  // Enriched Findings API methods (Level 5)
  // -------------------------------------------------------------------------

  /**
   * GET /findings/{id}?engagement_id=...
   * Retrieve a single enriched finding record within an engagement.
   */
  async getFinding(findingId: string, engagementId: string): Promise<EnrichedFindingItem> {
    const res = await fetch(
      `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}?engagement_id=${encodeURIComponent(
        engagementId
      )}`
    );
    const raw = await handleResponse<Record<string, unknown>>(res);
    return normalizeEnrichedFinding(raw);
  },

  /**
   * GET /findings?engagement_id=...&limit=...&offset=...
   * Query paginated collection of enriched findings for the given engagement.
   */
  async getFindings(
    engagementId: string,
    limit = 50,
    offset = 0,
    signal?: AbortSignal
  ): Promise<EnrichedFindingListResponse> {
    const res = await fetch(
      `${API_BASE_URL}/findings?engagement_id=${encodeURIComponent(
        engagementId
      )}&limit=${limit}&offset=${offset}`,
      { signal }
    );
    const data = await handleResponse<{
      items: unknown[];
      total: number;
      limit: number;
      offset: number;
    }>(res);

    const items = (data.items || []).map((raw) => normalizeEnrichedFinding(raw));
    return {
      items,
      total: data.total,
      limit: data.limit,
      offset: data.offset,
    };
  },

  /**
   * POST /findings/enrich/batch
   *
   * Submits a batch of findings (up to 1000) for synchronous or asynchronous enrichment
   * against the backend findings router (`apps/api/routers/findings.py`).
   *
   * In standard SeekThreat workflows, findings enrichment is automatically triggered
   * post-scan via Celery (`seekthreat.enrichment.sync_new_findings_cves`). This client
   * method preserves API contract parity for direct batch enrichment operations,
   * script-driven re-enrichments, and future batch UI workflows.
   */
  async enrichFindingsBatch(
    engagementId: string,
    findings: Record<string, unknown>[],
    asyncDispatch = false
  ): Promise<BatchEnrichResult> {
    const res = await fetch(`${API_BASE_URL}/findings/enrich/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        engagement_id: engagementId,
        findings,
        async_dispatch: asyncDispatch,
      }),
    });
    const data = await handleResponse<{
      status: string;
      count: number;
      finding_ids?: string[];
      items?: unknown[];
    }>(res);

    return {
      status: data.status,
      count: data.count,
      finding_ids: data.finding_ids,
      items: (data.items || []).map((raw) => normalizeEnrichedFinding(raw)),
    };
  },
};
