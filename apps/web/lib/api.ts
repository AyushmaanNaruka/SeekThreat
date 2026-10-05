/**
 * SeekThreat API Client
 * Type-safe communication with the backend FastAPI service.
 */

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
  scanner: "nmap" | "nuclei" | string;
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
// ---------------------------------------------------------------------------

export interface ProvenanceInfo {
  source: string;
  confidence: string;
  retrieved_at: string;
  note?: string;
}

export interface AttributedValue<T> {
  value: T;
  provenance: ProvenanceInfo;
}

export interface ScoreComponentInfo {
  name: string;
  raw_value: number;
  weight: number;
  weighted_value: number;
  explanation: string;
  provenance: ProvenanceInfo;
}

export interface ERSInfo {
  score: number;
  components: ScoreComponentInfo[];
  explanation: string;
}

export interface EnrichedFindingItem {
  finding_id: string;
  engagement_id: string;
  cve_id: string;
  cvss: AttributedValue<number> | null;
  epss: AttributedValue<number> | null;
  in_kev: AttributedValue<boolean | null> | null; // null value = unknown
  cwe_ids: AttributedValue<string[]> | null;
  description: AttributedValue<string> | null;
  ers: ERSInfo | null;
  enriched_at: string;
}

export interface EnrichedFindingListResponse {
  items: EnrichedFindingItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface BatchEnrichResult {
  status: string;
  count: number;
  items?: EnrichedFindingItem[];
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `Request failed with status ${res.status}`;
    try {
      const body = await res.json();
      if (body && body.detail) {
        errorDetail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      // not JSON
    }
    throw new ApiError(errorDetail, res.status);
  }
  return res.json();
}

/**
 * Normalizes backend EnrichedFinding structures into EnrichedFindingItem.
 */
export function normalizeEnrichedFinding(raw: Record<string, unknown>): EnrichedFindingItem {
  if (!raw) {
    return {
      finding_id: "unknown",
      engagement_id: "",
      cve_id: "N/A",
      cvss: null,
      epss: null,
      in_kev: null,
      cwe_ids: null,
      description: null,
      ers: null,
      enriched_at: new Date().toISOString(),
    };
  }

  // If already shaped as EnrichedFindingItem
  if (
    typeof raw.finding_id === "string" &&
    raw.cve_id !== undefined &&
    raw.cvss !== undefined
  ) {
    return raw as unknown as EnrichedFindingItem;
  }

  const finding = (raw.finding as Record<string, unknown>) || {};
  const fields = (raw.fields as Record<string, Record<string, unknown>>) || {};
  const rawErs = (raw.ers as Record<string, unknown>) || null;

  const cvssRaw = fields.cvss_score;
  const cvss: AttributedValue<number> | null = cvssRaw
    ? {
        value: Number(cvssRaw.value),
        provenance: cvssRaw.provenance as unknown as ProvenanceInfo,
      }
    : null;

  const epssRaw = fields.epss_score;
  const epss: AttributedValue<number> | null = epssRaw
    ? {
        value: Number(epssRaw.value),
        provenance: epssRaw.provenance as unknown as ProvenanceInfo,
      }
    : null;

  const inKevRaw = fields.in_kev;
  const in_kev: AttributedValue<boolean | null> | null = inKevRaw
    ? {
        value: inKevRaw.value === null ? null : Boolean(inKevRaw.value),
        provenance: inKevRaw.provenance as unknown as ProvenanceInfo,
      }
    : null;

  const cweRaw = fields.cwe_ids;
  const cwe_ids: AttributedValue<string[]> | null = cweRaw
    ? {
        value: Array.isArray(cweRaw.value) ? (cweRaw.value as string[]) : [],
        provenance: cweRaw.provenance as unknown as ProvenanceInfo,
      }
    : null;

  const descRaw = fields.summary;
  const description: AttributedValue<string> | null = descRaw
    ? {
        value: String(descRaw.value),
        provenance: descRaw.provenance as unknown as ProvenanceInfo,
      }
    : null;

  let ers: ERSInfo | null = null;
  if (rawErs) {
    const comps = Array.isArray(rawErs.components)
      ? (rawErs.components as Array<Record<string, unknown>>)
      : [];
    ers = {
      score: Number(rawErs.value ?? 0),
      components: comps.map((c) => ({
        name: String(c.name || "component"),
        raw_value: Number(c.value ?? 0),
        weight: Number(c.weight ?? 0),
        weighted_value: Number(c.value ?? 0) * Number(c.weight ?? 0),
        explanation: String(c.explanation || ""),
        provenance: (c.provenance as unknown as ProvenanceInfo) || {
          source: "derived",
          confidence: "low",
          retrieved_at: new Date().toISOString(),
        },
      })),
      explanation: String(rawErs.explanation || `Exposure Risk Score: ${rawErs.value ?? 0}`),
    };
  }

  const rawCves = finding.cve_ids;
  const primaryCve =
    Array.isArray(rawCves) && rawCves.length > 0
      ? String(rawCves[0])
      : typeof raw.cve_id === "string"
      ? raw.cve_id
      : "N/A";

  return {
    finding_id: String(finding.finding_id || raw.finding_id || "unknown"),
    engagement_id: String(finding.engagement_id || raw.engagement_id || ""),
    cve_id: primaryCve,
    cvss,
    epss,
    in_kev,
    cwe_ids,
    description,
    ers,
    enriched_at:
      cvss?.provenance?.retrieved_at ||
      (typeof finding.detected_at === "string" ? finding.detected_at : new Date().toISOString()),
  };
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
    offset = 0
  ): Promise<EnrichedFindingListResponse> {
    const res = await fetch(
      `${API_BASE_URL}/findings?engagement_id=${encodeURIComponent(
        engagementId
      )}&limit=${limit}&offset=${offset}`
    );
    const data = await handleResponse<{
      items: Array<Record<string, unknown>>;
      total: number;
      limit: number;
      offset: number;
    }>(res);

    return {
      items: (data.items || []).map(normalizeEnrichedFinding),
      total: data.total ?? (data.items || []).length,
      limit: data.limit ?? limit,
      offset: data.offset ?? offset,
    };
  },

  /**
   * POST /findings/enrich/batch
   * Batches up to 1000 findings with engagement_id in body.
   */
  async enrichFindingsBatch(
    engagementId: string,
    findings: Record<string, unknown>[]
  ): Promise<BatchEnrichResult> {
    const res = await fetch(`${API_BASE_URL}/findings/enrich/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        engagement_id: engagementId,
        findings,
        async_dispatch: false,
      }),
    });
    const data = await handleResponse<{
      status: string;
      count: number;
      items?: Array<Record<string, unknown>>;
    }>(res);

    return {
      status: data.status,
      count: data.count,
      items: (data.items || []).map(normalizeEnrichedFinding),
    };
  },
};
