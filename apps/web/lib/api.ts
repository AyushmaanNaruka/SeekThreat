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
  options: Record<string, any>;
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
  options?: Record<string, any>;
}

export interface ObservationItem {
  observation_id: string;
  engagement_id: string;
  scanner: string;
  kind: string;
  subject: string;
  attributes: Record<string, any>;
  artifact_id: string;
  observed_at: string;
}

export interface ObservationListResponse {
  items: ObservationItem[];
  total: number;
  limit: number;
  offset: number;
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
};
