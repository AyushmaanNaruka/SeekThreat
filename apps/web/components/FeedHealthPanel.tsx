"use client";

/**
 * FeedHealthPanel — displays live mirror freshness for all 8 intelligence feeds.
 *
 * Fetches GET /feeds/status from the API and renders a grid of feed cards with:
 * - Freshness badge: "Healthy", "Stale", or "Never synced"
 * - Last synced timestamp (human-readable)
 * - Record count
 * - Not-found cache size
 *
 * Data is NEVER fabricated: if synced_at is null the card shows "Never synced".
 * The panel auto-refreshes every 60 seconds.
 */

import React, { useEffect, useState, useCallback } from "react";
import { API_BASE_URL } from "../lib/api";

// ---------------------------------------------------------------------------
// Types (mirror the backend FeedStatus Pydantic model)
// ---------------------------------------------------------------------------

interface FeedStatus {
  name: string;
  synced_at: string | null;
  record_count: number | null;
  sha256: string | null;
  last_sync_result: string;
  is_stale: boolean;
  not_found_cache_size: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "UTC",
      timeZoneName: "short",
    });
  } catch {
    return iso;
  }
}

function friendlyName(name: string): string {
  const MAP: Record<string, string> = {
    kev: "CISA KEV",
    epss: "FIRST EPSS v4",
    exploitdb: "ExploitDB",
    metasploit: "Metasploit",
    cve_org: "CVE.org",
    vulnrichment: "Vulnrichment",
    euvd: "ENISA EUVD",
    nvd: "NVD 2.0",
  };
  return MAP[name] ?? name;
}

type BadgeVariant = "healthy" | "stale" | "never";

function badge(feed: FeedStatus): BadgeVariant {
  if (!feed.synced_at) return "never";
  if (feed.is_stale) return "stale";
  return "healthy";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const BADGE_STYLES: Record<BadgeVariant, React.CSSProperties> = {
  healthy: {
    background: "rgba(34,197,94,0.18)",
    color: "#4ade80",
    border: "1px solid rgba(34,197,94,0.35)",
  },
  stale: {
    background: "rgba(251,191,36,0.18)",
    color: "#fbbf24",
    border: "1px solid rgba(251,191,36,0.35)",
  },
  never: {
    background: "rgba(148,163,184,0.12)",
    color: "#94a3b8",
    border: "1px solid rgba(148,163,184,0.25)",
  },
};

const BADGE_LABEL: Record<BadgeVariant, string> = {
  healthy: "Healthy",
  stale: "Stale",
  never: "Never synced",
};

function FeedBadge({ variant }: { variant: BadgeVariant }) {
  return (
    <span
      style={{
        ...BADGE_STYLES[variant],
        padding: "2px 10px",
        borderRadius: 99,
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
      }}
    >
      {BADGE_LABEL[variant]}
    </span>
  );
}

function FeedCard({ feed }: { feed: FeedStatus }) {
  const variant = badge(feed);
  const isHealthy = variant === "healthy";

  return (
    <div
      style={{
        background: "rgba(15,23,42,0.75)",
        border: isHealthy
          ? "1px solid rgba(34,197,94,0.2)"
          : variant === "stale"
          ? "1px solid rgba(251,191,36,0.2)"
          : "1px solid rgba(148,163,184,0.12)",
        borderRadius: 12,
        padding: "16px 18px",
        display: "flex",
        flexDirection: "column",
        gap: 10,
        transition: "border-color 0.2s, box-shadow 0.2s",
        boxShadow: isHealthy
          ? "0 0 0 0 transparent"
          : "none",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.boxShadow =
          "0 4px 24px rgba(0,0,0,0.3)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.boxShadow = "none";
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: "#e2e8f0" }}>
          {friendlyName(feed.name)}
        </span>
        <FeedBadge variant={variant} />
      </div>

      {/* Stat rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        <StatRow label="Last synced" value={formatDate(feed.synced_at)} />
        <StatRow
          label="Records"
          value={feed.record_count !== null ? feed.record_count.toLocaleString() : "—"}
        />
        <StatRow
          label="Not-found cache"
          value={feed.not_found_cache_size > 0 ? `${feed.not_found_cache_size} CVEs` : "—"}
        />
        {feed.sha256 && (
          <StatRow
            label="SHA-256"
            value={feed.sha256.slice(0, 12) + "…"}
            mono
          />
        )}
      </div>

      {/* Sync result if not ok */}
      {feed.last_sync_result && feed.last_sync_result !== "ok" && feed.last_sync_result !== "never" && (
        <div
          style={{
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.25)",
            borderRadius: 6,
            padding: "4px 8px",
            fontSize: 11,
            color: "#f87171",
            wordBreak: "break-all",
          }}
        >
          {feed.last_sync_result}
        </div>
      )}
    </div>
  );
}

function StatRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
      <span style={{ color: "#64748b", fontSize: 11, flexShrink: 0 }}>{label}</span>
      <span
        style={{
          color: "#94a3b8",
          fontSize: 11,
          textAlign: "right",
          fontFamily: mono ? "monospace" : undefined,
        }}
      >
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

interface FeedHealthPanelProps {
  /** Auto-refresh interval in ms (default 60 000 — every minute). */
  refreshIntervalMs?: number;
}

export default function FeedHealthPanel({
  refreshIntervalMs = 60_000,
}: FeedHealthPanelProps) {
  const [feeds, setFeeds] = useState<FeedStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/feeds/status`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data: FeedStatus[] = await res.json();
      setFeeds(data);
      setError(null);
      setLastFetched(new Date());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, refreshIntervalMs);
    return () => clearInterval(interval);
  }, [fetchStatus, refreshIntervalMs]);

  // Summary counts
  const healthyCount = feeds?.filter((f) => badge(f) === "healthy").length ?? 0;
  const staleCount = feeds?.filter((f) => badge(f) === "stale").length ?? 0;
  const neverCount = feeds?.filter((f) => badge(f) === "never").length ?? 0;

  return (
    <section
      id="feed-health-panel"
      style={{
        background: "rgba(7,14,34,0.85)",
        border: "1px solid rgba(100,116,139,0.2)",
        borderRadius: 16,
        padding: "20px 24px",
        fontFamily:
          "'Inter', 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif",
      }}
    >
      {/* Panel header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 16,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 16 }}>📡</span>
          <h2
            style={{
              margin: 0,
              fontSize: 14,
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "0.02em",
            }}
          >
            Feed Health
          </h2>
          {feeds && (
            <div style={{ display: "flex", gap: 6, marginLeft: 8 }}>
              {healthyCount > 0 && (
                <span
                  style={{
                    ...BADGE_STYLES.healthy,
                    padding: "1px 8px",
                    borderRadius: 99,
                    fontSize: 11,
                    fontWeight: 600,
                  }}
                >
                  {healthyCount} ok
                </span>
              )}
              {staleCount > 0 && (
                <span
                  style={{
                    ...BADGE_STYLES.stale,
                    padding: "1px 8px",
                    borderRadius: 99,
                    fontSize: 11,
                    fontWeight: 600,
                  }}
                >
                  {staleCount} stale
                </span>
              )}
              {neverCount > 0 && (
                <span
                  style={{
                    ...BADGE_STYLES.never,
                    padding: "1px 8px",
                    borderRadius: 99,
                    fontSize: 11,
                    fontWeight: 600,
                  }}
                >
                  {neverCount} never
                </span>
              )}
            </div>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {lastFetched && (
            <span style={{ color: "#475569", fontSize: 10 }}>
              Updated {lastFetched.toLocaleTimeString("en-GB")}
            </span>
          )}
          <button
            id="feed-health-refresh-btn"
            onClick={fetchStatus}
            disabled={loading}
            style={{
              background: "rgba(100,116,139,0.15)",
              border: "1px solid rgba(100,116,139,0.25)",
              borderRadius: 8,
              padding: "4px 12px",
              color: "#94a3b8",
              fontSize: 11,
              cursor: loading ? "not-allowed" : "pointer",
              transition: "background 0.15s",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background =
                "rgba(100,116,139,0.25)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background =
                "rgba(100,116,139,0.15)";
            }}
          >
            {loading ? "Loading…" : "↻ Refresh"}
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          style={{
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.2)",
            borderRadius: 8,
            padding: "10px 14px",
            color: "#f87171",
            fontSize: 12,
            marginBottom: 14,
          }}
        >
          ⚠ Could not fetch feed status: {error}
        </div>
      )}

      {/* Loading skeleton */}
      {loading && !feeds && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
            gap: 10,
          }}
        >
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              style={{
                background: "rgba(15,23,42,0.5)",
                border: "1px solid rgba(148,163,184,0.08)",
                borderRadius: 12,
                height: 110,
                animation: "pulse 1.5s ease-in-out infinite",
              }}
            />
          ))}
        </div>
      )}

      {/* Feed grid */}
      {feeds && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
            gap: 10,
          }}
        >
          {feeds.map((feed) => (
            <FeedCard key={feed.name} feed={feed} />
          ))}
        </div>
      )}

      {/* Footer note */}
      <p
        style={{
          margin: "14px 0 0",
          color: "#334155",
          fontSize: 10,
          textAlign: "right",
        }}
      >
        Source: <code>/feeds/status</code> · Data from .meta.json sidecars only · Auto-refreshes
        every {refreshIntervalMs / 1000}s
      </p>
    </section>
  );
}
