"use client";

import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { api, ApiError, API_BASE_URL, EngagementItem } from "../lib/api";
import {
  EnrichedFindingItem,
  ProvenanceInfo,
  ProvenanceSource,
  ConfidenceLevel,
  getErsSeverityBand,
  ersHasDerivedInputs,
  isDerived,
  distinctSources,
  formatCvss,
  formatEpss,
  MISSING_VALUE,
} from "../lib/findings";

interface EnrichedFindingsViewProps {
  activeEngagement: EngagementItem | null;
  onSelectEngagementPrompt?: () => void;
}

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNSCORED";
type SortField = "ERS" | "CVSS" | "EPSS" | "CVE";
type SortOrder = "asc" | "desc";

const PAGE_SIZE = 100;

const ESTIMATE_LABEL = "estimate, not measured";
const MUTED = "#7B8A8D";

// ERS band thresholds (8 / 6 / 4) are a UI display convention defined in
// lib/findings.ts. The backend defines no ERS severity bands and the cut-offs
// are not calibrated against measured outcomes.
const BAND_TOOLTIP =
  "ERS band thresholds (8 / 6 / 4) are a UI display convention, not a backend-defined or calibrated severity scale.";

const SEVERITY_BUTTONS: ReadonlyArray<{ id: SeverityFilter; label: string; color: string }> = [
  { id: "ALL", label: "All", color: "#F5F7F8" },
  { id: "CRITICAL", label: "Critical (≥8)", color: "#FF3838" },
  { id: "HIGH", label: "High (≥6)", color: "#FF7A00" },
  { id: "MEDIUM", label: "Medium (≥4)", color: "#FFC312" },
  { id: "LOW", label: "Low (<4)", color: "#20D6A3" },
  { id: "UNSCORED", label: "Not scored", color: "#A7B2B5" },
];

function describeFindingsError(err: unknown, engagementId: string): string {
  if (err instanceof ApiError) {
    if (err.status === 404) {
      return `Engagement '${engagementId}' was not found.`;
    }
    if (err.status === 422) {
      return `The API rejected the findings request (422): ${err.message}`;
    }
    if (err.status === 503) {
      return "The findings service is temporarily unavailable (503). Try again shortly.";
    }
    return `Failed to load enriched findings (HTTP ${err.status}): ${err.message}`;
  }
  if (err instanceof TypeError) {
    // fetch() rejects with TypeError on network failure / CORS / DNS errors.
    return `Could not reach the SeekThreat API at ${API_BASE_URL}. Check that the backend is running.`;
  }
  if (err instanceof Error) {
    // e.g. normalization rejected a malformed record rather than inventing data.
    return `Could not display enriched findings: ${err.message}`;
  }
  return String(err);
}

function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

/** Compare two nullable numbers; nulls always sort last regardless of order. */
function compareNullable(a: number | null | undefined, b: number | null | undefined, order: SortOrder): number {
  const aMissing = a === null || a === undefined;
  const bMissing = b === null || b === undefined;
  if (aMissing && bMissing) return 0;
  if (aMissing) return 1;
  if (bMissing) return -1;
  return order === "asc" ? a - b : b - a;
}

function EstimateTag({ label = ESTIMATE_LABEL, title }: { label?: string; title?: string | null }) {
  return (
    <span
      title={title ?? "Backend placeholder (source: derived). Not a measurement."}
      style={{
        fontSize: "0.62rem",
        fontWeight: 500,
        fontStyle: "italic",
        padding: "0.1rem 0.4rem",
        borderRadius: "4px",
        border: "1px dashed rgba(131, 149, 167, 0.45)",
        color: MUTED,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

export default function EnrichedFindingsView({
  activeEngagement,
  onSelectEngagementPrompt,
}: EnrichedFindingsViewProps) {
  const [findings, setFindings] = useState<EnrichedFindingItem[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [sortField, setSortField] = useState<SortField>("ERS");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const engagementId = activeEngagement?.engagement_id;

  // Stale-response guard: every request gets an id; only the latest may commit.
  const requestIdRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  const loadPage = useCallback(
    async (offset: number, append: boolean) => {
      if (!engagementId) return;
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      const requestId = ++requestIdRef.current;

      if (append) setLoadingMore(true);
      else setLoading(true);
      setError(null);

      try {
        const resp = await api.getFindings(engagementId, PAGE_SIZE, offset, controller.signal);
        if (requestId !== requestIdRef.current) return;
        setFindings((prev) => (append ? [...prev, ...resp.items] : resp.items));
        setTotal(resp.total);
      } catch (err: unknown) {
        if (requestId !== requestIdRef.current || isAbortError(err)) return;
        setError(describeFindingsError(err, engagementId));
        if (!append) {
          setFindings([]);
          setTotal(null);
        }
      } finally {
        if (requestId === requestIdRef.current) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [engagementId]
  );

  useEffect(() => {
    // Engagement changed: drop everything belonging to the previous one.
    setFindings([]);
    setTotal(null);
    setExpandedFindingId(null);
    setError(null);
    if (!engagementId) {
      setLoading(false);
      setLoadingMore(false);
      return;
    }
    void loadPage(0, false);
    return () => {
      abortRef.current?.abort();
      requestIdRef.current += 1;
    };
  }, [engagementId, loadPage]);

  const sources = useMemo(() => distinctSources(findings), [findings]);

  const filteredFindings = useMemo(() => {
    return findings
      .filter((item) => {
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const haystack = [
            item.cve_ids.join(" "),
            item.finding_id,
            item.title,
            item.description?.value ?? "",
            (item.cwe_ids?.value ?? []).join(" "),
          ]
            .join(" ")
            .toLowerCase();
          if (!haystack.includes(q)) return false;
        }
        if (severityFilter !== "ALL") {
          const band = getErsSeverityBand(item.ers?.score ?? null).band.toUpperCase();
          if (band !== severityFilter) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortField === "ERS") return compareNullable(a.ers?.score, b.ers?.score, sortOrder);
        if (sortField === "CVSS") return compareNullable(a.cvss?.value, b.cvss?.value, sortOrder);
        if (sortField === "EPSS") return compareNullable(a.epss?.value, b.epss?.value, sortOrder);
        const ca = a.cve_id ?? "";
        const cb = b.cve_id ?? "";
        return sortOrder === "asc" ? ca.localeCompare(cb) : cb.localeCompare(ca);
      });
  }, [findings, searchQuery, severityFilter, sortField, sortOrder]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  const sortArrow = (field: SortField) =>
    sortField === field ? (sortOrder === "asc" ? " ▲" : " ▼") : null;

  const hasMore = total !== null && findings.length < total;
  const filtersActive = searchQuery.trim() !== "" || severityFilter !== "ALL";

  if (!activeEngagement) {
    return (
      <div className="db-empty-state" style={{ padding: "4rem 2rem", textAlign: "center" }}>
        <div
          style={{
            width: "56px",
            height: "56px",
            borderRadius: "14px",
            background: "rgba(216, 170, 69, 0.12)",
            border: "1px solid rgba(216, 170, 69, 0.3)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 1.25rem",
          }}
        >
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#D8AA45" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <h2 style={{ fontSize: "1.35rem", fontWeight: 700, color: "#F5F7F8", marginBottom: "0.5rem" }}>
          Engagement Scope Required
        </h2>
        <p style={{ maxWidth: "480px", margin: "0 auto 1.5rem", color: "#A7B2B5", fontSize: "0.9rem", lineHeight: 1.6 }}>
          Per SeekThreat authorization constraints (CLAUDE.md & D-032), all vulnerability findings and
          threat intelligence lookups must be scoped to an authorized engagement record.
        </p>
        {onSelectEngagementPrompt && (
          <button
            onClick={onSelectEngagementPrompt}
            className="db-btn db-btn-primary"
            style={{ margin: "0 auto" }}
          >
            Select or Create Engagement
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="db-findings-container">
      {/* Header controls & stats */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.25rem" }}>
            <h2 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#F5F7F8", margin: 0 }}>
              Enriched Findings
            </h2>
            <span
              style={{
                background: "rgba(32, 214, 163, 0.15)",
                border: "1px solid rgba(32, 214, 163, 0.3)",
                color: "#20D6A3",
                fontSize: "0.75rem",
                fontWeight: 700,
                padding: "0.15rem 0.6rem",
                borderRadius: "12px",
              }}
            >
              {total !== null ? `Showing ${findings.length} of ${total}` : `${findings.length} loaded`}
            </span>
          </div>
          <span style={{ fontSize: "0.85rem", color: "#A7B2B5" }}>
            {sources.length > 0
              ? `Per-field provenance from ${sources.length} attributed source${
                  sources.length === 1 ? "" : "s"
                } in the loaded findings (${sources.join(", ")}).`
              : "Per-field provenance and Exposure Risk Scores for enriched findings."}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <button
            type="button"
            onClick={() => void loadPage(0, false)}
            disabled={loading}
            className="db-card-action-btn"
            style={{ height: "34px", padding: "0 0.85rem" }}
          >
            <span>{loading ? "Refreshing..." : "Refresh"}</span>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="23 4 23 10 17 10" />
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
            </svg>
          </button>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          style={{
            background: "rgba(228, 93, 104, 0.12)",
            border: "1px solid rgba(228, 93, 104, 0.3)",
            color: "#E45D68",
            padding: "0.75rem 1rem",
            borderRadius: "8px",
            fontSize: "0.85rem",
            marginBottom: "1rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "1rem",
          }}
        >
          <span>{error}</span>
          <button
            type="button"
            aria-label="Dismiss error"
            onClick={() => setError(null)}
            style={{ background: "none", border: "none", color: "#E45D68", cursor: "pointer" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div
        style={{
          background: "#0B1012",
          border: "1px solid rgba(217, 226, 229, 0.18)",
          borderRadius: "12px",
          padding: "0.85rem 1.15rem",
          display: "flex",
          flexWrap: "wrap",
          gap: "1rem",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "1.25rem",
        }}
      >
        <div style={{ position: "relative", flex: "1 1 240px", maxWidth: "380px" }}>
          <svg
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#7B8A8D"
            strokeWidth="2"
            style={{ position: "absolute", left: "0.85rem", top: "50%", transform: "translateY(-50%)" }}
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search CVE ID, title, CWE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              background: "rgba(255, 255, 255, 0.04)",
              border: "1px solid rgba(217, 226, 229, 0.18)",
              borderRadius: "8px",
              padding: "0.5rem 0.85rem 0.5rem 2.3rem",
              color: "#F5F7F8",
              fontSize: "0.85rem",
              outline: "none",
            }}
          />
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", flexWrap: "wrap" }}>
          <span
            title={BAND_TOOLTIP}
            style={{ fontSize: "0.75rem", color: "#A7B2B5", textTransform: "uppercase", letterSpacing: "0.05em" }}
          >
            ERS band:
          </span>
          {SEVERITY_BUTTONS.map((b) => {
            const active = severityFilter === b.id;
            return (
              <button
                key={b.id}
                type="button"
                title={b.id === "UNSCORED" ? "Findings the backend did not score" : BAND_TOOLTIP}
                onClick={() => setSeverityFilter(b.id)}
                style={{
                  background: active ? "rgba(255, 255, 255, 0.15)" : "rgba(255, 255, 255, 0.03)",
                  border: active ? `1px solid ${b.color}` : "1px solid rgba(217, 226, 229, 0.12)",
                  color: active ? b.color : "#A7B2B5",
                  padding: "0.35rem 0.65rem",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  fontWeight: active ? 700 : 500,
                  cursor: "pointer",
                  transition: "all 0.15s ease",
                }}
              >
                {b.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Table */}
      {filteredFindings.length === 0 ? (
        <div className="db-card" style={{ padding: "3rem 2rem", textAlign: "center" }}>
          <div className="db-empty-state">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#667276" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <div className="db-empty-state-title" style={{ marginTop: "1rem" }}>
              {loading
                ? "Loading enriched findings…"
                : filtersActive && findings.length > 0
                ? "No loaded findings match the active filters"
                : error
                ? "Enriched findings could not be loaded"
                : "No enriched findings for this engagement yet"}
            </div>
            {!loading && filtersActive && findings.length > 0 && (
              <div className="db-empty-state-desc" style={{ maxWidth: "460px", margin: "0.5rem auto 0" }}>
                Try clearing your search query or selecting a different ERS band.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="db-card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="db-table-container" style={{ margin: 0 }}>
            <table className="db-table">
              <thead>
                <tr>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("CVE")}>
                    Vulnerability / CVE{sortArrow("CVE")}
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("CVSS")}>
                    CVSS Score{sortArrow("CVSS")}
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("EPSS")}>
                    EPSS Probability{sortArrow("EPSS")}
                  </th>
                  <th>CISA KEV Status</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("ERS")} title={BAND_TOOLTIP}>
                    Exposure Risk Score (ERS){sortArrow("ERS")}
                  </th>
                  <th style={{ width: "50px", textAlign: "center" }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((item) => {
                  const isExpanded = expandedFindingId === item.finding_id;
                  const ersScore = item.ers?.score ?? null;
                  const severity = getErsSeverityBand(ersScore);
                  const ersEstimated = ersHasDerivedInputs(item.ers);
                  const cvssVal = item.cvss?.value ?? null;
                  const epssVal = item.epss?.value ?? null;
                  const inKevVal = item.in_kev?.value ?? null;
                  const cvssDerived = isDerived(item.cvss);
                  const epssDerived = isDerived(item.epss);
                  const cweDerived = isDerived(item.cwe_ids);
                  const firstCwe = item.cwe_ids?.value[0];

                  return (
                    <React.Fragment key={item.finding_id}>
                      <tr
                        style={{
                          background: isExpanded ? "rgba(255, 255, 255, 0.03)" : undefined,
                          cursor: "pointer",
                          borderBottom: isExpanded ? "none" : undefined,
                        }}
                        onClick={() => setExpandedFindingId(isExpanded ? null : item.finding_id)}
                      >
                        <td>
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                              <span
                                style={{
                                  fontWeight: 700,
                                  color: item.cve_id ? "#F5F7F8" : MUTED,
                                  fontFamily: "monospace",
                                  fontSize: "0.88rem",
                                }}
                              >
                                {item.cve_id ?? "No CVE"}
                              </span>
                              {firstCwe && (
                                <span
                                  title={item.cwe_ids?.provenance.note ?? undefined}
                                  style={{
                                    fontSize: "0.7rem",
                                    padding: "0.1rem 0.4rem",
                                    borderRadius: "4px",
                                    background: cweDerived ? "transparent" : "rgba(217, 226, 229, 0.08)",
                                    border: cweDerived ? "1px dashed rgba(131, 149, 167, 0.45)" : "none",
                                    color: cweDerived ? MUTED : "#A7B2B5",
                                    fontStyle: cweDerived ? "italic" : "normal",
                                  }}
                                >
                                  {firstCwe}
                                </span>
                              )}
                              {cweDerived && <EstimateTag title={item.cwe_ids?.provenance.note} />}
                            </div>
                            <div
                              style={{
                                fontSize: "0.75rem",
                                color: "#A7B2B5",
                                marginTop: "0.2rem",
                                maxWidth: "320px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                              title={item.description?.value || item.title || item.finding_id}
                            >
                              {item.description?.value || item.title || item.finding_id}
                            </div>
                          </div>
                        </td>

                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                            <span
                              title={item.cvss?.provenance.note ?? undefined}
                              style={{
                                fontWeight: cvssDerived ? 500 : 800,
                                fontStyle: cvssDerived ? "italic" : "normal",
                                fontSize: "0.95rem",
                                color:
                                  cvssVal === null || cvssDerived
                                    ? MUTED
                                    : cvssVal >= 9.0
                                    ? "#FF3838"
                                    : cvssVal >= 7.0
                                    ? "#FF7A00"
                                    : cvssVal >= 4.0
                                    ? "#FFC312"
                                    : "#20D6A3",
                              }}
                            >
                              {formatCvss(cvssVal)}
                            </span>
                            {item.cvss &&
                              (cvssDerived ? (
                                <EstimateTag title={item.cvss.provenance.note} />
                              ) : (
                                <span
                                  title={`Retrieved: ${item.cvss.provenance.retrieved_at}${
                                    item.cvss.provenance.note ? ` | ${item.cvss.provenance.note}` : ""
                                  }`}
                                  style={{
                                    fontSize: "0.65rem",
                                    fontWeight: 600,
                                    textTransform: "uppercase",
                                    padding: "0.15rem 0.45rem",
                                    borderRadius: "4px",
                                    background: "rgba(0, 210, 211, 0.15)",
                                    border: "1px solid #00D2D3",
                                    color: "#55D6E8",
                                  }}
                                >
                                  {item.cvss.provenance.source}
                                </span>
                              ))}
                          </div>
                        </td>

                        <td>
                          <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", minWidth: "110px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem" }}>
                              <span
                                title={item.epss?.provenance.note ?? undefined}
                                style={{
                                  fontWeight: epssDerived ? 500 : 700,
                                  fontStyle: epssDerived ? "italic" : "normal",
                                  color: epssVal === null || epssDerived ? MUTED : "#F5F7F8",
                                }}
                              >
                                {formatEpss(epssVal)}
                              </span>
                              {item.epss &&
                                (epssDerived ? (
                                  <EstimateTag title={item.epss.provenance.note} />
                                ) : (
                                  <span style={{ fontSize: "0.65rem", color: "#20D6A3" }}>
                                    {item.epss.provenance.source}
                                  </span>
                                ))}
                            </div>
                            {epssVal !== null && !epssDerived && (
                              <div
                                style={{
                                  width: "100%",
                                  height: "4px",
                                  background: "rgba(255, 255, 255, 0.08)",
                                  borderRadius: "2px",
                                  overflow: "hidden",
                                }}
                              >
                                <div
                                  style={{
                                    width: `${Math.min(100, epssVal * 100)}%`,
                                    height: "100%",
                                    background: epssVal > 0.5 ? "#FF3838" : epssVal > 0.2 ? "#FF7A00" : "#20D6A3",
                                    borderRadius: "2px",
                                  }}
                                />
                              </div>
                            )}
                          </div>
                        </td>

                        <td>
                          {inKevVal === true ? (
                            <span
                              title={item.in_kev?.provenance.note ?? undefined}
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "0.35rem",
                                background: "rgba(255, 56, 56, 0.18)",
                                border: "1px solid #FF3838",
                                color: "#FF3838",
                                padding: "0.25rem 0.6rem",
                                borderRadius: "12px",
                                fontSize: "0.75rem",
                                fontWeight: 700,
                              }}
                            >
                              <span
                                style={{
                                  width: "6px",
                                  height: "6px",
                                  borderRadius: "50%",
                                  background: "#FF3838",
                                  boxShadow: "0 0 6px #FF3838",
                                }}
                              />
                              Active Exploitation
                            </span>
                          ) : inKevVal === false ? (
                            <span
                              title={item.in_kev?.provenance.note ?? undefined}
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "0.35rem",
                                background: "rgba(32, 214, 163, 0.08)",
                                border: "1px solid rgba(32, 214, 163, 0.25)",
                                color: "#20D6A3",
                                padding: "0.25rem 0.6rem",
                                borderRadius: "12px",
                                fontSize: "0.75rem",
                                fontWeight: 500,
                              }}
                            >
                              Not in KEV
                            </span>
                          ) : (
                            <span
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                background: "rgba(131, 149, 167, 0.1)",
                                border: "1px dashed rgba(131, 149, 167, 0.35)",
                                color: "#A7B2B5",
                                padding: "0.25rem 0.6rem",
                                borderRadius: "12px",
                                fontSize: "0.72rem",
                              }}
                              title={item.in_kev?.provenance.note ?? "KEV status unknown"}
                            >
                              Unknown
                            </span>
                          )}
                        </td>

                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
                            {ersScore === null ? (
                              <span
                                title="The backend did not compute an Exposure Risk Score for this finding."
                                style={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  background: severity.bg,
                                  border: `1px dashed ${severity.border}`,
                                  color: severity.color,
                                  padding: "0.25rem 0.6rem",
                                  borderRadius: "6px",
                                  fontSize: "0.75rem",
                                  fontWeight: 500,
                                }}
                              >
                                Not scored
                              </span>
                            ) : (
                              <>
                                <div
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    width: "42px",
                                    height: "28px",
                                    borderRadius: "6px",
                                    background: "rgba(255, 255, 255, 0.06)",
                                    border: `1px solid ${severity.color}`,
                                    color: severity.color,
                                    fontWeight: 800,
                                    fontSize: "0.95rem",
                                  }}
                                >
                                  {ersScore.toFixed(1)}
                                </div>
                                <span
                                  title={BAND_TOOLTIP}
                                  style={{ fontSize: "0.75rem", fontWeight: 600, color: severity.color }}
                                >
                                  {severity.label}
                                </span>
                                {ersEstimated && (
                                  <EstimateTag
                                    label="includes estimated inputs"
                                    title="At least one ERS component used a derived placeholder input, not a measurement."
                                  />
                                )}
                              </>
                            )}
                          </div>
                        </td>

                        <td style={{ textAlign: "center" }}>
                          <button
                            type="button"
                            className="db-more-btn"
                            aria-label={isExpanded ? "Collapse details" : "Expand details"}
                            style={{
                              transform: isExpanded ? "rotate(180deg)" : "none",
                              transition: "transform 0.2s ease",
                            }}
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polyline points="6 9 12 15 18 9" />
                            </svg>
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr key={`${item.finding_id}-expanded`} style={{ background: "var(--surface-sunken, #080c14)" }}>
                          <td colSpan={6} style={{ padding: "1.25rem 1.5rem", borderBottom: "1px solid var(--border, #1f293d)" }}>
                            <FindingDetails item={item} engagementName={activeEngagement.name} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Pagination */}
      {findings.length > 0 && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "1rem",
            fontSize: "0.8rem",
            color: "#A7B2B5",
            flexWrap: "wrap",
            gap: "0.75rem",
          }}
        >
          <span>
            {total !== null ? `Showing ${findings.length} of ${total} findings` : `${findings.length} findings loaded`}
            {filtersActive && ` (${filteredFindings.length} match the active filters)`}
          </span>
          {hasMore && (
            <button
              type="button"
              className="db-card-action-btn"
              disabled={loadingMore || loading}
              onClick={() => void loadPage(findings.length, true)}
              style={{ height: "34px", padding: "0 0.85rem" }}
            >
              {loadingMore ? "Loading…" : `Load ${Math.min(PAGE_SIZE, (total ?? 0) - findings.length)} more`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expanded row: ERS breakdown + per-field provenance
// ---------------------------------------------------------------------------

function FindingDetails({ item, engagementName }: { item: EnrichedFindingItem; engagementName: string }) {
  const ers = item.ers;
  const severity = getErsSeverityBand(ers?.score ?? null);
  const ersEstimated = ersHasDerivedInputs(ers);

  const epssValue =
    item.epss?.value != null
      ? `${formatEpss(item.epss.value, 2)}${
          item.epss_percentile?.value != null && !isDerived(item.epss_percentile)
            ? ` (${(item.epss_percentile.value * 100).toFixed(1)}th percentile)`
            : ""
        }`
      : MISSING_VALUE;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* ERS Component Breakdown */}
      <div
        style={{
          background: "var(--surface-elevated, #111827)",
          border: "1px solid var(--border, #1f293d)",
          borderRadius: "8px",
          padding: "1.25rem",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.75rem" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
              <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
                Exposure Risk Score (ERS) Breakdown
              </h4>
              <span
                title={ers ? BAND_TOOLTIP : undefined}
                style={{
                  fontSize: "0.7rem",
                  padding: "2px 8px",
                  borderRadius: "12px",
                  background: severity.bg,
                  color: severity.color,
                  border: `1px solid ${severity.border}`,
                  fontWeight: 600,
                }}
              >
                {ers ? `Composite: ${ers.score.toFixed(2)} / 10.0 (${severity.label})` : "Not scored"}
              </span>
              {ersEstimated && <EstimateTag label="includes estimated inputs" />}
            </div>
            {ers && (
              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.8rem", color: "var(--text-muted, #9ca3af)" }}>
                Additive weighted sum of the components below, as computed by the backend.
              </p>
            )}
          </div>

          {ers && (
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", fontSize: "0.75rem", color: "var(--text-secondary, #d1d5db)" }}>
              <span>
                Formula:{" "}
                <code style={{ color: "var(--accent, #6366f1)", background: "rgba(99, 102, 241, 0.1)", padding: "2px 6px", borderRadius: "4px" }}>
                  ERS = Σ(wᵢ × cᵢ)
                </code>
              </span>
            </div>
          )}
        </div>

        {ers && ers.components.length > 0 ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "0.75rem" }}>
            {ers.components.map((comp, idx) => {
              const compDerived = comp.provenance.source === "derived";
              const pct = Math.min(100, Math.max(0, (comp.value / 10.0) * 100));

              return (
                <div
                  key={`${comp.name}-${idx}`}
                  style={{
                    padding: "0.875rem",
                    borderRadius: "6px",
                    background: "var(--surface-sunken, #080c14)",
                    border: compDerived ? "1px dashed rgba(131, 149, 167, 0.45)" : "1px solid var(--border, #1f293d)",
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.5rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                      <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
                        {comp.name}
                      </span>
                      <div style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)" }}>
                        Weight: {(comp.weight * 100).toFixed(0)}%
                      </div>
                    </div>

                    <div style={{ textAlign: "right" }}>
                      <span
                        style={{
                          fontSize: "0.9rem",
                          fontWeight: 700,
                          fontStyle: compDerived ? "italic" : "normal",
                          color: compDerived ? MUTED : "var(--accent, #6366f1)",
                        }}
                      >
                        {comp.value.toFixed(2)}
                      </span>
                      <span style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)" }}> / 10</span>
                    </div>
                  </div>

                  <div
                    style={{
                      height: "6px",
                      width: "100%",
                      background: "rgba(255, 255, 255, 0.08)",
                      borderRadius: "3px",
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        height: "100%",
                        width: `${pct}%`,
                        background: compDerived ? MUTED : "linear-gradient(90deg, #6366f1, #a855f7)",
                        borderRadius: "3px",
                      }}
                    />
                  </div>

                  {/* Backend-rendered explanation: every score explains itself. */}
                  <p style={{ margin: 0, fontSize: "0.75rem", lineHeight: 1.45, color: "var(--text-secondary, #d1d5db)" }}>
                    {comp.explanation}
                  </p>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.7rem", gap: "0.5rem", flexWrap: "wrap" }}>
                    <span style={{ color: "var(--text-muted, #9ca3af)" }}>
                      Weighted: <strong style={{ color: "var(--text-primary, #f9fafb)" }}>{comp.weighted_value.toFixed(2)}</strong>
                    </span>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem" }}>
                      {compDerived && <EstimateTag title={comp.provenance.note} />}
                      <span style={{ color: "var(--text-muted, #9ca3af)" }}>
                        {comp.provenance.source} ·{" "}
                        <span style={{ color: CONFIDENCE_COLORS[comp.provenance.confidence] }}>
                          {comp.provenance.confidence}
                        </span>
                      </span>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted, #9ca3af)", fontStyle: "italic", padding: "0.5rem 0" }}>
            No Exposure Risk Score was computed for this finding, so there is no breakdown to show.
          </div>
        )}
      </div>

      {/* Per-Field Provenance & Lineage */}
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.875rem" }}>
          <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
            Field Provenance & Lineage
          </h4>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "0.875rem" }}>
          <FieldProvenanceCard
            label="CVSS Base Severity"
            value={item.cvss?.value != null ? `${formatCvss(item.cvss.value)} / 10.0` : MISSING_VALUE}
            provenance={item.cvss?.provenance}
          />
          <FieldProvenanceCard
            label="EPSS Exploit Likelihood"
            value={epssValue}
            provenance={item.epss?.provenance}
          />
          <FieldProvenanceCard
            label="CISA KEV Catalog"
            value={
              item.in_kev?.value === true
                ? "Actively exploited (listed in CISA KEV)"
                : item.in_kev?.value === false
                ? "Not listed in CISA KEV"
                : "Unknown"
            }
            provenance={item.in_kev?.provenance}
            highlight={item.in_kev?.value === true ? "danger" : "neutral"}
            derivedLabel={item.in_kev?.value == null ? "unknown, not measured" : undefined}
          />
          <FieldProvenanceCard
            label="CWE Weakness Types"
            value={item.cwe_ids && item.cwe_ids.value.length > 0 ? item.cwe_ids.value.join(", ") : MISSING_VALUE}
            provenance={item.cwe_ids?.provenance}
          />
          {item.ransomware_use && (
            <FieldProvenanceCard
              label="Known Ransomware Campaign Use"
              value={item.ransomware_use.value ?? MISSING_VALUE}
              provenance={item.ransomware_use.provenance}
              highlight="danger"
            />
          )}
          {item.has_public_exploit && (
            <FieldProvenanceCard
              label="Public Exploit (ExploitDB)"
              value={
                item.has_public_exploit.value === true
                  ? `Listed${item.exploit_ids?.value.length ? `: EDB ${item.exploit_ids.value.join(", ")}` : ""}`
                  : item.has_public_exploit.value === false
                  ? "Not listed"
                  : "Unknown"
              }
              provenance={item.has_public_exploit.provenance}
              highlight={item.has_public_exploit.value === true ? "danger" : "neutral"}
              derivedLabel={item.has_public_exploit.value == null ? "unknown, not measured" : undefined}
            />
          )}
          {item.has_metasploit_module && (
            <FieldProvenanceCard
              label="Metasploit Module"
              value={
                item.has_metasploit_module.value === true
                  ? `Available${
                      item.metasploit_modules?.value.length ? `: ${item.metasploit_modules.value.join(", ")}` : ""
                    }`
                  : item.has_metasploit_module.value === false
                  ? "Not listed"
                  : "Unknown"
              }
              provenance={item.has_metasploit_module.provenance}
              highlight={item.has_metasploit_module.value === true ? "danger" : "neutral"}
              derivedLabel={item.has_metasploit_module.value == null ? "unknown, not measured" : undefined}
            />
          )}
          <FieldProvenanceCard
            label="Vulnerability Description & Summary"
            value={item.description?.value || MISSING_VALUE}
            provenance={item.description?.provenance}
            isLongText
          />
        </div>
      </div>

      {/* Asset & Target Context */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0.75rem 1rem",
          borderRadius: "6px",
          background: "rgba(255, 255, 255, 0.02)",
          border: "1px solid var(--border, #1f293d)",
          fontSize: "0.75rem",
          color: "var(--text-muted, #9ca3af)",
          flexWrap: "wrap",
          gap: "0.5rem",
        }}
      >
        <div>
          CVEs: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{item.cve_ids.length ? item.cve_ids.join(", ") : MISSING_VALUE}</code>
          <span> | Asset: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{item.asset_id || MISSING_VALUE}</code></span>
          <span> | Scanner: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{item.scanner || MISSING_VALUE}</code></span>
          <span> | Scope: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{engagementName}</code></span>
        </div>
        <div>
          Finding ID: <code style={{ fontSize: "0.7rem" }}>{item.finding_id}</code>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: FieldProvenanceCard
// ---------------------------------------------------------------------------

const CONFIDENCE_COLORS: Record<ConfidenceLevel, string> = {
  high: "#34d399",
  medium: "#fbbf24",
  low: "#f87171",
};

interface BadgeStyle {
  bg: string;
  color: string;
  border: string;
}

const ADVISORY_BADGE: BadgeStyle = { bg: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", border: "rgba(59, 130, 246, 0.4)" };
const EXPLOIT_BADGE: BadgeStyle = { bg: "rgba(249, 115, 22, 0.15)", color: "#fb923c", border: "rgba(249, 115, 22, 0.4)" };
const NEUTRAL_BADGE: BadgeStyle = { bg: "rgba(107, 114, 128, 0.15)", color: "#9ca3af", border: "#4b5563" };

/** Exact-match badge styling per backend `Source` value. */
const SOURCE_BADGES: Record<ProvenanceSource, BadgeStyle> = {
  "cve.org": ADVISORY_BADGE,
  nvd: ADVISORY_BADGE,
  "enisa.euvd": ADVISORY_BADGE,
  "osv.dev": ADVISORY_BADGE,
  "github.advisories": ADVISORY_BADGE,
  "cisa.vulnrichment": { bg: "rgba(168, 85, 247, 0.15)", color: "#c084fc", border: "rgba(168, 85, 247, 0.4)" },
  "first.epss": { bg: "rgba(14, 165, 233, 0.15)", color: "#38bdf8", border: "rgba(14, 165, 233, 0.4)" },
  "cisa.kev": { bg: "rgba(239, 68, 68, 0.15)", color: "#f87171", border: "rgba(239, 68, 68, 0.4)" },
  exploitdb: EXPLOIT_BADGE,
  metasploit: EXPLOIT_BADGE,
  bron: NEUTRAL_BADGE,
  scanner: NEUTRAL_BADGE,
  derived: { bg: "transparent", color: MUTED, border: "rgba(131, 149, 167, 0.45)" },
};

interface FieldProvenanceCardProps {
  label: string;
  value: string;
  provenance?: ProvenanceInfo | null;
  highlight?: "danger" | "neutral";
  isLongText?: boolean;
  /** Label shown for derived values; defaults to "estimate, not measured". */
  derivedLabel?: string;
}

export function FieldProvenanceCard({
  label,
  value,
  provenance,
  highlight = "neutral",
  isLongText = false,
  derivedLabel = ESTIMATE_LABEL,
}: FieldProvenanceCardProps) {
  const derived = provenance?.source === "derived";
  const badge = provenance ? SOURCE_BADGES[provenance.source] : NEUTRAL_BADGE;

  const formattedTime =
    provenance && !derived
      ? new Date(provenance.retrieved_at).toLocaleString(undefined, {
          month: "short",
          day: "numeric",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        })
      : null;

  return (
    <div
      style={{
        background: "var(--surface, #1e2640)",
        border: derived ? "1px dashed rgba(131, 149, 167, 0.45)" : "1px solid var(--border, #1f293d)",
        borderRadius: "6px",
        padding: "0.875rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
        gridColumn: isLongText ? "1 / -1" : undefined,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem" }}>
        <span style={{ color: "var(--text-muted, #9ca3af)", fontSize: "0.75rem", fontWeight: 500 }}>{label}</span>

        <span
          title={provenance ? `Attributed source: ${provenance.source}` : "No source reported this field"}
          style={{
            fontSize: "0.68rem",
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.03em",
            padding: "2px 7px",
            borderRadius: "4px",
            background: badge.bg,
            color: badge.color,
            border: `1px ${derived ? "dashed" : "solid"} ${badge.border}`,
          }}
        >
          {provenance ? provenance.source : "not reported"}
        </span>
      </div>

      <div
        style={{
          fontSize: isLongText ? "0.8rem" : "0.875rem",
          fontWeight: isLongText || derived ? 400 : 600,
          fontStyle: derived ? "italic" : "normal",
          color: derived
            ? MUTED
            : highlight === "danger"
            ? "#f87171"
            : "var(--text-primary, #f9fafb)",
          lineHeight: 1.45,
          maxHeight: isLongText ? "80px" : undefined,
          overflowY: isLongText ? "auto" : undefined,
          display: "flex",
          alignItems: "center",
          gap: "0.4rem",
          flexWrap: "wrap",
        }}
      >
        <span>{value}</span>
        {derived && <EstimateTag label={derivedLabel} />}
      </div>

      {provenance?.note && (
        <div style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)", lineHeight: 1.4 }}>
          {provenance.note}
        </div>
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: "0.68rem",
          color: "var(--text-muted, #9ca3af)",
          borderTop: "1px solid rgba(255, 255, 255, 0.05)",
          paddingTop: "0.375rem",
          marginTop: "auto",
        }}
      >
        <div>
          {provenance ? (
            <span>
              Confidence:{" "}
              <strong style={{ color: CONFIDENCE_COLORS[provenance.confidence] }}>{provenance.confidence}</strong>
            </span>
          ) : (
            <span>No provenance</span>
          )}
        </div>
        <div>
          {derived ? (
            <span>Not fetched — placeholder</span>
          ) : formattedTime ? (
            <span title={provenance?.retrieved_at}>Fetched: {formattedTime}</span>
          ) : null}
        </div>
      </div>
    </div>
  );
}
