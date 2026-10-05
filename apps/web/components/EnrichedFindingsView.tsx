"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  api,
  EngagementItem,
  EnrichedFindingItem,
  ScoreComponentInfo,
  ProvenanceInfo,
} from "../lib/api";

interface EnrichedFindingsViewProps {
  activeEngagement: EngagementItem | null;
  onSelectEngagementPrompt?: () => void;
}

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type SortField = "ERS" | "CVSS" | "EPSS" | "CVE";
type SortOrder = "asc" | "desc";

export default function EnrichedFindingsView({
  activeEngagement,
  onSelectEngagementPrompt,
}: EnrichedFindingsViewProps) {
  const [findings, setFindings] = useState<EnrichedFindingItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [sortField, setSortField] = useState<SortField>("ERS");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [enrichingBatch, setEnrichingBatch] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const engagementId = activeEngagement?.engagement_id;

  const fetchFindings = useCallback(async () => {
    if (!engagementId) {
      setFindings([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = await api.getFindings(engagementId, 100, 0);
      setFindings(resp.items || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("404") || msg.toLowerCase().includes("not found")) {
        setError(`Engagement '${engagementId}' was not found in database.`);
      } else {
        setError(msg || "Failed to load enriched findings.");
      }
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  // Demo enrichment trigger
  const handleRunDemoEnrichment = async () => {
    if (!engagementId) return;
    setEnrichingBatch(true);
    setActionNotice(null);
    try {
      const demoFindings = [
        {
          finding_id: `finding-${engagementId}-log4shell`,
          engagement_id: engagementId,
          asset_id: "asset-core-gateway",
          scanner: "nuclei",
          cve_ids: ["CVE-2021-44228"],
          title: "Apache Log4j2 JNDI RCE (Log4Shell)",
          description: "Remote code execution vulnerability in Log4j JNDI lookup functionality.",
          observation_ids: ["obs-log4shell-01"],
          detected_at: new Date().toISOString(),
        },
        {
          finding_id: `finding-${engagementId}-apache-traversal`,
          engagement_id: engagementId,
          asset_id: "asset-dmz-web",
          scanner: "nuclei",
          cve_ids: ["CVE-2021-41773"],
          title: "Apache HTTP Server Path Traversal & File Disclosure",
          description: "Path normalization flaw in Apache 2.4.49 allowing arbitrary file read.",
          observation_ids: ["obs-apache-01"],
          detected_at: new Date().toISOString(),
        },
        {
          finding_id: `finding-${engagementId}-spring-gateway`,
          engagement_id: engagementId,
          asset_id: "asset-cloud-gw",
          scanner: "nuclei",
          cve_ids: ["CVE-2022-22947"],
          title: "Spring Cloud Gateway Code Injection",
          description: "Code injection in Spring Cloud Gateway via SpEL expression evaluation.",
          observation_ids: ["obs-spring-01"],
          detected_at: new Date().toISOString(),
        },
        {
          finding_id: `finding-${engagementId}-jenkins-cli`,
          engagement_id: engagementId,
          asset_id: "asset-ci-build",
          scanner: "nuclei",
          cve_ids: ["CVE-2024-23897"],
          title: "Jenkins CLI Arbitrary File Read (args4j)",
          description: "Arbitrary file read via Jenkins CLI using args4j expand-at-files feature.",
          observation_ids: ["obs-jenkins-01"],
          detected_at: new Date().toISOString(),
        },
        {
          finding_id: `finding-${engagementId}-spring4shell`,
          engagement_id: engagementId,
          asset_id: "asset-api-service",
          scanner: "nuclei",
          cve_ids: ["CVE-2022-22965"],
          title: "Spring Framework RCE (Spring4Shell)",
          description: "Remote code execution in Spring MVC / WebFlux on JDK 9+.",
          observation_ids: ["obs-spring4shell-01"],
          detected_at: new Date().toISOString(),
        },
      ];

      const res = await api.enrichFindingsBatch(engagementId, demoFindings);
      setActionNotice(
        `Enrichment executed successfully: ${res.count ?? demoFindings.length} findings enriched.`
      );
      await fetchFindings();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Batch enrichment failed: ${msg}`);
    } finally {
      setEnrichingBatch(false);
    }
  };

  const getErsSeverityBand = (score: number): { label: string; band: string; color: string; bg: string; border: string } => {
    if (score >= 8.0) return { label: "Critical", band: "critical", color: "#FF3838", bg: "rgba(255, 56, 56, 0.15)", border: "rgba(255, 56, 56, 0.4)" };
    if (score >= 6.0) return { label: "High", band: "high", color: "#FF7A00", bg: "rgba(255, 122, 0, 0.15)", border: "rgba(255, 122, 0, 0.4)" };
    if (score >= 4.0) return { label: "Medium", band: "medium", color: "#FFC312", bg: "rgba(255, 195, 18, 0.15)", border: "rgba(255, 195, 18, 0.4)" };
    return { label: "Low", band: "low", color: "#20D6A3", bg: "rgba(32, 214, 163, 0.15)", border: "rgba(32, 214, 163, 0.4)" };
  };

  const filteredFindings = useMemo(() => {
    return findings
      .filter((item) => {
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const cve = item.cve_id.toLowerCase();
          const fid = item.finding_id.toLowerCase();
          const desc = (item.description?.value || "").toLowerCase();
          const cwes = (item.cwe_ids?.value || []).join(" ").toLowerCase();
          if (!cve.includes(q) && !fid.includes(q) && !desc.includes(q) && !cwes.includes(q)) {
            return false;
          }
        }
        if (severityFilter !== "ALL") {
          const score = item.ers?.score ?? (item.cvss?.value ? item.cvss.value * 0.9 : 0);
          const band = getErsSeverityBand(score).band.toUpperCase();
          if (band !== severityFilter) {
            return false;
          }
        }
        return true;
      })
      .sort((a, b) => {
        let valA = 0;
        let valB = 0;
        if (sortField === "ERS") {
          valA = a.ers?.score ?? 0;
          valB = b.ers?.score ?? 0;
        } else if (sortField === "CVSS") {
          valA = a.cvss?.value ?? 0;
          valB = b.cvss?.value ?? 0;
        } else if (sortField === "EPSS") {
          valA = a.epss?.value ?? 0;
          valB = b.epss?.value ?? 0;
        } else if (sortField === "CVE") {
          return sortOrder === "asc"
            ? a.cve_id.localeCompare(b.cve_id)
            : b.cve_id.localeCompare(a.cve_id);
        }
        return sortOrder === "asc" ? valA - valB : valB - valA;
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
              {findings.length} findings
            </span>
          </div>
          <span style={{ fontSize: "0.85rem", color: "#A7B2B5" }}>
            Fused intelligence across 7 feeds with per-field provenance and Exposure Risk Scores.
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <button
            type="button"
            onClick={handleRunDemoEnrichment}
            disabled={enrichingBatch}
            className="db-btn"
            style={{
              background: "rgba(85, 214, 232, 0.12)",
              border: "1px solid rgba(85, 214, 232, 0.35)",
              color: "#55D6E8",
              fontSize: "0.8rem",
              fontWeight: 600,
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              padding: "0.5rem 0.9rem",
              borderRadius: "8px",
              cursor: enrichingBatch ? "not-allowed" : "pointer",
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            <span>{enrichingBatch ? "Enriching..." : "Enrich Sample Findings"}</span>
          </button>

          <button
            type="button"
            onClick={fetchFindings}
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

      {actionNotice && (
        <div
          style={{
            background: "rgba(32, 214, 163, 0.12)",
            border: "1px solid rgba(32, 214, 163, 0.3)",
            color: "#20D6A3",
            padding: "0.75rem 1rem",
            borderRadius: "8px",
            fontSize: "0.85rem",
            marginBottom: "1rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{actionNotice}</span>
          <button
            onClick={() => setActionNotice(null)}
            style={{ background: "none", border: "none", color: "#20D6A3", cursor: "pointer" }}
          >
            ?
          </button>
        </div>
      )}

      {error && (
        <div
          style={{
            background: "rgba(228, 93, 104, 0.12)",
            border: "1px solid rgba(228, 93, 104, 0.3)",
            color: "#E45D68",
            padding: "0.75rem 1rem",
            borderRadius: "8px",
            fontSize: "0.85rem",
            marginBottom: "1rem",
          }}
        >
          {error}
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
          <span style={{ fontSize: "0.75rem", color: "#A7B2B5", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Severity:
          </span>
          {(
            [
              { id: "ALL", label: "All", color: "#F5F7F8" },
              { id: "CRITICAL", label: "Critical (?8)", color: "#FF3838" },
              { id: "HIGH", label: "High (?6)", color: "#FF7A00" },
              { id: "MEDIUM", label: "Medium (?4)", color: "#FFC312" },
              { id: "LOW", label: "Low (<4)", color: "#20D6A3" },
            ] as const
          ).map((b) => (
            <button
              key={b.id}
              type="button"
              onClick={() => setSeverityFilter(b.id)}
              style={{
                background:
                  severityFilter === b.id
                    ? b.color
                      ? "rgba(255, 255, 255, 0.15)"
                      : "rgba(255, 255, 255, 0.15)"
                    : "rgba(255, 255, 255, 0.03)",
                border:
                  severityFilter === b.id
                    ? `1px solid ${b.color || "#F5F7F8"}`
                    : "1px solid rgba(217, 226, 229, 0.12)",
                color: severityFilter === b.id ? (b.color || "#F5F7F8") : "#A7B2B5",
                padding: "0.35rem 0.65rem",
                borderRadius: "6px",
                fontSize: "0.75rem",
                fontWeight: severityFilter === b.id ? 700 : 500,
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              {b.label}
            </button>
          ))}
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
              {searchQuery || severityFilter !== "ALL"
                ? "No findings match the active search filters"
                : "No enriched findings recorded yet"}
            </div>
            <div className="db-empty-state-desc" style={{ maxWidth: "460px", margin: "0.5rem auto 1.5rem" }}>
              {searchQuery || severityFilter !== "ALL"
                ? "Try clearing your search query or selecting a different severity band."
                : `Run a Nuclei scan or click 'Enrich Sample Findings' to populate multi-source vulnerability intelligence for ${activeEngagement.name}.`}
            </div>
            {!searchQuery && severityFilter === "ALL" && (
              <button
                type="button"
                onClick={handleRunDemoEnrichment}
                disabled={enrichingBatch}
                className="db-btn db-btn-primary"
                style={{ margin: "0 auto" }}
              >
                {enrichingBatch ? "Enriching..." : "Enrich Sample Findings Now"}
              </button>
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
                    Vulnerability / CVE {sortField === "CVE" && (sortOrder === "asc" ? "?" : "?")}
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("CVSS")}>
                    CVSS Score {sortField === "CVSS" && (sortOrder === "asc" ? "?" : "?")}
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("EPSS")}>
                    EPSS Probability {sortField === "EPSS" && (sortOrder === "asc" ? "?" : "?")}
                  </th>
                  <th>CISA KEV Status</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("ERS")}>
                    Exposure Risk Score (ERS) {sortField === "ERS" && (sortOrder === "asc" ? "?" : "?")}
                  </th>
                  <th style={{ width: "50px", textAlign: "center" }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((item) => {
                  const isExpanded = expandedFindingId === item.finding_id;
                  const ersScore = item.ers?.score ?? 0;
                  const severity = getErsSeverityBand(ersScore);
                  const cvssVal = item.cvss?.value;
                  const epssVal = item.epss?.value;
                  const inKevVal = item.in_kev?.value;
                  const isCvssDerived = item.cvss?.provenance?.source === "derived";

                  return (
                    <React.Fragment key={item.finding_id}>
                      <tr
                        style={{
                          background: isExpanded ? "rgba(255, 255, 255, 0.03)" : undefined,
                          cursor: "pointer",
                          borderBottom: isExpanded ? "none" : undefined,
                        }}
                        onClick={() =>
                          setExpandedFindingId(isExpanded ? null : item.finding_id)
                        }
                      >
                        <td>
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                              <span
                                style={{
                                  fontWeight: 700,
                                  color: "#F5F7F8",
                                  fontFamily: "monospace",
                                  fontSize: "0.88rem",
                                }}
                              >
                                {item.cve_id}
                              </span>
                              {item.cwe_ids?.value && item.cwe_ids.value.length > 0 && (
                                <span
                                  style={{
                                    fontSize: "0.7rem",
                                    padding: "0.1rem 0.4rem",
                                    borderRadius: "4px",
                                    background: "rgba(217, 226, 229, 0.08)",
                                    color: "#A7B2B5",
                                  }}
                                >
                                  {item.cwe_ids.value[0]}
                                </span>
                              )}
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
                              title={item.description?.value || item.finding_id}
                            >
                              {item.description?.value || item.finding_id}
                            </div>
                          </div>
                        </td>

                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                            <span
                              style={{
                                fontWeight: 800,
                                fontSize: "0.95rem",
                                color:
                                  cvssVal !== null && cvssVal !== undefined
                                    ? cvssVal >= 9.0
                                      ? "#FF3838"
                                      : cvssVal >= 7.0
                                      ? "#FF7A00"
                                      : cvssVal >= 4.0
                                      ? "#FFC312"
                                      : "#20D6A3"
                                    : "#667276",
                              }}
                            >
                              {cvssVal !== null && cvssVal !== undefined ? cvssVal.toFixed(1) : "?"}
                            </span>
                            {item.cvss?.provenance && (
                              <span
                                title={`Retrieved: ${item.cvss.provenance.retrieved_at} | ${item.cvss.provenance.note || ""}`}
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
                                {isCvssDerived ? "derived (est)" : item.cvss.provenance.source}
                              </span>
                            )}
                          </div>
                        </td>

                        <td>
                          <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", minWidth: "110px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem" }}>
                              <span style={{ fontWeight: 700, color: "#F5F7F8" }}>
                                {epssVal !== null && epssVal !== undefined
                                  ? `${(epssVal * 100).toFixed(1)}%`
                                  : "?"}
                              </span>
                              <span style={{ fontSize: "0.65rem", color: "#20D6A3" }}>EPSS v4</span>
                            </div>
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
                                  width: `${Math.min(100, (epssVal ?? 0) * 100)}%`,
                                  height: "100%",
                                  background:
                                    (epssVal ?? 0) > 0.5
                                      ? "#FF3838"
                                      : (epssVal ?? 0) > 0.2
                                      ? "#FF7A00"
                                      : "#20D6A3",
                                  borderRadius: "2px",
                                }}
                              />
                            </div>
                          </div>
                        </td>

                        <td>
                          {inKevVal === true ? (
                            <span
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
                              title="KEV status unknown"
                            >
                              Unknown
                            </span>
                          )}
                        </td>

                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
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
                            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: severity.color }}>
                              {severity.label}
                            </span>
                          </div>
                        </td>

                        <td style={{ textAlign: "center" }}>
                          <button
                            type="button"
                            className="db-more-btn"
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
                            <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                              
                              {/* 5.3 ERS Component Breakdown */}
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
                                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                      <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
                                        Exposure Risk Score (ERS) Breakdown
                                      </h4>
                                      <span
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
                                        Composite: {ersScore.toFixed(2)} / 10.0
                                      </span>
                                    </div>
                                    <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.8rem", color: "var(--text-muted, #9ca3af)" }}>
                                      Deterministic composite formula weighting CVSS baseline, EPSS likelihood, and CISA KEV exploitation.
                                    </p>
                                  </div>

                                  <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", fontSize: "0.75rem", color: "var(--text-secondary, #d1d5db)" }}>
                                    <span>Formula: <code style={{ color: "var(--accent, #6366f1)", background: "rgba(99, 102, 241, 0.1)", padding: "2px 6px", borderRadius: "4px" }}>ERS = sum(w_i * c_i)</code></span>
                                  </div>
                                </div>

                                {item.ers?.components && item.ers.components.length > 0 ? (
                                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "0.75rem" }}>
                                    {item.ers.components.map((comp, idx) => {
                                      const isDerived = comp.provenance?.source === "derived" || comp.provenance?.source?.toLowerCase().includes("derived");
                                      const pct = Math.min(100, Math.max(0, (comp.raw_value / 10.0) * 100));

                                      return (
                                        <div
                                          key={idx}
                                          style={{
                                            padding: "0.875rem",
                                            borderRadius: "6px",
                                            background: "var(--surface-sunken, #080c14)",
                                            border: isDerived ? "1px dashed #d97706" : "1px solid var(--border, #1f293d)",
                                            position: "relative",
                                          }}
                                        >
                                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
                                            <div>
                                              <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
                                                {comp.name}
                                              </span>
                                              <div style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)" }}>
                                                Weight: {(comp.weight * 100).toFixed(0)}%
                                              </div>
                                            </div>

                                            <div style={{ textAlign: "right" }}>
                                              <span style={{ fontSize: "0.9rem", fontWeight: 700, color: "var(--accent, #6366f1)" }}>
                                                {comp.raw_value.toFixed(2)}
                                              </span>
                                              <span style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)" }}> / 10</span>
                                            </div>
                                          </div>

                                          {/* Score bar */}
                                          <div
                                            style={{
                                              height: "6px",
                                              width: "100%",
                                              background: "rgba(255, 255, 255, 0.08)",
                                              borderRadius: "3px",
                                              overflow: "hidden",
                                              marginBottom: "0.5rem",
                                            }}
                                          >
                                            <div
                                              style={{
                                                height: "100%",
                                                width: `${pct}%`,
                                                background: isDerived ? "#d97706" : "linear-gradient(90deg, #6366f1, #a855f7)",
                                                borderRadius: "3px",
                                              }}
                                            />
                                          </div>

                                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.7rem" }}>
                                            <span style={{ color: "var(--text-muted, #9ca3af)" }}>
                                              Weighted: <strong style={{ color: "var(--text-primary, #f9fafb)" }}>{(comp.weighted_value ?? (comp.raw_value * comp.weight)).toFixed(2)}</strong>
                                            </span>

                                            {/* Flag derived estimates */}
                                            {isDerived ? (
                                              <span
                                                title="Calculated using heuristic placeholder defaults. Not directly measured."
                                                style={{
                                                  display: "inline-flex",
                                                  alignItems: "center",
                                                  gap: "3px",
                                                  color: "#d97706",
                                                  background: "rgba(217, 119, 6, 0.1)",
                                                  padding: "1px 6px",
                                                  borderRadius: "4px",
                                                  fontWeight: 500,
                                                }}
                                              >
                                                Warning: Estimate (not measured)
                                              </span>
                                            ) : (
                                              <span style={{ color: "var(--text-muted, #9ca3af)" }}>
                                                Source: {comp.provenance?.source ?? "rule"}
                                              </span>
                                            )}
                                          </div>
                                        </div>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <div style={{ fontSize: "0.8rem", color: "var(--text-muted, #9ca3af)", fontStyle: "italic", padding: "0.5rem 0" }}>
                                    Default composite baseline calculation: raw CVSS scaled with EPSS risk multipliers.
                                  </div>
                                )}
                              </div>

                              {/* 5.4 Per-Field Provenance & Lineage */}
                              <div>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.875rem" }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                    <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: "var(--text-primary, #f9fafb)" }}>
                                      Field Provenance & Lineage
                                    </h4>
                                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted, #9ca3af)" }}>
                                      (Evidence attribution per Level 2-4 enrichment)
                                    </span>
                                  </div>
                                </div>

                                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "0.875rem" }}>
                                  
                                  {/* CVSS Provenance */}
                                  <FieldProvenanceCard
                                    label="CVSS Base Severity"
                                    value={item.cvss?.value != null ? `${item.cvss.value} / 10.0` : "N/A"}
                                    provenance={item.cvss?.provenance}
                                    icon={
                                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                                      </svg>
                                    }
                                  />

                                  {/* EPSS Provenance */}
                                  <FieldProvenanceCard
                                    label="EPSS Exploit Likelihood"
                                    value={
                                      item.epss?.value != null
                                        ? `${(item.epss.value * 100).toFixed(2)}%`
                                        : "Not scored"
                                    }
                                    provenance={item.epss?.provenance}
                                    icon={
                                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
                                        <polyline points="17 6 23 6 23 12" />
                                      </svg>
                                    }
                                  />

                                  {/* CISA KEV Provenance */}
                                  <FieldProvenanceCard
                                    label="CISA KEV Catalog"
                                    value={
                                      item.in_kev?.value === true
                                        ? "Actively Exploited (In CISA Catalog)"
                                        : item.in_kev?.value === false
                                        ? "Not listed in CISA KEV"
                                        : "Unknown"
                                    }
                                    provenance={item.in_kev?.provenance}
                                    highlight={item.in_kev?.value ? "danger" : "neutral"}
                                    icon={
                                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                      </svg>
                                    }
                                  />

                                  {/* CWE Weaknesses */}
                                  <FieldProvenanceCard
                                    label="CWE Weakness Types"
                                    value={
                                      item.cwe_ids?.value && item.cwe_ids.value.length > 0
                                        ? item.cwe_ids.value.join(", ")
                                        : "None mapped"
                                    }
                                    provenance={item.cwe_ids?.provenance}
                                    icon={
                                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10" />
                                        <line x1="12" y1="8" x2="12" y2="12" />
                                        <line x1="12" y1="16" x2="12.01" y2="16" />
                                      </svg>
                                    }
                                  />

                                  {/* Description & Reference Lineage */}
                                  <FieldProvenanceCard
                                    label="Vulnerability Description & Summary"
                                    value={item.description?.value || "No description available for this finding."}
                                    provenance={item.description?.provenance}
                                    isLongText
                                    icon={
                                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                        <polyline points="14 2 14 8 20 8" />
                                        <line x1="16" y1="13" x2="8" y2="13" />
                                        <line x1="16" y1="17" x2="8" y2="17" />
                                        <polyline points="10 9 9 9 8 9" />
                                      </svg>
                                    }
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
                                  Finding: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{item.cve_id}</code>
                                  <span> | Scope: <code style={{ color: "var(--text-primary, #f9fafb)" }}>{activeEngagement.name}</code></span>
                                </div>
                                <div>
                                  Finding UUID: <code style={{ fontSize: "0.7rem" }}>{item.finding_id}</code>
                                </div>
                              </div>

                            </div>
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// 5.4 Sub-component: FieldProvenanceCard
// ---------------------------------------------------------------------------

interface FieldProvenanceCardProps {
  label: string;
  value: string;
  provenance?: ProvenanceInfo | null;
  highlight?: "danger" | "warning" | "success" | "neutral";
  isLongText?: boolean;
  icon?: React.ReactNode;
}

export function FieldProvenanceCard({
  label,
  value,
  provenance,
  highlight = "neutral",
  isLongText = false,
  icon,
}: FieldProvenanceCardProps) {
  // Source badge color resolution
  const source = provenance?.source?.toLowerCase() ?? "rule";
  let badgeBg = "rgba(107, 114, 128, 0.15)";
  let badgeColor = "#9ca3af";
  let badgeBorder = "#4b5563";
  let isDerived = false;

  if (source.includes("cve_org") || source.includes("nvd") || source.includes("cve")) {
    badgeBg = "rgba(59, 130, 246, 0.15)";
    badgeColor = "#60a5fa";
    badgeBorder = "rgba(59, 130, 246, 0.4)";
  } else if (source.includes("vulnrichment") || source.includes("advisory")) {
    badgeBg = "rgba(168, 85, 247, 0.15)";
    badgeColor = "#c084fc";
    badgeBorder = "rgba(168, 85, 247, 0.4)";
  } else if (source.includes("epss") || source.includes("first")) {
    badgeBg = "rgba(14, 165, 233, 0.15)";
    badgeColor = "#38bdf8";
    badgeBorder = "rgba(14, 165, 233, 0.4)";
  } else if (source.includes("cisa") || source.includes("kev")) {
    badgeBg = "rgba(239, 68, 68, 0.15)";
    badgeColor = "#f87171";
    badgeBorder = "rgba(239, 68, 68, 0.4)";
  } else if (source.includes("derived") || source.includes("default") || source.includes("heuristic")) {
    isDerived = true;
    badgeBg = "rgba(217, 119, 6, 0.15)";
    badgeColor = "#fbbf24";
    badgeBorder = "rgba(217, 119, 6, 0.4)";
  }

  // Format retrieval time
  const formattedTime = provenance?.retrieved_at
    ? new Date(provenance.retrieved_at).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  return (
    <div
      style={{
        background: "var(--surface, #1e2640)",
        border: "1px solid var(--border, #1f293d)",
        borderRadius: "6px",
        padding: "0.875rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
        gridColumn: isLongText ? "1 / -1" : undefined,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.375rem", color: "var(--text-muted, #9ca3af)", fontSize: "0.75rem", fontWeight: 500 }}>
          {icon}
          <span>{label}</span>
        </div>

        {/* Source Badge */}
        <span
          title={`Attributed upstream source: ${provenance?.source ?? "unspecified"}`}
          style={{
            fontSize: "0.68rem",
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.03em",
            padding: "2px 7px",
            borderRadius: "4px",
            background: badgeBg,
            color: badgeColor,
            border: `1px solid ${badgeBorder}`,
            display: "inline-flex",
            alignItems: "center",
            gap: "3px",
          }}
        >
          {isDerived && "Warning: "}
          {provenance?.source ?? "rule"}
        </span>
      </div>

      <div
        style={{
          fontSize: isLongText ? "0.8rem" : "0.875rem",
          fontWeight: isLongText ? 400 : 600,
          color: highlight === "danger" ? "#f87171" : "var(--text-primary, #f9fafb)",
          lineHeight: 1.45,
          maxHeight: isLongText ? "80px" : undefined,
          overflowY: isLongText ? "auto" : undefined,
        }}
      >
        {value}
      </div>

      {/* Lineage Metadata Footer */}
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
          {provenance?.confidence != null ? (
            <span>
              Confidence:{" "}
              <strong style={{ color: "#34d399" }}>
                {provenance.confidence}
              </strong>
            </span>
          ) : (
            <span>Rule Verified</span>
          )}
        </div>

        <div>
          {formattedTime ? <span>Fetched: {formattedTime}</span> : <span>Synced local</span>}
        </div>
      </div>
    </div>
  );
}
