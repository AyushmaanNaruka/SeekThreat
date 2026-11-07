"use client";

/**
 * The evidence panel: given a cited id (obs:, finding:, topology:, path:,
 * chokepoint:), fetch and show the real record it names. Shared by the attack-path
 * view (edge evidence) and the assistant (citation chips).
 *
 * Usage: `const ev = useEvidencePanel(engagementId, graph)`, call
 * `ev.openEvidence(ref, context)`, render `{ev.panel}`. When no graph is passed,
 * path and chokepoint ids are looked up in the attack graph fetched from the server.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, API_BASE_URL } from "../lib/api";
import type { ObservationItem } from "../lib/api";
import type { EnrichedFindingItem } from "../lib/findings";
import { formatCvss, formatEpss } from "../lib/findings";
import { nodeIndex, nodeLabel } from "../lib/attackGraph";
import type { AttackGraphResult, AttackPath, Chokepoint, EvidenceRef, GraphNode, NetworkTopology } from "../lib/attackGraph";
import { KV, PathChain } from "./PathParts";
import type { OpenEvidence } from "./PathParts";

export function describeError(err: unknown, what: string): string {
  if (err instanceof ApiError) return `${what} failed (HTTP ${err.status}): ${err.message}`;
  if (err instanceof TypeError) {
    return `Could not reach the SeekThreat API at ${API_BASE_URL}. Check that the backend is running.`;
  }
  if (err instanceof Error) return `${what} failed: ${err.message}`;
  return `${what} failed: ${String(err)}`;
}

export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

type EvidenceState =
  | { ref: EvidenceRef; context: string; status: "loading" }
  | { ref: EvidenceRef; context: string; status: "error"; message: string }
  | { ref: EvidenceRef; context: string; status: "observation"; data: ObservationItem }
  | { ref: EvidenceRef; context: string; status: "finding"; data: EnrichedFindingItem }
  | { ref: EvidenceRef; context: string; status: "topology"; data: NetworkTopology }
  | { ref: EvidenceRef; context: string; status: "path"; data: AttackPath; nodes: Map<string, GraphNode> }
  | { ref: EvidenceRef; context: string; status: "chokepoint"; data: Chokepoint; graph: AttackGraphResult };

// ---------------------------------------------------------------------------
// Record details
// ---------------------------------------------------------------------------

function ObservationDetail({ obs, cited }: { obs: ObservationItem; cited: string }) {
  const attrs = Object.entries(obs.attributes ?? {});
  return (
    <div className="ap-detail">
      {obs.observation_id !== cited && (
        <div className="ap-warn" role="alert">
          The server returned observation {obs.observation_id}, not the cited {cited}.
        </div>
      )}
      <KV k="Observation" v={obs.observation_id} mono />
      <KV k="Scanner" v={obs.scanner} />
      <KV k="Kind" v={obs.kind} />
      <KV k="Subject" v={obs.subject} mono />
      <KV k="Observed at" v={obs.observed_at} mono />
      <KV k="Raw artifact" v={obs.artifact_id} mono />
      <KV
        k="Provenance"
        v={
          obs.provenance
            ? `${obs.provenance.source} · ${obs.provenance.confidence} confidence · retrieved ${obs.provenance.retrieved_at}${
                obs.provenance.note ? ` · ${obs.provenance.note}` : ""
              }`
            : "none returned"
        }
      />
      <div className="ap-subhead">Attributes ({attrs.length})</div>
      {attrs.length === 0 ? (
        <div className="ap-muted">No attributes.</div>
      ) : (
        <div className="ap-table-wrap">
          <table className="ap-table">
            <tbody>
              {attrs.map(([k, v]) => (
                <tr key={k}>
                  <td className="ap-mono">{k}</td>
                  <td className="ap-mono ap-break">{typeof v === "string" ? v : JSON.stringify(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingDetail({ f }: { f: EnrichedFindingItem }) {
  return (
    <div className="ap-detail">
      <KV k="Finding" v={f.finding_id} mono />
      <KV k="Title" v={f.title || "—"} />
      <KV k="Asset" v={f.asset_id} mono />
      <KV k="Scanner" v={f.scanner} />
      <KV k="CVEs" v={f.cve_ids.length > 0 ? f.cve_ids.join(", ") : "none reported"} mono />
      <KV k="Detected at" v={f.detected_at} mono />
      <KV
        k="CWE"
        v={f.cwe_ids && f.cwe_ids.value.length > 0 ? `${f.cwe_ids.value.join(", ")} (${f.cwe_ids.provenance.source})` : "—"}
      />
      <KV k="CVSS" v={f.cvss ? `${formatCvss(f.cvss.value)} (${f.cvss.provenance.source})` : "—"} />
      <KV k="EPSS" v={f.epss ? `${formatEpss(f.epss.value)} (${f.epss.provenance.source})` : "—"} />
      <KV
        k="CISA KEV"
        v={
          f.in_kev
            ? `${f.in_kev.value === null ? "unknown" : f.in_kev.value ? "listed" : "not listed"} (${f.in_kev.provenance.source})`
            : "—"
        }
      />
      <div className="ap-subhead">Scanner report (verbatim)</div>
      <pre className="ap-pre">{f.scanner_report || "—"}</pre>
      <div className="ap-muted" style={{ fontSize: "0.75rem" }}>
        The Exposure Risk Score and its per-component explanation are in the Findings view.
      </div>
    </div>
  );
}

function TopologyDetail({ t, cited }: { t: NetworkTopology; cited: string | null }) {
  return (
    <div className="ap-detail">
      {cited !== null && t.topology_id !== cited && (
        <div className="ap-warn" role="alert">
          The engagement&apos;s current topology is {t.topology_id}, but this reference cites {cited}. The
          declaration has changed since it was cited; rebuild the graph (and re-index the assistant) to cite the
          current version.
        </div>
      )}
      <KV k="Topology" v={t.topology_id} mono />
      <KV k="Declared by" v={t.declared_by} />
      <KV k="Declared at" v={t.declared_at} mono />
      <KV k="Source" v={t.source_note || "—"} />
      <KV k="Intra-zone reachable" v={t.intra_zone_reachable ? "yes (flat segments)" : "no"} />
      <div className="ap-subhead">Zones ({t.zones.length})</div>
      <div className="ap-table-wrap">
        <table className="ap-table">
          <thead>
            <tr>
              <th>Zone</th>
              <th>CIDRs</th>
              <th>Role</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {t.zones.map((z) => (
              <tr key={z.name}>
                <td className="ap-mono">{z.name}</td>
                <td className="ap-mono">{z.cidrs.join(", ")}</td>
                <td>
                  {[z.attacker_entry ? "attacker entry" : null, z.crown_jewel ? "crown jewel (goal)" : null]
                    .filter(Boolean)
                    .join(", ") || "—"}
                </td>
                <td>{z.description || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="ap-subhead">Multi-homed hosts ({t.multi_homed_hosts.length})</div>
      {t.multi_homed_hosts.length === 0 ? (
        <div className="ap-muted">None declared.</div>
      ) : (
        <ul className="ap-list">
          {t.multi_homed_hosts.map((h) => (
            <li key={h.name}>
              <span className="ap-mono">{h.name}</span>: {h.addresses.join(", ")}
            </li>
          ))}
        </ul>
      )}
      <div className="ap-subhead">Declared cross-zone flows ({t.flows.length})</div>
      {t.flows.length === 0 ? (
        <div className="ap-muted">None declared.</div>
      ) : (
        <ul className="ap-list">
          {t.flows.map((f, i) => (
            <li key={`${f.from_zone}-${f.to_zone}-${i}`}>
              <span className="ap-mono">
                {f.from_zone} → {f.to_zone}
              </span>{" "}
              ports {f.ports.length > 0 ? f.ports.join(", ") : "all"}
              {f.description ? ` · ${f.description}` : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ChokepointDetail({
  c,
  graph,
  onOpen,
}: {
  c: Chokepoint;
  graph: AttackGraphResult;
  onOpen: OpenEvidence;
}) {
  const nodes = nodeIndex(graph.nodes);
  return (
    <div className="ap-detail">
      <KV k="Rank" v={`#${c.rank}`} />
      <KV k="Remediation" v={c.remediation} />
      <KV
        k="Finding"
        v={
          <button
            type="button"
            className="ap-evidence ap-evidence-finding"
            onClick={() => onOpen({ raw: c.finding_id, kind: "finding", lookupId: c.finding_id }, `Chokepoint #${c.rank}`)}
          >
            <span className="ap-evidence-kind">finding</span>
            {c.finding_id}
          </button>
        }
      />
      <KV k="Asset" v={c.asset_id ?? "—"} mono />
      <KV k="CVEs" v={c.cve_ids.length > 0 ? c.cve_ids.join(", ") : "none reported"} mono />
      <KV
        k="Paths broken"
        v={`${c.paths_broken.length} of ${graph.paths.length} enumerated${graph.truncated ? " (enumeration truncated)" : ""}`}
      />
      <KV
        k="Goals cut"
        v={
          c.goals_cut.length === 0
            ? "none — every goal stays reachable another way"
            : c.goals_cut.map((id) => nodeLabel(nodes, id)).join("; ")
        }
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useEvidencePanel(
  engagementId: string | null,
  graph: AttackGraphResult | null = null
): { openEvidence: OpenEvidence; closeEvidence: () => void; panel: React.ReactNode } {
  const [evidence, setEvidence] = useState<EvidenceState | null>(null);
  const evidenceReq = useRef(0);
  const evidenceAbort = useRef<AbortController | null>(null);
  // Attack graph fetched for path/chokepoint lookups when the caller has none loaded.
  const fetchedGraph = useRef<{ engagementId: string; graph: AttackGraphResult } | null>(null);

  // Close the panel on Escape; abort any in-flight lookup on unmount.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setEvidence(null);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      evidenceAbort.current?.abort();
    };
  }, []);

  const loadGraph = useCallback(
    async (eid: string, signal: AbortSignal): Promise<AttackGraphResult> => {
      if (graph && graph.engagement_id === eid) return graph;
      const cached = fetchedGraph.current;
      if (cached && cached.engagementId === eid) return cached.graph;
      const g = await api.getAttackGraph(eid, { signal });
      fetchedGraph.current = { engagementId: eid, graph: g };
      return g;
    },
    [graph]
  );

  const openEvidence = useCallback(
    async (ref: EvidenceRef, context: string) => {
      if (!engagementId) return;
      evidenceAbort.current?.abort();
      const controller = new AbortController();
      evidenceAbort.current = controller;
      const req = ++evidenceReq.current;
      setEvidence({ ref, context, status: "loading" });
      try {
        let next: EvidenceState;
        if (ref.kind === "observation") {
          next = { ref, context, status: "observation", data: await api.getObservation(ref.lookupId, engagementId, controller.signal) };
        } else if (ref.kind === "finding") {
          next = { ref, context, status: "finding", data: await api.getFinding(ref.lookupId, engagementId, controller.signal) };
        } else if (ref.kind === "topology") {
          next = { ref, context, status: "topology", data: await api.getTopology(engagementId, controller.signal) };
        } else if (ref.kind === "path") {
          const g = await loadGraph(engagementId, controller.signal);
          const p = g.paths.find((x) => x.path_id === ref.lookupId);
          next = p
            ? { ref, context, status: "path", data: p, nodes: nodeIndex(g.nodes) }
            : {
                ref,
                context,
                status: "error",
                message: `Path ${ref.lookupId} is not among the ${g.paths.length} paths in the attack graph the server returns now${
                  g.truncated ? " (enumeration truncated)" : ""
                }. The graph may have changed since it was cited; re-index the assistant.`,
              };
        } else if (ref.kind === "chokepoint") {
          const g = await loadGraph(engagementId, controller.signal);
          const c = g.chokepoints.find((x) => x.finding_id === ref.lookupId);
          next = c
            ? { ref, context, status: "chokepoint", data: c, graph: g }
            : {
                ref,
                context,
                status: "error",
                message: `No chokepoint for finding ${ref.lookupId} in the attack graph the server returns now. The graph may have changed since it was cited; re-index the assistant.`,
              };
        } else {
          next = { ref, context, status: "error", message: `Unrecognized evidence id: ${ref.raw}` };
        }
        if (req === evidenceReq.current) setEvidence(next);
      } catch (err: unknown) {
        if (req !== evidenceReq.current || isAbortError(err)) return;
        setEvidence({ ref, context, status: "error", message: describeError(err, `Fetching ${ref.kind} ${ref.lookupId}`) });
      }
    },
    [engagementId, loadGraph]
  );

  const closeEvidence = useCallback(() => {
    evidenceAbort.current?.abort();
    evidenceReq.current += 1;
    setEvidence(null);
  }, []);

  const open: OpenEvidence = (ref, context) => void openEvidence(ref, context);

  const panel = evidence ? (
    <div className="db-modal-overlay" onClick={closeEvidence}>
      <div
        className="db-modal-box ap-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Evidence detail"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="db-modal-header">
          <div className="db-modal-title">
            Evidence
            <span className={`ap-evidence ap-evidence-${evidence.ref.kind}`}>{evidence.ref.kind}</span>
          </div>
          <button type="button" className="db-modal-close-btn" aria-label="Close" onClick={closeEvidence}>
            ✕
          </button>
        </div>
        <KV k="Cited id" v={evidence.ref.raw} mono />
        <KV k="Cited by" v={evidence.context} mono />
        <div className="ap-modal-body">
          {evidence.status === "loading" && <div className="ap-muted">Fetching {evidence.ref.kind}…</div>}
          {evidence.status === "error" && (
            <div className="ap-error" role="alert">
              <span>{evidence.message}</span>
              <button
                type="button"
                className="db-card-action-btn"
                onClick={() => void openEvidence(evidence.ref, evidence.context)}
              >
                Retry
              </button>
            </div>
          )}
          {evidence.status === "observation" && <ObservationDetail obs={evidence.data} cited={evidence.ref.lookupId} />}
          {evidence.status === "finding" && <FindingDetail f={evidence.data} />}
          {evidence.status === "topology" && <TopologyDetail t={evidence.data} cited={evidence.ref.lookupId} />}
          {evidence.status === "path" && (
            <div className="ap-detail">
              <div className="ap-muted ap-note">
                This path was built by the deterministic rules engine. Click any evidence id to see the fact a step
                rests on.
              </div>
              <PathChain path={evidence.data} index={0} nodes={evidence.nodes} onOpen={open} />
            </div>
          )}
          {evidence.status === "chokepoint" && (
            <ChokepointDetail c={evidence.data} graph={evidence.graph} onOpen={open} />
          )}
        </div>
      </div>
    </div>
  ) : null;

  return { openEvidence: open, closeEvidence, panel };
}
