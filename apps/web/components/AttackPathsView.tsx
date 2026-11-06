"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, API_BASE_URL } from "../lib/api";
import type { EngagementItem, ObservationItem } from "../lib/api";
import type { EnrichedFindingItem } from "../lib/findings";
import { formatCvss, formatEpss } from "../lib/findings";
import {
  assumptionFor,
  classifyStep,
  groupPathsByGoal,
  nodeIndex,
  nodeLabel,
  parseEvidenceId,
  pathHasAssumption,
  shortEvidenceLabel,
  splitAssumedDescription,
} from "../lib/attackGraph";
import type {
  AttackGraphResult,
  AttackPath,
  EvidenceRef,
  GraphNode,
  NetworkTopology,
  PathEdge,
  SimulationResult,
  StepClass,
} from "../lib/attackGraph";

interface AttackPathsViewProps {
  activeEngagement: EngagementItem | null;
  onSelectEngagementPrompt?: () => void;
}

const PATHS_PAGE = 10;

// ---------------------------------------------------------------------------
// Load state. Keyed by engagement + reload token so a response for an older
// engagement never renders, and so nothing is set synchronously in an effect.
// ---------------------------------------------------------------------------

type LoadState =
  | { key: string; status: "ok"; graph: AttackGraphResult; topology: NetworkTopology | null; topologyError: string | null }
  | { key: string; status: "no-topology"; message: string }
  | { key: string; status: "error"; message: string };

type EvidenceState =
  | { ref: EvidenceRef; context: string; status: "loading" }
  | { ref: EvidenceRef; context: string; status: "error"; message: string }
  | { ref: EvidenceRef; context: string; status: "observation"; data: ObservationItem }
  | { ref: EvidenceRef; context: string; status: "finding"; data: EnrichedFindingItem }
  | { ref: EvidenceRef; context: string; status: "topology"; data: NetworkTopology };

type SimState =
  | { status: "loading" }
  | { status: "ok"; result: SimulationResult }
  | { status: "error"; message: string };

function describeError(err: unknown, what: string): string {
  if (err instanceof ApiError) return `${what} failed (HTTP ${err.status}): ${err.message}`;
  if (err instanceof TypeError) {
    return `Could not reach the SeekThreat API at ${API_BASE_URL}. Check that the backend is running.`;
  }
  if (err instanceof Error) return `${what} failed: ${err.message}`;
  return `${what} failed: ${String(err)}`;
}

function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

// ---------------------------------------------------------------------------
// Small presentational pieces
// ---------------------------------------------------------------------------

function ConfidenceBadge({ cls }: { cls: StepClass }) {
  const label = cls === "assumption" ? "Assumption" : `${cls} confidence`;
  return <span className={`ap-badge ap-badge-${cls}`}>{label}</span>;
}

function NodeChip({ node, nodeId }: { node: GraphNode | undefined; nodeId: string }) {
  return (
    <div className={`ap-node ${node?.goal ? "ap-node-goal" : ""}`} title={nodeId}>
      <span className="ap-node-kind">{node ? node.kind.replace(/_/g, " ") : "unknown node"}</span>
      <span className="ap-node-label">{node?.label ?? nodeId}</span>
      {node && node.zones.length > 0 && <span className="ap-node-zones">{node.zones.join(", ")}</span>}
    </div>
  );
}

function EvidenceButtons({
  edge,
  onOpen,
}: {
  edge: PathEdge;
  onOpen: (ref: EvidenceRef, context: string) => void;
}) {
  const context = `${edge.rule_name}: ${edge.from_node} → ${edge.to_node}`;
  return (
    <div className="ap-evidence-row">
      <span className="ap-evidence-label">Evidence</span>
      {edge.evidence.map((id) => {
        const ref = parseEvidenceId(id, edge.finding_ids);
        if (ref.kind === "unknown") {
          return (
            <span key={id} className="ap-evidence ap-evidence-unknown" title={`Unrecognized evidence id: ${id}`}>
              unrecognized: {id}
            </span>
          );
        }
        return (
          <button
            key={id}
            type="button"
            className={`ap-evidence ap-evidence-${ref.kind}`}
            title={`Open ${ref.kind} ${id}`}
            onClick={() => onOpen(ref, context)}
          >
            <span className="ap-evidence-kind">{ref.kind === "observation" ? "obs" : ref.kind}</span>
            {shortEvidenceLabel(ref)}
          </button>
        );
      })}
    </div>
  );
}

function Step({
  edge,
  onOpen,
}: {
  edge: PathEdge;
  onOpen: (ref: EvidenceRef, context: string) => void;
}) {
  const cls = classifyStep(edge);
  // The engine already appends "Assumed, not observed: <assumption>" to the
  // description of assumption-rule edges; split it out rather than repeat it.
  const { fact, assumed } = splitAssumedDescription(edge.description);
  const assumption = assumed ?? assumptionFor(edge.rule_name);
  return (
    <div className={`ap-step ap-step-${cls}`}>
      <div className="ap-step-head">
        <span className="ap-rule" title={edge.edge_id}>
          {edge.rule_name}
        </span>
        <ConfidenceBadge cls={cls} />
        {cls === "assumption" && edge.confidence !== "low" && (
          <span className="ap-badge ap-badge-neutral">{edge.confidence} confidence</span>
        )}
      </div>
      {fact && <div className="ap-step-desc">{fact}</div>}
      {assumption && (
        <div className="ap-assume-text">
          <strong>Assumption, not observed by any scan:</strong> {assumption.replace(/^Not observed\.\s*/, "")}
        </div>
      )}
      {cls === "low" && (
        <div className="ap-lowconf-text">
          The engine rated this step low confidence from the evidence it rests on.
        </div>
      )}
      <EvidenceButtons edge={edge} onOpen={onOpen} />
    </div>
  );
}

function PathChain({
  path,
  index,
  nodes,
  onOpen,
}: {
  path: AttackPath;
  index: number;
  nodes: Map<string, GraphNode>;
  onOpen: (ref: EvidenceRef, context: string) => void;
}) {
  const assumed = pathHasAssumption(path);
  return (
    <div className="ap-path">
      <div className="ap-path-head">
        <span className="ap-path-num">Path {index + 1}</span>
        <span className="ap-mono ap-muted" title="path_id">
          {path.path_id}
        </span>
        <span className="ap-muted">
          {path.edges.length} step{path.edges.length === 1 ? "" : "s"}
        </span>
        <span title="A path is only as certain as its weakest step (computed by the server).">
          <ConfidenceBadge cls={path.confidence} />
        </span>
        {assumed && <span className="ap-badge ap-badge-assumption">includes assumption</span>}
      </div>
      <div className="ap-chain">
        <NodeChip node={nodes.get(path.entry_node)} nodeId={path.entry_node} />
        {path.edges.map((edge) => (
          <React.Fragment key={edge.edge_id}>
            <Step edge={edge} onOpen={onOpen} />
            <NodeChip node={nodes.get(edge.to_node)} nodeId={edge.to_node} />
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function KV({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="ap-kv">
      <span className="ap-kv-k">{k}</span>
      <span className={`ap-kv-v ${mono ? "ap-mono" : ""}`}>{v}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Evidence detail
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
          The engagement&apos;s current topology is {t.topology_id}, but this step cites {cited}. The declaration
          has changed since this graph was built; rebuild the graph to cite the current version.
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

// ---------------------------------------------------------------------------
// Main view
// ---------------------------------------------------------------------------

export default function AttackPathsView({ activeEngagement, onSelectEngagementPrompt }: AttackPathsViewProps) {
  const engagementId = activeEngagement?.engagement_id ?? null;
  const [reloadToken, setReloadToken] = useState(0);
  const loadKey = engagementId ? `${engagementId}#${reloadToken}` : null;
  const [load, setLoad] = useState<LoadState | null>(null);
  const [evidence, setEvidence] = useState<EvidenceState | null>(null);
  const evidenceReq = useRef(0);
  const evidenceAbort = useRef<AbortController | null>(null);
  const [sims, setSims] = useState<Record<string, SimState>>({});
  const [openGroups, setOpenGroups] = useState<Record<string, number>>({});
  const [showAllEdges, setShowAllEdges] = useState(false);

  useEffect(() => {
    if (!engagementId || !loadKey) return;
    const controller = new AbortController();
    void (async () => {
      const [graphRes, topoRes] = await Promise.allSettled([
        api.getAttackGraph(engagementId, { signal: controller.signal }),
        api.getTopology(engagementId, controller.signal),
      ]);
      if (controller.signal.aborted) return;
      if (graphRes.status === "rejected") {
        const err = graphRes.reason;
        if (isAbortError(err)) return;
        if (err instanceof ApiError && (err.status === 404 || err.status === 409)) {
          setLoad({ key: loadKey, status: "no-topology", message: err.message });
        } else {
          setLoad({ key: loadKey, status: "error", message: describeError(err, "Loading the attack graph") });
        }
        return;
      }
      setLoad({
        key: loadKey,
        status: "ok",
        graph: graphRes.value,
        topology: topoRes.status === "fulfilled" ? topoRes.value : null,
        topologyError:
          topoRes.status === "rejected" ? describeError(topoRes.reason, "Loading the declared topology") : null,
      });
    })();
    return () => controller.abort();
  }, [engagementId, loadKey]);

  // Close the evidence panel on Escape; abort any in-flight lookup on unmount.
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

  const current = load && load.key === loadKey ? load : null;
  const graph = current?.status === "ok" ? current.graph : null;

  const nodes = useMemo(() => (graph ? nodeIndex(graph.nodes) : new Map<string, GraphNode>()), [graph]);
  const groups = useMemo(() => (graph ? groupPathsByGoal(graph.paths, graph.nodes) : []), [graph]);

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
        } else {
          next = { ref, context, status: "error", message: `Unrecognized evidence id: ${ref.raw}` };
        }
        if (req === evidenceReq.current) setEvidence(next);
      } catch (err: unknown) {
        if (req !== evidenceReq.current || isAbortError(err)) return;
        setEvidence({ ref, context, status: "error", message: describeError(err, `Fetching ${ref.kind} ${ref.lookupId}`) });
      }
    },
    [engagementId]
  );

  const closeEvidence = () => {
    evidenceAbort.current?.abort();
    evidenceReq.current += 1;
    setEvidence(null);
  };

  const simKey = (findingId: string) => `${loadKey}|${findingId}`;

  const runSimulation = async (findingId: string) => {
    if (!engagementId) return;
    const key = simKey(findingId);
    setSims((s) => ({ ...s, [key]: { status: "loading" } }));
    try {
      const result = await api.simulateRemediation(engagementId, [findingId]);
      setSims((s) => ({ ...s, [key]: { status: "ok", result } }));
    } catch (err: unknown) {
      setSims((s) => ({ ...s, [key]: { status: "error", message: describeError(err, "Simulation") } }));
    }
  };

  const findingRef = (findingId: string): EvidenceRef => ({ raw: findingId, kind: "finding", lookupId: findingId });

  // ----- No engagement -----
  if (!activeEngagement) {
    return (
      <div className="db-card ap-empty">
        <h2 className="ap-h2">Engagement Required</h2>
        <p className="ap-empty-text">
          Attack paths are built per authorized engagement. Select or create an engagement first.
        </p>
        {onSelectEngagementPrompt && (
          <button onClick={onSelectEngagementPrompt} className="db-btn-create-eng" style={{ margin: "0 auto" }}>
            Create Engagement
          </button>
        )}
      </div>
    );
  }

  const loading = current === null;

  return (
    <div className="ap-root">
      <div className="ap-header">
        <div>
          <h2 className="ap-h2">Attack Paths</h2>
          <div className="ap-muted" style={{ fontSize: "0.85rem" }}>
            Every step below was built by the deterministic rules engine from an observed scan fact and a named
            rule. Click any evidence id to see the fact it rests on.
          </div>
        </div>
        <button
          type="button"
          className="db-card-action-btn"
          disabled={loading}
          onClick={() => setReloadToken((t) => t + 1)}
          style={{ height: "34px", padding: "0 0.85rem" }}
        >
          {loading ? "Loading..." : "Rebuild"}
        </button>
      </div>

      {loading && <div className="db-card ap-empty">Building the attack graph for {activeEngagement.name}…</div>}

      {current?.status === "error" && (
        <div className="ap-error" role="alert">
          <span>{current.message}</span>
          <button type="button" className="db-card-action-btn" onClick={() => setReloadToken((t) => t + 1)}>
            Retry
          </button>
        </div>
      )}

      {current?.status === "no-topology" && (
        <div className="db-card ap-empty">
          <h3 className="ap-h3">No network topology declared</h3>
          <div className="ap-warn" role="status" style={{ textAlign: "left" }}>
            <span>Server: {current.message}</span>
          </div>
          <p className="ap-empty-text">
            A scan observes which services are open, not which hosts can reach which. That comes from the network
            owner, so the attack-path engine needs a declared topology (zones, the attacker-entry zone, crown-jewel
            zones, multi-homed hosts and allowed flows), attributed to a named person, before it builds any path.
            No path is inferred without one.
          </p>
          <p className="ap-empty-text">
            For the lab, the declaration is <code className="ap-mono">lab/topology.yaml</code>. Once a topology is
            declared for this engagement, press Rebuild.
          </p>
        </div>
      )}

      {graph && current?.status === "ok" && (
        <>
          {/* ---------- Summary ---------- */}
          <div className="db-card ap-card">
            <div className="ap-summary-grid">
              <div className="ap-stat">
                <span className="ap-stat-num">{graph.paths.length}</span>
                <span className="ap-stat-label">paths enumerated</span>
              </div>
              <div className="ap-stat">
                <span className="ap-stat-num">{groups.length}</span>
                <span className="ap-stat-label">goals reached</span>
              </div>
              <div className="ap-stat">
                <span className="ap-stat-num">{graph.edges.length}</span>
                <span className="ap-stat-label">graph edges</span>
              </div>
              <div className="ap-stat">
                <span className="ap-stat-num">{graph.chokepoints.length}</span>
                <span className="ap-stat-label">chokepoints</span>
              </div>
            </div>
            {graph.truncated && (
              <div className="ap-warn" role="alert">
                Truncated: enumeration stopped at its limit (max_paths {graph.max_paths}, max_depth {graph.max_depth}).
                The paths below and the chokepoint counts are a deterministic prefix, not the full set.
              </div>
            )}
            <KV k="Ordering" v={graph.ordering} />
            <KV k="Path score" v="not assigned — paths are unranked" />
            <KV k="Limits" v={`max_depth ${graph.max_depth} · max_paths ${graph.max_paths}`} />
            <KV k="Topology" v={graph.topology_id} mono />
            <KV k="Rules digest" v={graph.rules_digest} mono />
            {current.topology ? (
              <>
                {current.topology.topology_id !== graph.topology_id && (
                  <div className="ap-warn" role="alert">
                    The declared topology is now {current.topology.topology_id}; this graph was built against{" "}
                    {graph.topology_id}. Rebuild to use the current declaration.
                  </div>
                )}
                <KV
                  k="Declared by"
                  v={`${current.topology.declared_by} at ${current.topology.declared_at}`}
                />
                <div className="ap-zones">
                  {current.topology.zones.map((z) => (
                    <span key={z.name} className="ap-zone" title={`${z.cidrs.join(", ")}${z.description ? ` · ${z.description}` : ""}`}>
                      <span className="ap-mono">{z.name}</span>
                      {z.attacker_entry && <span className="ap-zone-flag ap-zone-entry">entry</span>}
                      {z.crown_jewel && <span className="ap-zone-flag ap-zone-goal">crown jewel</span>}
                    </span>
                  ))}
                  <button
                    type="button"
                    className="ap-linkbtn"
                    onClick={() =>
                      void openEvidence(
                        { raw: graph.topology_id, kind: "topology", lookupId: graph.topology_id },
                        "Declared topology for this graph"
                      )
                    }
                  >
                    View declaration
                  </button>
                </div>
              </>
            ) : (
              current.topologyError && <div className="ap-warn">{current.topologyError}</div>
            )}
          </div>

          {/* ---------- Paths by goal ---------- */}
          <h3 className="ap-h3">Paths by goal</h3>
          {groups.length === 0 ? (
            <div className="db-card ap-empty">
              The engine found no path from the attacker-entry zone to any goal with the current observations and
              topology.
            </div>
          ) : (
            groups.map((g) => {
              const shown = openGroups[g.goal_node] ?? 0;
              const goal = nodes.get(g.goal_node);
              return (
                <div key={g.goal_node} className="db-card ap-card">
                  <button
                    type="button"
                    className="ap-group-head"
                    aria-expanded={shown > 0}
                    onClick={() =>
                      setOpenGroups((o) => ({ ...o, [g.goal_node]: shown > 0 ? 0 : PATHS_PAGE }))
                    }
                  >
                    <span className="ap-caret">{shown > 0 ? "▾" : "▸"}</span>
                    <span className="ap-group-title">{g.goal_label}</span>
                    {!g.goal_known && <span className="ap-badge ap-badge-low">goal node not in result</span>}
                    {goal && <span className="ap-muted">{goal.kind.replace(/_/g, " ")}</span>}
                    <span className="ap-count">
                      {g.paths.length} path{g.paths.length === 1 ? "" : "s"}
                    </span>
                  </button>
                  {shown > 0 && (
                    <div className="ap-group-body">
                      {g.paths.slice(0, shown).map((p, i) => (
                        <PathChain key={p.path_id} path={p} index={i} nodes={nodes} onOpen={openEvidence} />
                      ))}
                      {shown < g.paths.length && (
                        <button
                          type="button"
                          className="ap-linkbtn"
                          onClick={() => setOpenGroups((o) => ({ ...o, [g.goal_node]: shown + PATHS_PAGE }))}
                        >
                          Show {Math.min(PATHS_PAGE, g.paths.length - shown)} more of {g.paths.length - shown} remaining
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}

          {/* ---------- Chokepoints ---------- */}
          <h3 className="ap-h3">Chokepoints</h3>
          <div className="ap-muted ap-note">
            Findings that paths depend on, in the server&apos;s order: goals cut first, then paths broken, then
            finding id. Simulating a fix asks the server to rebuild the graph as if the finding had never been
            reported.
          </div>
          {graph.chokepoints.length === 0 ? (
            <div className="db-card ap-empty">No path depends on a finding.</div>
          ) : (
            graph.chokepoints.map((c) => {
              const sim = sims[simKey(c.finding_id)];
              return (
                <div key={c.finding_id} className="db-card ap-card">
                  <div className="ap-choke-head">
                    <span className="ap-count">#{c.rank}</span>
                    <span className="ap-group-title">{c.remediation}</span>
                  </div>
                  <div className="ap-choke-meta">
                    <button
                      type="button"
                      className="ap-evidence ap-evidence-finding"
                      onClick={() => void openEvidence(findingRef(c.finding_id), `Chokepoint #${c.rank}`)}
                    >
                      <span className="ap-evidence-kind">finding</span>
                      {c.finding_id}
                    </button>
                    {c.asset_id && <span className="ap-mono ap-muted">{c.asset_id}</span>}
                    {c.cve_ids.length > 0 && <span className="ap-mono">{c.cve_ids.join(", ")}</span>}
                  </div>
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
                  <div className="ap-sim">
                    <button
                      type="button"
                      className="db-btn-secondary ap-sim-btn"
                      disabled={sim?.status === "loading"}
                      onClick={() => void runSimulation(c.finding_id)}
                    >
                      {sim?.status === "loading" ? "Simulating…" : "Simulate fix"}
                    </button>
                    {sim?.status === "error" && (
                      <div className="ap-error" role="alert">
                        <span>{sim.message}</span>
                      </div>
                    )}
                    {sim?.status === "ok" && (
                      <div className="ap-sim-result">
                        <div>
                          Server rebuilt the graph with{" "}
                          <span className="ap-mono">{sim.result.fixed_finding_ids.join(", ")}</span> fixed:{" "}
                          <strong>{sim.result.removed_path_ids.length}</strong> path
                          {sim.result.removed_path_ids.length === 1 ? "" : "s"} removed (
                          {sim.result.baseline_path_count} → {sim.result.remaining_path_count}).
                        </div>
                        <div>
                          Goals no longer reachable:{" "}
                          {sim.result.goals_no_longer_reachable.length === 0
                            ? "none"
                            : sim.result.goals_no_longer_reachable.map((id) => nodeLabel(nodes, id)).join("; ")}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}

          {/* ---------- Gaps ---------- */}
          <h3 className="ap-h3">Coverage gaps</h3>
          <div className="db-card ap-card">
            <div className="ap-subhead">Unclassified findings ({graph.unclassified_findings.length})</div>
            <div className="ap-muted ap-note">
              Findings no capability rule could turn into an attacker step. They are not on any path, which does not
              mean they are harmless.
            </div>
            {graph.unclassified_findings.length === 0 ? (
              <div className="ap-muted">None.</div>
            ) : (
              <div className="ap-table-wrap">
                <table className="ap-table">
                  <thead>
                    <tr>
                      <th>Finding</th>
                      <th>Asset</th>
                      <th>CVEs</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {graph.unclassified_findings.map((u) => (
                      <tr key={u.finding_id}>
                        <td>
                          <button
                            type="button"
                            className="ap-evidence ap-evidence-finding"
                            onClick={() => void openEvidence(findingRef(u.finding_id), "Unclassified finding")}
                          >
                            {u.finding_id}
                          </button>
                        </td>
                        <td className="ap-mono">{u.asset_id}</td>
                        <td className="ap-mono">{u.cve_ids.join(", ") || "—"}</td>
                        <td>{u.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="ap-subhead">Unzoned addresses ({graph.unzoned_addresses.length})</div>
            <div className="ap-muted ap-note">
              Observed addresses that fall in no declared zone. No rule can place them, so nothing about them appears
              in the graph.
            </div>
            {graph.unzoned_addresses.length === 0 ? (
              <div className="ap-muted">None.</div>
            ) : (
              <div className="ap-zones">
                {graph.unzoned_addresses.map((a) => (
                  <span key={a} className="ap-zone ap-mono">
                    {a}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* ---------- Every edge ---------- */}
          <h3 className="ap-h3">All graph edges</h3>
          <div className="db-card ap-card">
            <button
              type="button"
              className="ap-group-head"
              aria-expanded={showAllEdges}
              onClick={() => setShowAllEdges((v) => !v)}
            >
              <span className="ap-caret">{showAllEdges ? "▾" : "▸"}</span>
              <span className="ap-group-title">Every edge the engine built, including ones on no enumerated path</span>
              <span className="ap-count">{graph.edges.length}</span>
            </button>
            {showAllEdges && (
              <div className="ap-group-body">
                {graph.edges.map((e) => (
                  <div key={e.edge_id} className="ap-edge-row">
                    <div className="ap-edge-nodes">
                      <span>{nodeLabel(nodes, e.from_node)}</span>
                      <span className="ap-arrow">→</span>
                      <span>{nodeLabel(nodes, e.to_node)}</span>
                    </div>
                    <Step edge={e} onOpen={openEvidence} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* ---------- Evidence panel ---------- */}
      {evidence && (
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
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
