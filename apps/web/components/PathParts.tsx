"use client";

/**
 * Presentational pieces for proven attack paths, shared by AttackPathsView and the
 * evidence panel (which shows a cited path). They only display what the rules
 * engine returned.
 */

import React from "react";
import {
  assumptionFor,
  classifyStep,
  parseEvidenceId,
  pathHasAssumption,
  shortEvidenceLabel,
  splitAssumedDescription,
} from "../lib/attackGraph";
import type { AttackPath, EvidenceRef, GraphNode, PathEdge, StepClass } from "../lib/attackGraph";

export type OpenEvidence = (ref: EvidenceRef, context: string) => void;

export function KV({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="ap-kv">
      <span className="ap-kv-k">{k}</span>
      <span className={`ap-kv-v ${mono ? "ap-mono" : ""}`}>{v}</span>
    </div>
  );
}

export function ConfidenceBadge({ cls }: { cls: StepClass }) {
  const label = cls === "assumption" ? "Assumption" : `${cls} confidence`;
  return <span className={`ap-badge ap-badge-${cls}`}>{label}</span>;
}

export function NodeChip({ node, nodeId }: { node: GraphNode | undefined; nodeId: string }) {
  return (
    <div className={`ap-node ${node?.goal ? "ap-node-goal" : ""}`} title={nodeId}>
      <span className="ap-node-kind">{node ? node.kind.replace(/_/g, " ") : "unknown node"}</span>
      <span className="ap-node-label">{node?.label ?? nodeId}</span>
      {node && node.zones.length > 0 && <span className="ap-node-zones">{node.zones.join(", ")}</span>}
    </div>
  );
}

function EvidenceButtons({ edge, onOpen }: { edge: PathEdge; onOpen: OpenEvidence }) {
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

export function Step({ edge, onOpen }: { edge: PathEdge; onOpen: OpenEvidence }) {
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

export function PathChain({
  path,
  index,
  nodes,
  onOpen,
  children,
}: {
  path: AttackPath;
  index: number;
  nodes: Map<string, GraphNode>;
  onOpen: OpenEvidence;
  /** Rendered under the chain (e.g. the narration controls). */
  children?: React.ReactNode;
}) {
  const assumed = pathHasAssumption(path);
  return (
    <div className="ap-path">
      <div className="ap-path-head">
        <span className="ap-path-num">
          {typeof path.rank === "number" ? `Rank ${path.rank}` : `Path ${index + 1}`}
        </span>
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
      {path.rank_explanation && <p className="ap-muted ap-rank-why">{path.rank_explanation}</p>}
      <div className="ap-chain">
        <NodeChip node={nodes.get(path.entry_node)} nodeId={path.entry_node} />
        {path.edges.map((edge) => (
          <React.Fragment key={edge.edge_id}>
            <Step edge={edge} onOpen={onOpen} />
            <NodeChip node={nodes.get(edge.to_node)} nodeId={edge.to_node} />
          </React.Fragment>
        ))}
      </div>
      {children}
    </div>
  );
}
