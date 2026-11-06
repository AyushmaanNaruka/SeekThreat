/**
 * Pure attack-graph (Layer 3) display logic: response types, evidence-id parsing,
 * grouping paths by goal, and step classification.
 *
 * Kept free of imports (and of non-erasable TypeScript syntax) so the Node test
 * runner can import it directly via type stripping, exactly like lib/findings.ts.
 *
 * Backend contract: packages/schema/models/{graph,topology}.py, serialized with
 * model_dump(mode="json"); computed fields (edge_id, confidence, entry_node,
 * goal_node, topology_id) are present in the JSON.
 *
 * Nothing here creates, infers or reorders edges. Paths come from the
 * deterministic rules engine (services/graph); this module only groups and
 * labels what the server returned.
 */

// ---------------------------------------------------------------------------
// Types (mirror packages/schema/models/graph.py and topology.py)
// ---------------------------------------------------------------------------

export type GraphConfidence = "high" | "medium" | "low";

export type NodeKind =
  | "attacker"
  | "network_access"
  | "code_execution"
  | "file_read"
  | "credentials";

export interface GraphNode {
  node_id: string;
  kind: NodeKind | string;
  label: string;
  machine: string | null;
  zones: string[];
  goal: boolean;
}

export interface PathEdge {
  from_node: string;
  to_node: string;
  rule_name: string;
  /** Prefixed ids: "obs:..." observations, "finding:..." findings, "topology:..." the declared topology. */
  evidence: string[];
  description: string;
  confidence: GraphConfidence;
  finding_ids: string[];
  edge_id: string;
}

export interface AttackPath {
  path_id: string;
  edges: PathEdge[];
  /** Always null until a path-scoring formula is signed off (D-039). Never displayed. */
  score: number | null;
  narration: string | null;
  confidence: GraphConfidence;
  entry_node: string;
  goal_node: string;
}

export interface Chokepoint {
  finding_id: string;
  paths_broken: string[];
  remediation: string;
  rank: number;
  goals_cut: string[];
  asset_id: string | null;
  cve_ids: string[];
}

export interface UnclassifiedFinding {
  finding_id: string;
  asset_id: string;
  cve_ids: string[];
  reason: string;
}

export interface AttackGraphResult {
  engagement_id: string;
  topology_id: string;
  rules_digest: string;
  nodes: GraphNode[];
  edges: PathEdge[];
  paths: AttackPath[];
  chokepoints: Chokepoint[];
  unclassified_findings: UnclassifiedFinding[];
  unzoned_addresses: string[];
  max_depth: number;
  max_paths: number;
  truncated: boolean;
  ordering: string;
}

export interface SimulationResult {
  fixed_finding_ids: string[];
  baseline_path_count: number;
  remaining_path_count: number;
  removed_path_ids: string[];
  goals_no_longer_reachable: string[];
  after: AttackGraphResult;
}

export interface TopologyZone {
  name: string;
  cidrs: string[];
  attacker_entry: boolean;
  crown_jewel: boolean;
  description: string;
}

export interface MultiHomedHost {
  name: string;
  addresses: string[];
}

export interface ZoneFlow {
  from_zone: string;
  to_zone: string;
  ports: number[];
  description: string;
}

export interface NetworkTopology {
  engagement_id: string;
  declared_by: string;
  declared_at: string;
  zones: TopologyZone[];
  multi_homed_hosts: MultiHomedHost[];
  flows: ZoneFlow[];
  intra_zone_reachable: boolean;
  source_note: string;
  topology_id: string;
}

// ---------------------------------------------------------------------------
// Validation (throw on malformed input rather than render invented structure)
// ---------------------------------------------------------------------------

type RawRecord = Record<string, unknown>;

function isRecord(v: unknown): v is RawRecord {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireArray(obj: RawRecord, key: string, context: string): unknown[] {
  const v = obj[key];
  if (!Array.isArray(v)) throw new Error(`${context}.${key}: expected an array`);
  return v;
}

function requireString(obj: RawRecord, key: string, context: string): string {
  const v = obj[key];
  if (typeof v !== "string") throw new Error(`${context}.${key}: expected a string`);
  return v;
}

/**
 * Check the shape of a backend AttackGraphResult. Returns it typed; throws on a
 * missing required field so the UI shows an error instead of a half-rendered graph.
 */
export function parseAttackGraphResult(raw: unknown): AttackGraphResult {
  if (!isRecord(raw)) throw new Error("AttackGraphResult: expected an object");
  const ctx = "AttackGraphResult";
  requireString(raw, "engagement_id", ctx);
  requireString(raw, "topology_id", ctx);
  requireString(raw, "rules_digest", ctx);
  requireString(raw, "ordering", ctx);
  requireArray(raw, "nodes", ctx);
  requireArray(raw, "chokepoints", ctx);
  requireArray(raw, "unclassified_findings", ctx);
  requireArray(raw, "unzoned_addresses", ctx);
  const edges = requireArray(raw, "edges", ctx);
  const paths = requireArray(raw, "paths", ctx);
  if (typeof raw.truncated !== "boolean") throw new Error(`${ctx}.truncated: expected a boolean`);
  const checkEdge = (e: unknown, where: string) => {
    if (!isRecord(e)) throw new Error(`${where}: expected an object`);
    requireString(e, "edge_id", where);
    requireString(e, "rule_name", where);
    requireString(e, "from_node", where);
    requireString(e, "to_node", where);
    if (requireArray(e, "evidence", where).length === 0) {
      throw new Error(`${where}.evidence: an edge must cite evidence`);
    }
  };
  edges.forEach((e, i) => checkEdge(e, `${ctx}.edges[${i}]`));
  paths.forEach((p, i) => {
    const where = `${ctx}.paths[${i}]`;
    if (!isRecord(p)) throw new Error(`${where}: expected an object`);
    requireString(p, "path_id", where);
    requireString(p, "goal_node", where);
    const pe = requireArray(p, "edges", where);
    if (pe.length === 0) throw new Error(`${where}.edges: a path needs at least one edge`);
    pe.forEach((e, j) => checkEdge(e, `${where}.edges[${j}]`));
  });
  return raw as unknown as AttackGraphResult;
}

// ---------------------------------------------------------------------------
// Evidence ids
// ---------------------------------------------------------------------------

export type EvidenceKind = "observation" | "finding" | "topology" | "unknown";

export interface EvidenceRef {
  /** The id exactly as the edge cited it. */
  raw: string;
  kind: EvidenceKind;
  /**
   * The id to look the evidence up by:
   * - observation: the full id, prefix included (observation ids are "obs:sha256:...").
   * - finding: the finding id with the "finding:" prefix stripped, unless the
   *   finding's own id already starts with "finding:" (services/graph/builder.py
   *   `_finding_ref` does not double-prefix such ids).
   * - topology: the full topology_id ("topology:sha256:...").
   */
  lookupId: string;
}

/**
 * Parse one evidence id. `knownFindingIds` (normally the edge's `finding_ids`) lets
 * a finding whose own id begins with "finding:" resolve to itself.
 */
export function parseEvidenceId(raw: string, knownFindingIds: readonly string[] = []): EvidenceRef {
  if (raw.startsWith("obs:")) return { raw, kind: "observation", lookupId: raw };
  if (raw.startsWith("topology:")) return { raw, kind: "topology", lookupId: raw };
  if (raw.startsWith("finding:")) {
    if (knownFindingIds.includes(raw)) return { raw, kind: "finding", lookupId: raw };
    const stripped = raw.slice("finding:".length);
    if (stripped === "") return { raw, kind: "unknown", lookupId: raw };
    return { raw, kind: "finding", lookupId: stripped };
  }
  return { raw, kind: "unknown", lookupId: raw };
}

/** Short display form: "sha256:" hashes cut to 12 hex chars. The full id stays in the title. */
export function shortEvidenceLabel(ref: EvidenceRef): string {
  const body = ref.kind === "finding" ? ref.lookupId : ref.raw.replace(/^(obs|topology):/, "");
  return body.replace(/sha256:([0-9a-f]{12})[0-9a-f]+/i, "sha256:$1…");
}

// ---------------------------------------------------------------------------
// Rules that rest on an assumption (mirrors services/graph/rules/core.yaml)
// ---------------------------------------------------------------------------

/**
 * Rules whose edges rest on something no scan observed. Text copied from the
 * `assumption` field of services/graph/rules/core.yaml; tests/attackGraph.test.mjs
 * fails if the two drift apart.
 */
export const ASSUMPTION_RULES: Readonly<Record<string, string>> = {
  local_access_exposes_credentials:
    "Not observed. Assumes the machine stores reusable credentials (keys, tokens, config secrets). True on many servers, verified on none by this scan.",
  credential_reuse_remote_login:
    "Not observed. Assumes credentials from the source machine are valid on the target login service. Credential reuse is common, but this scan proves nothing about it.",
};

export type StepClass = "assumption" | "low" | "medium" | "high";

/** How a step should be presented: assumption rules first, then the edge's own confidence. */
export function classifyStep(edge: Pick<PathEdge, "rule_name" | "confidence">): StepClass {
  if (Object.prototype.hasOwnProperty.call(ASSUMPTION_RULES, edge.rule_name)) return "assumption";
  return edge.confidence;
}

export function assumptionFor(ruleName: string): string | null {
  return Object.prototype.hasOwnProperty.call(ASSUMPTION_RULES, ruleName)
    ? ASSUMPTION_RULES[ruleName]
    : null;
}

/** Marker services/graph/builder.py puts before a rule's assumption in an edge description. */
export const ASSUMED_MARKER = "Assumed, not observed:";

/**
 * Split an edge description into the observed part and the engine-appended
 * assumption. `assumed` is null when the description carries no assumption.
 */
export function splitAssumedDescription(description: string): { fact: string; assumed: string | null } {
  const at = description.indexOf(ASSUMED_MARKER);
  if (at < 0) return { fact: description.trim(), assumed: null };
  const fact = description.slice(0, at).trim().replace(/[.;,]$/, "");
  const assumed = description.slice(at + ASSUMED_MARKER.length).trim();
  return { fact, assumed: assumed === "" ? null : assumed };
}

/** True when any step of the path is an assumption-rule step. */
export function pathHasAssumption(path: Pick<AttackPath, "edges">): boolean {
  return path.edges.some((e) => classifyStep(e) === "assumption");
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

export function nodeIndex(nodes: readonly GraphNode[]): Map<string, GraphNode> {
  return new Map(nodes.map((n) => [n.node_id, n]));
}

/** A node's label, or its id when the server returned no such node. */
export function nodeLabel(index: Map<string, GraphNode>, nodeId: string): string {
  return index.get(nodeId)?.label ?? nodeId;
}

export interface GoalGroup {
  goal_node: string;
  goal_label: string;
  /** False when the goal id was not among the result's nodes (shown as the raw id). */
  goal_known: boolean;
  paths: AttackPath[];
}

/**
 * Group paths by goal node. Groups are ordered by goal label (then id) so the order
 * implies nothing about risk; paths inside a group keep the server's order, which is
 * the engine's stated, unranked `ordering`.
 */
export function groupPathsByGoal(
  paths: readonly AttackPath[],
  nodes: readonly GraphNode[]
): GoalGroup[] {
  const index = nodeIndex(nodes);
  const groups = new Map<string, GoalGroup>();
  for (const path of paths) {
    let group = groups.get(path.goal_node);
    if (!group) {
      const node = index.get(path.goal_node);
      group = {
        goal_node: path.goal_node,
        goal_label: node?.label ?? path.goal_node,
        goal_known: node !== undefined,
        paths: [],
      };
      groups.set(path.goal_node, group);
    }
    group.paths.push(path);
  }
  return [...groups.values()].sort(
    (a, b) =>
      a.goal_label.localeCompare(b.goal_label, "en") ||
      (a.goal_node < b.goal_node ? -1 : a.goal_node > b.goal_node ? 1 : 0)
  );
}
