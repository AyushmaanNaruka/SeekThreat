/**
 * Pure assistant (Layer 4) display logic: response types, runtime shape checks,
 * splitting answer text into plain text and citation markers, and the grounding
 * verdict.
 *
 * Kept free of imports (and of non-erasable TypeScript syntax) so the Node test
 * runner can import it directly via type stripping, like lib/attackGraph.ts.
 * Mapping a cited doc id to the record it names is parseEvidenceId in
 * lib/attackGraph.ts (obs:, finding:, topology:, path:, chokepoint:).
 *
 * Backend contract: packages/schema/models/{assistant,citation}.py serialized with
 * model_dump(mode="json"). GroundingCheck.grounded is a Python @property and is NOT
 * in the JSON; isGrounded() recomputes it from the two lists.
 *
 * The model only narrates. Paths come from the deterministic rules engine; nothing
 * here turns model text into graph structure.
 */

// ---------------------------------------------------------------------------
// Types (mirror packages/schema/models/assistant.py and citation.py)
// ---------------------------------------------------------------------------

export type CitationKind = "observation" | "finding" | "path" | "topology" | "source";

export interface Citation {
  kind: CitationKind | string;
  ref_id: string;
  excerpt: string | null;
}

export interface AssistantDocument {
  doc_id: string;
  kind: CitationKind | string;
  engagement_id: string;
  title: string;
  text: string;
  metadata: Record<string, string>;
}

export type RetrievalMethod = "vector" | "lexical" | "hybrid";

export interface RetrievedDocument {
  document: AssistantDocument;
  /** Retrieval similarity of the document to the question. Says nothing about the answer. */
  score: number;
  method: RetrievalMethod | string;
}

/** A near-miss citation id resolved to exactly one supplied document (D-052). */
export interface CitationRepair {
  cited: string;
  resolved: string;
  rule: string;
}

export interface GroundingCheck {
  checked_entities: string[];
  unsupported_entities: string[];
  invalid_citations: string[];
  /** Absent in responses from before D-052. */
  repaired_citations?: CitationRepair[];
}

export interface Answer {
  question: string;
  engagement_id: string;
  text: string;
  citations: Citation[];
  refused: boolean;
  refusal_reason: string | null;
  retrieved: RetrievedDocument[];
  grounding: GroundingCheck;
  model: string;
}

export interface PathNarration {
  path_id: string;
  engagement_id: string;
  text: string;
  citations: Citation[];
  grounding: GroundingCheck;
  model: string;
}

export interface IndexResult {
  engagement_id: string;
  indexed: number;
  by_kind: Record<string, number>;
  embed_model: string;
}

export interface AssistantStatus {
  ollama_base_url: string;
  model: string;
  embed_model: string;
  reachable: boolean;
  models_available: string[];
  /** Any explanatory message the server attached (detail / error / message). */
  message: string | null;
}

// ---------------------------------------------------------------------------
// Grounding
// ---------------------------------------------------------------------------

/** Mirrors GroundingCheck.grounded: nothing unsupported and no citation outside the supplied records. */
export function isGrounded(g: Pick<GroundingCheck, "unsupported_entities" | "invalid_citations">): boolean {
  return g.unsupported_entities.length === 0 && g.invalid_citations.length === 0;
}

// ---------------------------------------------------------------------------
// Citation markers
// ---------------------------------------------------------------------------

export type Segment =
  | { type: "text"; text: string }
  /** `n` is 1-based, numbered by the id's first appearance in the text. */
  | { type: "cite"; docId: string; n: number };

const CITE_RE = /\[cite:([^\]]*)\]/g;

/**
 * Split model text into plain text and citation markers. `[cite:<doc_id>]` becomes a
 * cite segment; a marker listing several ids separated by commas yields one segment
 * per id. The same id always gets the same number. Empty markers are dropped.
 */
export function renderSegments(text: string): Segment[] {
  const out: Segment[] = [];
  const numbers = new Map<string, number>();
  let last = 0;
  const pushText = (t: string) => {
    if (t === "") return;
    const prev = out[out.length - 1];
    if (prev && prev.type === "text") prev.text += t;
    else out.push({ type: "text", text: t });
  };
  for (const m of text.matchAll(CITE_RE)) {
    const at = m.index ?? 0;
    pushText(text.slice(last, at));
    last = at + m[0].length;
    const ids = m[1]
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "");
    for (const docId of ids) {
      let n = numbers.get(docId);
      if (n === undefined) {
        n = numbers.size + 1;
        numbers.set(docId, n);
      }
      out.push({ type: "cite", docId, n });
    }
  }
  pushText(text.slice(last));
  return out;
}

/** Cited doc ids in order of first appearance (index i has number i + 1). */
export function citedIdsInOrder(segments: readonly Segment[]): string[] {
  const seen: string[] = [];
  for (const s of segments) if (s.type === "cite" && !seen.includes(s.docId)) seen.push(s.docId);
  return seen;
}

// ---------------------------------------------------------------------------
// Validation (throw on malformed input rather than render invented structure)
// ---------------------------------------------------------------------------

type RawRecord = Record<string, unknown>;

function isRecord(v: unknown): v is RawRecord {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(obj: RawRecord, key: string, ctx: string): string {
  const v = obj[key];
  if (typeof v !== "string") throw new Error(`${ctx}.${key}: expected a string`);
  return v;
}

function optStr(obj: RawRecord, key: string, ctx: string): string | null {
  const v = obj[key];
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") throw new Error(`${ctx}.${key}: expected a string or null`);
  return v;
}

function arr(obj: RawRecord, key: string, ctx: string): unknown[] {
  const v = obj[key];
  if (!Array.isArray(v)) throw new Error(`${ctx}.${key}: expected an array`);
  return v;
}

function strArr(obj: RawRecord, key: string, ctx: string): string[] {
  return arr(obj, key, ctx).map((v, i) => {
    if (typeof v !== "string") throw new Error(`${ctx}.${key}[${i}]: expected a string`);
    return v;
  });
}

function parseCitation(raw: unknown, ctx: string): Citation {
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  return { kind: str(raw, "kind", ctx), ref_id: str(raw, "ref_id", ctx), excerpt: optStr(raw, "excerpt", ctx) };
}

export function parseGrounding(raw: unknown, ctx = "GroundingCheck"): GroundingCheck {
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  return {
    checked_entities: strArr(raw, "checked_entities", ctx),
    unsupported_entities: strArr(raw, "unsupported_entities", ctx),
    invalid_citations: strArr(raw, "invalid_citations", ctx),
  };
}

function parseRetrieved(raw: unknown, ctx: string): RetrievedDocument {
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  const d = raw.document;
  const dctx = `${ctx}.document`;
  if (!isRecord(d)) throw new Error(`${dctx}: expected an object`);
  if (typeof raw.score !== "number" || !Number.isFinite(raw.score)) {
    throw new Error(`${ctx}.score: expected a finite number`);
  }
  const metadata: Record<string, string> = {};
  if (d.metadata !== undefined && d.metadata !== null) {
    if (!isRecord(d.metadata)) throw new Error(`${dctx}.metadata: expected an object`);
    for (const [k, v] of Object.entries(d.metadata)) metadata[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return {
    document: {
      doc_id: str(d, "doc_id", dctx),
      kind: str(d, "kind", dctx),
      engagement_id: str(d, "engagement_id", dctx),
      title: str(d, "title", dctx),
      text: str(d, "text", dctx),
      metadata,
    },
    score: raw.score,
    method: str(raw, "method", ctx),
  };
}

/** Check the shape of a backend Answer. Throws on a missing or mistyped field. */
export function parseAnswer(raw: unknown): Answer {
  const ctx = "Answer";
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  if (typeof raw.refused !== "boolean") throw new Error(`${ctx}.refused: expected a boolean`);
  return {
    question: str(raw, "question", ctx),
    engagement_id: str(raw, "engagement_id", ctx),
    text: str(raw, "text", ctx),
    citations: arr(raw, "citations", ctx).map((c, i) => parseCitation(c, `${ctx}.citations[${i}]`)),
    refused: raw.refused,
    refusal_reason: optStr(raw, "refusal_reason", ctx),
    retrieved: arr(raw, "retrieved", ctx).map((r, i) => parseRetrieved(r, `${ctx}.retrieved[${i}]`)),
    grounding: parseGrounding(raw.grounding, `${ctx}.grounding`),
    model: str(raw, "model", ctx),
  };
}

/** Check the shape of a backend PathNarration. */
export function parsePathNarration(raw: unknown): PathNarration {
  const ctx = "PathNarration";
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  return {
    path_id: str(raw, "path_id", ctx),
    engagement_id: str(raw, "engagement_id", ctx),
    text: str(raw, "text", ctx),
    citations: arr(raw, "citations", ctx).map((c, i) => parseCitation(c, `${ctx}.citations[${i}]`)),
    grounding: parseGrounding(raw.grounding, `${ctx}.grounding`),
    model: str(raw, "model", ctx),
  };
}

export function parseIndexResult(raw: unknown): IndexResult {
  const ctx = "IndexResult";
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  if (typeof raw.indexed !== "number") throw new Error(`${ctx}.indexed: expected a number`);
  if (!isRecord(raw.by_kind)) throw new Error(`${ctx}.by_kind: expected an object`);
  const by_kind: Record<string, number> = {};
  for (const [k, v] of Object.entries(raw.by_kind)) {
    if (typeof v !== "number") throw new Error(`${ctx}.by_kind.${k}: expected a number`);
    by_kind[k] = v;
  }
  return {
    engagement_id: str(raw, "engagement_id", ctx),
    indexed: raw.indexed,
    by_kind,
    embed_model: str(raw, "embed_model", ctx),
  };
}

export function parseAssistantStatus(raw: unknown): AssistantStatus {
  const ctx = "AssistantStatus";
  if (!isRecord(raw)) throw new Error(`${ctx}: expected an object`);
  if (typeof raw.reachable !== "boolean") throw new Error(`${ctx}.reachable: expected a boolean`);
  const avail = raw.models_available;
  const models_available = Array.isArray(avail) ? avail.filter((m): m is string => typeof m === "string") : [];
  let message: string | null = null;
  for (const key of ["detail", "error", "message"]) {
    if (typeof raw[key] === "string" && raw[key] !== "") {
      message = raw[key] as string;
      break;
    }
  }
  return {
    ollama_base_url: str(raw, "ollama_base_url", ctx),
    model: str(raw, "model", ctx),
    embed_model: str(raw, "embed_model", ctx),
    reachable: raw.reachable,
    models_available,
    message,
  };
}

/**
 * True when `name` is among the models the server listed. Ollama reports tags
 * ("llama3:latest"), so a bare name also matches its ":latest" tag.
 */
export function modelListed(name: string, available: readonly string[]): boolean {
  return available.includes(name) || (!name.includes(":") && available.includes(`${name}:latest`));
}

/** Retrieval similarity for display: three decimals, labelled by the caller. */
export function formatSimilarity(score: number): string {
  return score.toFixed(3);
}
