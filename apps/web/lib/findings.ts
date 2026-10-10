/**
 * Pure enriched-finding logic: backend-shape normalization, ERS display bands,
 * derived-value detection and display formatting.
 *
 * Kept free of imports (and of non-erasable TypeScript syntax) so the Node test
 * runner can import it directly via type stripping, exactly like lib/polling.ts.
 *
 * Backend contract: packages/schema/models/{finding,scoring,provenance}.py and
 * services/enrichment/fusion.py. The backend sends an `EnrichedFinding`:
 *   { finding: Finding, fields: { <key>: { value, provenance } }, ers: ExposureRiskScore | null }
 */

// ---------------------------------------------------------------------------
// Types (mirror packages/schema)
// ---------------------------------------------------------------------------

/** Values of `packages.schema.models.provenance.Source`. */
export const PROVENANCE_SOURCES = [
  "cve.org",
  "cisa.vulnrichment",
  "cisa.kev",
  "first.epss",
  "nvd",
  "enisa.euvd",
  "osv.dev",
  "github.advisories",
  "exploitdb",
  "metasploit",
  "bron",
  "derived",
  "scanner",
] as const;

export type ProvenanceSource = (typeof PROVENANCE_SOURCES)[number];

/** Values of `packages.schema.models.provenance.Confidence` (lowercase on the wire). */
export const CONFIDENCE_LEVELS = ["high", "medium", "low"] as const;

export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];

export interface ProvenanceInfo {
  source: ProvenanceSource;
  confidence: ConfidenceLevel;
  retrieved_at: string;
  note: string | null;
}

export interface AttributedValue<T> {
  value: T;
  provenance: ProvenanceInfo;
}

/** `ScoreComponent`: one ERS input with its backend-rendered explanation. */
export interface ScoreComponentInfo {
  name: string;
  /** Component value on the 0-10 scale. */
  value: number;
  weight: number;
  /** value * weight, i.e. this component's contribution to the composite. */
  weighted_value: number;
  explanation: string;
  provenance: ProvenanceInfo;
}

/** `ExposureRiskScore`: value is the weighted sum of its components. */
export interface ERSInfo {
  score: number;
  components: ScoreComponentInfo[];
}

export interface EnrichedFindingItem {
  finding_id: string;
  engagement_id: string;
  asset_id: string;
  scanner: string;
  title: string;
  detected_at: string;
  cve_ids: string[];
  /** First CVE on the finding, or null if the scanner reported none. */
  cve_id: string | null;
  cvss: AttributedValue<number | null> | null;
  epss: AttributedValue<number | null> | null;
  epss_percentile: AttributedValue<number | null> | null;
  /** value null = KEV status unknown (never treated as "not in KEV"). */
  in_kev: AttributedValue<boolean | null> | null;
  cwe_ids: AttributedValue<string[]> | null;
  description: AttributedValue<string> | null;
  ransomware_use: AttributedValue<string | null> | null;
  has_public_exploit: AttributedValue<boolean | null> | null;
  exploit_ids: AttributedValue<string[]> | null;
  has_metasploit_module: AttributedValue<boolean | null> | null;
  metasploit_modules: AttributedValue<string[]> | null;
  /** null = the backend did not score this finding. */
  ers: ERSInfo | null;
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

type RawRecord = Record<string, unknown>;

function isRecord(v: unknown): v is RawRecord {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isSource(v: unknown): v is ProvenanceSource {
  return typeof v === "string" && (PROVENANCE_SOURCES as readonly string[]).includes(v);
}

function isConfidence(v: unknown): v is ConfidenceLevel {
  return typeof v === "string" && (CONFIDENCE_LEVELS as readonly string[]).includes(v);
}

/** Parse a backend Provenance. Throws rather than inventing attribution. */
export function normalizeProvenance(raw: unknown, context: string): ProvenanceInfo {
  if (!isRecord(raw)) {
    throw new Error(`${context}: missing provenance`);
  }
  if (!isSource(raw.source)) {
    throw new Error(`${context}: unknown provenance source ${JSON.stringify(raw.source)}`);
  }
  if (!isConfidence(raw.confidence)) {
    throw new Error(`${context}: unknown confidence ${JSON.stringify(raw.confidence)}`);
  }
  if (typeof raw.retrieved_at !== "string" || raw.retrieved_at === "") {
    throw new Error(`${context}: missing provenance.retrieved_at`);
  }
  return {
    source: raw.source,
    confidence: raw.confidence,
    retrieved_at: raw.retrieved_at,
    note: typeof raw.note === "string" ? raw.note : null,
  };
}

function toNumberOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function toBoolOrNull(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function toStringList(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

function attributed<T>(
  fields: RawRecord,
  key: string,
  coerce: (v: unknown) => T
): AttributedValue<T> | null {
  const raw = fields[key];
  if (raw === undefined || raw === null) return null;
  if (!isRecord(raw)) throw new Error(`fields.${key}: expected an attributed value`);
  return {
    value: coerce(raw.value),
    provenance: normalizeProvenance(raw.provenance, `fields.${key}`),
  };
}

function normalizeErs(raw: unknown): ERSInfo | null {
  if (raw === undefined || raw === null) return null;
  if (!isRecord(raw)) throw new Error("ers: expected an object");
  const score = toNumberOrNull(raw.value);
  if (score === null) throw new Error("ers.value: expected a number");
  const comps = Array.isArray(raw.components) ? raw.components : [];
  return {
    score,
    components: comps.map((c, i) => {
      if (!isRecord(c)) throw new Error(`ers.components[${i}]: expected an object`);
      const value = toNumberOrNull(c.value);
      const weight = toNumberOrNull(c.weight);
      if (value === null || weight === null) {
        throw new Error(`ers.components[${i}]: value and weight must be numbers`);
      }
      return {
        name: String(c.name ?? ""),
        value,
        weight,
        weighted_value: value * weight,
        explanation: String(c.explanation ?? ""),
        provenance: normalizeProvenance(c.provenance, `ers.components[${i}]`),
      };
    }),
  };
}

/**
 * Normalize a backend `EnrichedFinding` JSON object for the UI.
 * Throws on malformed input instead of fabricating ids, timestamps or provenance.
 */
export function normalizeEnrichedFinding(raw: unknown): EnrichedFindingItem {
  if (!isRecord(raw)) throw new Error("EnrichedFinding: expected an object");
  const finding = raw.finding;
  if (!isRecord(finding)) throw new Error("EnrichedFinding.finding: missing");
  if (typeof finding.finding_id !== "string" || finding.finding_id === "") {
    throw new Error("EnrichedFinding.finding.finding_id: missing");
  }
  const fields = isRecord(raw.fields) ? raw.fields : {};
  const cveIds = toStringList(finding.cve_ids);

  return {
    finding_id: finding.finding_id,
    engagement_id: String(finding.engagement_id ?? ""),
    asset_id: String(finding.asset_id ?? ""),
    scanner: String(finding.scanner ?? ""),
    title: String(finding.title ?? ""),
    detected_at: String(finding.detected_at ?? ""),
    cve_ids: cveIds,
    cve_id: cveIds.length > 0 ? cveIds[0] : null,
    cvss: attributed(fields, "cvss_score", toNumberOrNull),
    epss: attributed(fields, "epss_score", toNumberOrNull),
    epss_percentile: attributed(fields, "epss_percentile", toNumberOrNull),
    in_kev: attributed(fields, "in_kev", toBoolOrNull),
    cwe_ids: attributed(fields, "cwe_ids", toStringList),
    description: attributed(fields, "summary", (v) => (v == null ? "" : String(v))),
    ransomware_use: attributed(fields, "ransomware_use", (v) => (v == null ? null : String(v))),
    has_public_exploit: attributed(fields, "has_public_exploit", toBoolOrNull),
    exploit_ids: attributed(fields, "exploit_ids", toStringList),
    has_metasploit_module: attributed(fields, "has_metasploit_module", toBoolOrNull),
    metasploit_modules: attributed(fields, "metasploit_modules", toStringList),
    ers: normalizeErs(raw.ers),
  };
}

// ---------------------------------------------------------------------------
// Derived (placeholder) detection
// ---------------------------------------------------------------------------

/** True when the value is a backend placeholder (Source.DERIVED), not a measurement. */
export function isDerived(attr: { provenance: ProvenanceInfo } | null | undefined): boolean {
  return attr?.provenance.source === "derived";
}

/** True when any ERS component was computed from a derived placeholder input. */
export function ersHasDerivedInputs(ers: ERSInfo | null): boolean {
  return ers !== null && ers.components.some((c) => c.provenance.source === "derived");
}

// ---------------------------------------------------------------------------
// ERS severity bands
// ---------------------------------------------------------------------------

/**
 * ERS display bands. These thresholds are a UI display convention only; the
 * backend defines no ERS severity bands. They are not calibrated against
 * measured outcomes.
 */
export const ERS_BAND_THRESHOLDS = { critical: 8.0, high: 6.0, medium: 4.0 } as const;

export type ErsBand = "critical" | "high" | "medium" | "low" | "unscored";

export interface ErsBandInfo {
  label: string;
  band: ErsBand;
  color: string;
  bg: string;
  border: string;
}

/** Map an ERS value to its display band. null (not scored) gets a neutral band. */
export function getErsSeverityBand(score: number | null | undefined): ErsBandInfo {
  if (score === null || score === undefined || !Number.isFinite(score)) {
    return { label: "Not scored", band: "unscored", color: "#A7B2B5", bg: "rgba(131, 149, 167, 0.1)", border: "rgba(131, 149, 167, 0.35)" };
  }
  if (score >= ERS_BAND_THRESHOLDS.critical) return { label: "Critical", band: "critical", color: "#FF3838", bg: "rgba(255, 56, 56, 0.15)", border: "rgba(255, 56, 56, 0.4)" };
  if (score >= ERS_BAND_THRESHOLDS.high) return { label: "High", band: "high", color: "#FF7A00", bg: "rgba(255, 122, 0, 0.15)", border: "rgba(255, 122, 0, 0.4)" };
  if (score >= ERS_BAND_THRESHOLDS.medium) return { label: "Medium", band: "medium", color: "#FFC312", bg: "rgba(255, 195, 18, 0.15)", border: "rgba(255, 195, 18, 0.4)" };
  return { label: "Low", band: "low", color: "#20D6A3", bg: "rgba(32, 214, 163, 0.15)", border: "rgba(32, 214, 163, 0.4)" };
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

export const MISSING_VALUE = "—"; // em dash

export function formatCvss(value: number | null | undefined): string {
  return value === null || value === undefined ? MISSING_VALUE : value.toFixed(1);
}

export function formatEpss(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? MISSING_VALUE : `${(value * 100).toFixed(digits)}%`;
}

/** Distinct non-derived sources attributed on the given findings' fields and ERS components. */
export function distinctSources(findings: EnrichedFindingItem[]): ProvenanceSource[] {
  const seen = new Set<ProvenanceSource>();
  const fieldKeys = [
    "cvss",
    "epss",
    "epss_percentile",
    "in_kev",
    "cwe_ids",
    "description",
    "ransomware_use",
    "has_public_exploit",
    "exploit_ids",
    "has_metasploit_module",
    "metasploit_modules",
  ] as const;
  for (const f of findings) {
    for (const key of fieldKeys) {
      const attr = f[key];
      if (attr && attr.provenance.source !== "derived") seen.add(attr.provenance.source);
    }
    for (const c of f.ers?.components ?? []) {
      if (c.provenance.source !== "derived") seen.add(c.provenance.source);
    }
  }
  return [...seen].sort();
}
