import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeEnrichedFinding,
  normalizeProvenance,
  getErsSeverityBand,
  isDerived,
  ersHasDerivedInputs,
  distinctSources,
  formatCvss,
  formatEpss,
  ERS_BAND_THRESHOLDS,
  PROVENANCE_SOURCES,
  CONFIDENCE_LEVELS,
} from "../lib/findings.ts";

// Fixture mirrors the JSON the backend serializes for
// packages.schema.models.finding.EnrichedFinding (see services/enrichment/fusion.py
// and services/enrichment/ers.py). Values are test fixtures, not measurements.
const T = "2026-10-05T12:00:00Z";
const prov = (source, confidence = "high", note = null) => ({
  source,
  confidence,
  retrieved_at: T,
  note,
});

function backendFinding(overrides = {}) {
  return {
    finding: {
      finding_id: "find-fixture-01",
      engagement_id: "eng-lab-01",
      asset_id: "asset-lab-web",
      scanner: "nuclei",
      cve_ids: ["CVE-2021-44228", "CVE-2021-45046"],
      title: "Fixture finding",
      description: "",
      observation_ids: ["obs-1"],
      detected_at: T,
    },
    fields: {
      cvss_score: { value: 10.0, provenance: prov("cve.org", "high", "CVSS v3.1 (selected from CVE-2021-44228)") },
      cvss_vector: { value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", provenance: prov("cve.org") },
      epss_score: { value: 0.975, provenance: prov("first.epss") },
      epss_percentile: { value: 0.999, provenance: prov("first.epss") },
      in_kev: { value: true, provenance: prov("cisa.kev") },
      cwe_ids: { value: ["CWE-502", "CWE-917"], provenance: prov("cve.org") },
      summary: { value: "Fixture summary text", provenance: prov("cve.org") },
      ransomware_use: { value: "Known", provenance: prov("cisa.kev") },
      has_public_exploit: { value: true, provenance: prov("exploitdb") },
      exploit_ids: { value: ["50592"], provenance: prov("exploitdb") },
    },
    ers: {
      value: 0.4 * 10.0 + 0.35 * 9.75 + 0.25 * 10.0,
      components: [
        {
          name: "CVSS Base Severity",
          value: 10.0,
          weight: 0.4,
          explanation: "CVSS base severity score of 10.0/10.0 ... [cve.org].",
          provenance: prov("cve.org"),
        },
        {
          name: "EPSS Exploit Likelihood",
          value: 9.75,
          weight: 0.35,
          explanation: "FIRST EPSS v4 probability of 97.50% ... [first.epss].",
          provenance: prov("first.epss"),
        },
        {
          name: "CISA KEV Active Exploitation",
          value: 10.0,
          weight: 0.25,
          explanation: "Confirmed active exploitation in the wild ...",
          provenance: prov("cisa.kev"),
        },
      ],
    },
    ...overrides,
  };
}

describe("normalizeEnrichedFinding (real lib/findings.ts)", () => {
  it("maps the backend EnrichedFinding shape onto the UI item", () => {
    const item = normalizeEnrichedFinding(backendFinding());
    assert.equal(item.finding_id, "find-fixture-01");
    assert.equal(item.engagement_id, "eng-lab-01");
    assert.equal(item.cve_id, "CVE-2021-44228");
    assert.deepEqual(item.cve_ids, ["CVE-2021-44228", "CVE-2021-45046"]);
    assert.equal(item.cvss.value, 10.0);
    assert.equal(item.cvss.provenance.source, "cve.org");
    assert.equal(item.cvss.provenance.confidence, "high");
    assert.equal(item.cvss.provenance.note, "CVSS v3.1 (selected from CVE-2021-44228)");
    assert.equal(item.epss.value, 0.975);
    assert.equal(item.epss_percentile.value, 0.999);
    assert.equal(item.in_kev.value, true);
    assert.deepEqual(item.cwe_ids.value, ["CWE-502", "CWE-917"]);
    assert.equal(item.description.value, "Fixture summary text");
    assert.equal(item.ransomware_use.value, "Known");
    assert.equal(item.has_public_exploit.value, true);
    assert.deepEqual(item.exploit_ids.value, ["50592"]);
    assert.equal(item.has_metasploit_module, null);
    assert.equal("enriched_at" in item, false, "no fabricated enriched_at");
  });

  it("carries ERS value and each component's backend explanation", () => {
    const item = normalizeEnrichedFinding(backendFinding());
    assert.ok(Math.abs(item.ers.score - 9.9125) < 1e-9);
    assert.equal(item.ers.components.length, 3);
    const [cvss, epss] = item.ers.components;
    assert.equal(cvss.value, 10.0);
    assert.equal(cvss.weight, 0.4);
    assert.ok(Math.abs(cvss.weighted_value - 4.0) < 1e-9);
    assert.match(cvss.explanation, /CVSS base severity/);
    assert.equal(epss.provenance.source, "first.epss");
    assert.equal("explanation" in item.ers, false, "no client-fabricated ERS explanation");
    const sum = item.ers.components.reduce((s, c) => s + c.weighted_value, 0);
    assert.ok(Math.abs(sum - item.ers.score) < 1e-9);
  });

  it("keeps in_kev null as unknown, never false", () => {
    const raw = backendFinding();
    raw.fields.in_kev = {
      value: null,
      provenance: prov("derived", "low", "CISA KEV mirror not loaded; KEV status unknown"),
    };
    const item = normalizeEnrichedFinding(raw);
    assert.equal(item.in_kev.value, null);
    assert.notEqual(item.in_kev.value, false);
    assert.equal(isDerived(item.in_kev), true);
  });

  it("flags derived CVSS, EPSS and CWE placeholders and derived ERS inputs", () => {
    const raw = backendFinding();
    raw.fields.cvss_score = { value: 5.0, provenance: prov("derived", "low", "Derived placeholder CVSS") };
    raw.fields.epss_score = { value: 0.001, provenance: prov("derived", "low", "Derived placeholder EPSS") };
    raw.fields.cwe_ids = { value: ["CWE-Other"], provenance: prov("derived", "low") };
    raw.ers.components[0] = { ...raw.ers.components[0], value: 5.0, provenance: prov("derived", "low") };
    raw.ers.value = raw.ers.components.reduce((s, c) => s + c.value * c.weight, 0);

    const item = normalizeEnrichedFinding(raw);
    assert.equal(isDerived(item.cvss), true);
    assert.equal(isDerived(item.epss), true);
    assert.equal(isDerived(item.cwe_ids), true);
    assert.equal(isDerived(item.description), false);
    assert.equal(ersHasDerivedInputs(item.ers), true);
    assert.equal(ersHasDerivedInputs(normalizeEnrichedFinding(backendFinding()).ers), false);
    assert.deepEqual(distinctSources([item]).includes("derived"), false);
  });

  it("leaves ers null when the backend did not score the finding", () => {
    const item = normalizeEnrichedFinding(backendFinding({ ers: null }));
    assert.equal(item.ers, null);
    assert.equal(ersHasDerivedInputs(item.ers), false);
    const band = getErsSeverityBand(item.ers?.score ?? null);
    assert.equal(band.band, "unscored");
    assert.equal(band.label, "Not scored");
  });

  it("returns cve_id null for findings without CVEs", () => {
    const raw = backendFinding();
    raw.finding.cve_ids = [];
    assert.equal(normalizeEnrichedFinding(raw).cve_id, null);
  });

  it("throws instead of fabricating ids or provenance", () => {
    assert.throws(() => normalizeEnrichedFinding(null), /expected an object/);
    const noId = backendFinding();
    delete noId.finding.finding_id;
    assert.throws(() => normalizeEnrichedFinding(noId), /finding_id/);
    const noProv = backendFinding();
    delete noProv.fields.cvss_score.provenance;
    assert.throws(() => normalizeEnrichedFinding(noProv), /fields\.cvss_score: missing provenance/);
    assert.throws(() => normalizeProvenance({ ...prov("cve_org") }, "x"), /unknown provenance source/);
    assert.throws(() => normalizeProvenance({ ...prov("cve.org", "HIGH") }, "x"), /unknown confidence/);
  });
});

describe("getErsSeverityBand", () => {
  it("classifies by the UI display thresholds", () => {
    assert.deepEqual(ERS_BAND_THRESHOLDS, { critical: 8.0, high: 6.0, medium: 4.0 });
    assert.equal(getErsSeverityBand(9.5).band, "critical");
    assert.equal(getErsSeverityBand(8.0).band, "critical");
    assert.equal(getErsSeverityBand(7.9).band, "high");
    assert.equal(getErsSeverityBand(6.0).band, "high");
    assert.equal(getErsSeverityBand(5.9).band, "medium");
    assert.equal(getErsSeverityBand(4.0).band, "medium");
    assert.equal(getErsSeverityBand(3.9).band, "low");
    assert.equal(getErsSeverityBand(0.0).band, "low");
  });

  it("does not treat a missing score as 0.0 / Low", () => {
    assert.equal(getErsSeverityBand(null).band, "unscored");
    assert.equal(getErsSeverityBand(undefined).band, "unscored");
    assert.equal(getErsSeverityBand(Number.NaN).band, "unscored");
  });
});

describe("display helpers", () => {
  it("formats missing CVSS/EPSS as an em dash", () => {
    assert.equal(formatCvss(null), "—");
    assert.equal(formatEpss(undefined), "—");
    assert.equal(formatCvss(9.8), "9.8");
    assert.equal(formatEpss(0.975), "97.5%");
    assert.equal(formatEpss(0.975, 2), "97.50%");
  });

  it("computes distinct attributed sources from the data shown", () => {
    const item = normalizeEnrichedFinding(backendFinding());
    assert.deepEqual(distinctSources([item]), ["cisa.kev", "cve.org", "exploitdb", "first.epss"]);
    assert.deepEqual(distinctSources([]), []);
  });
});

describe("provenance contract & parity", () => {
  it("enforces exact parity with backend packages.schema.models.provenance.Source", () => {
    const expectedSources = [
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
    ];
    assert.deepEqual(Array.from(PROVENANCE_SOURCES).sort(), expectedSources.slice().sort());
    assert.equal(new Set(PROVENANCE_SOURCES).size, PROVENANCE_SOURCES.length, "no duplicate sources");
  });

  it("enforces confidence levels contract", () => {
    assert.deepEqual(Array.from(CONFIDENCE_LEVELS).sort(), ["high", "low", "medium"]);
    assert.equal(new Set(CONFIDENCE_LEVELS).size, CONFIDENCE_LEVELS.length, "no duplicate confidence levels");
  });

  it("normalizes every valid source without throwing", () => {
    for (const source of PROVENANCE_SOURCES) {
      const parsed = normalizeProvenance(
        {
          source,
          confidence: "high",
          retrieved_at: "2026-10-05T12:00:00Z",
          note: null,
        },
        "test"
      );
      assert.equal(parsed.source, source);
      assert.equal(parsed.confidence, "high");
    }
  });

  it("rejects unauthorized sources and malformed confidence", () => {
    assert.throws(
      () =>
        normalizeProvenance(
          { source: "unregistered.feed", confidence: "high", retrieved_at: "2026-10-05T12:00:00Z" },
          "ctx"
        ),
      /unknown provenance source/
    );
    assert.throws(
      () =>
        normalizeProvenance(
          { source: "nvd", confidence: "VERY_HIGH", retrieved_at: "2026-10-05T12:00:00Z" },
          "ctx"
        ),
      /unknown confidence/
    );
  });
});
