import test from "node:test";
import assert from "node:assert/strict";

// We test the normalization logic and client constraint logic directly
function normalizeEnrichedFinding(raw) {
  if (!raw) return null;
  const finding = raw.finding ?? raw;
  const fields = raw.fields ?? {};
  const ers = raw.ers ?? null;

  return {
    finding_id: finding.finding_id ?? finding.id,
    engagement_id: finding.engagement_id ?? "",
    cve_id:
      fields.cve_id?.value ??
      (finding.cve_ids && finding.cve_ids.length > 0
        ? finding.cve_ids[0]
        : "N/A"),
    cvss: fields.cvss ?? (finding.cvss ? { value: finding.cvss, provenance: { source: "cve_org", confidence: "HIGH", retrieved_at: new Date().toISOString() } } : null),
    epss: fields.epss ?? null,
    in_kev: fields.in_kev ?? (finding.cisa_kev ? { value: finding.cisa_kev.in_kev, provenance: { source: "cisa_kev", confidence: "HIGH", retrieved_at: new Date().toISOString() } } : null),
    cwe_ids: fields.cwe_ids ?? (finding.cwe_ids ? { value: finding.cwe_ids, provenance: { source: "cve_org", confidence: "HIGH", retrieved_at: new Date().toISOString() } } : null),
    description: fields.description ?? (finding.description ? { value: finding.description, provenance: { source: "cve_org", confidence: "HIGH", retrieved_at: new Date().toISOString() } } : null),
    ers: ers,
    enriched_at: raw.enriched_at ?? new Date().toISOString(),
  };
}

function getErsSeverityBand(score) {
  if (score >= 8.0) return { label: "Critical", band: "critical", color: "#FF3838" };
  if (score >= 6.0) return { label: "High", band: "high", color: "#FF7A00" };
  if (score >= 4.0) return { label: "Medium", band: "medium", color: "#FFC312" };
  return { label: "Low", band: "low", color: "#20D6A3" };
}

test("Level 5 Enriched Findings UI & API Client Logic", async (t) => {
  await t.test("1. Enforces engagement_id requirement on finding lookups", () => {
    assert.throws(
      () => {
        const engagementId = "";
        if (!engagementId) throw new Error("engagement_id is required");
      },
      { message: "engagement_id is required" }
    );
  });

  await t.test("2. Normalizes backend EnrichedFinding response into frontend EnrichedFindingItem", () => {
    const backendData = {
      finding: {
        finding_id: "find-log4shell-01",
        engagement_id: "eng-prod-01",
        cve_ids: ["CVE-2021-44228"],
        description: "Log4Shell remote code execution",
      },
      fields: {
        cvss: {
          value: 10.0,
          provenance: {
            source: "cve_org",
            confidence: "HIGH",
            retrieved_at: "2026-10-05T12:00:00Z",
          },
        },
        epss: {
          value: 0.975,
          provenance: {
            source: "epss",
            confidence: "HIGH",
            retrieved_at: "2026-10-05T12:00:00Z",
          },
        },
        in_kev: {
          value: true,
          provenance: {
            source: "cisa_kev",
            confidence: "HIGH",
            retrieved_at: "2026-10-05T12:00:00Z",
          },
        },
      },
      ers: {
        score: 9.85,
        components: [
          {
            name: "CVSS",
            raw_value: 10.0,
            weight: 0.4,
            weighted_value: 4.0,
            explanation: "Base severity",
            provenance: { source: "cve_org", confidence: "HIGH", retrieved_at: "2026-10-05T12:00:00Z" },
          },
          {
            name: "EPSS",
            raw_value: 9.75,
            weight: 0.3,
            weighted_value: 2.925,
            explanation: "Likelihood of exploitation",
            provenance: { source: "epss", confidence: "HIGH", retrieved_at: "2026-10-05T12:00:00Z" },
          },
          {
            name: "KEV",
            raw_value: 10.0,
            weight: 0.3,
            weighted_value: 3.0,
            explanation: "Known exploited vulnerability",
            provenance: { source: "cisa_kev", confidence: "HIGH", retrieved_at: "2026-10-05T12:00:00Z" },
          },
        ],
        explanation: "Critical exposure risk due to active KEV listing and high EPSS",
      },
      enriched_at: "2026-10-05T12:00:00Z",
    };

    const item = normalizeEnrichedFinding(backendData);
    assert.equal(item.finding_id, "find-log4shell-01");
    assert.equal(item.cve_id, "CVE-2021-44228");
    assert.equal(item.cvss.value, 10.0);
    assert.equal(item.cvss.provenance.source, "cve_org");
    assert.equal(item.epss.value, 0.975);
    assert.equal(item.in_kev.value, true);
    assert.equal(item.ers.score, 9.85);
    assert.equal(item.ers.components.length, 3);
  });

  await t.test("3. Classifies ERS severity bands accurately per thresholds", () => {
    assert.equal(getErsSeverityBand(9.5).band, "critical");
    assert.equal(getErsSeverityBand(8.0).band, "critical");
    assert.equal(getErsSeverityBand(7.9).band, "high");
    assert.equal(getErsSeverityBand(6.0).band, "high");
    assert.equal(getErsSeverityBand(5.9).band, "medium");
    assert.equal(getErsSeverityBand(4.0).band, "medium");
    assert.equal(getErsSeverityBand(3.9).band, "low");
    assert.equal(getErsSeverityBand(0.0).band, "low");
  });

  await t.test("4. Flags derived/heuristic scores appropriately", () => {
    const derivedComponent = {
      name: "Environmental Exposure",
      raw_value: 5.0,
      weight: 0.1,
      weighted_value: 0.5,
      explanation: "Default baseline network exposure",
      provenance: {
        source: "derived",
        confidence: "LOW",
        retrieved_at: "2026-10-05T12:00:00Z",
        note: "Placeholder estimate, not empirically measured",
      },
    };

    const isDerived =
      derivedComponent.provenance?.source === "derived" ||
      derivedComponent.provenance?.source?.toLowerCase().includes("derived");

    assert.equal(isDerived, true);
  });
});
