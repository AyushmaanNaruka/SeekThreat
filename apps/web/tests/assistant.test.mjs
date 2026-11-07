import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  citedIdsInOrder,
  formatSimilarity,
  isGrounded,
  modelListed,
  parseAnswer,
  parseAssistantStatus,
  parseGrounding,
  parseIndexResult,
  parsePathNarration,
  renderSegments,
} from "../lib/assistant.ts";
import { parseEvidenceId, shortEvidenceLabel } from "../lib/attackGraph.ts";

// TEST FIXTURE SHAPE, hand-built to mirror packages/schema/models/assistant.py
// (Answer.model_dump(mode="json")). It is NOT model output and NOT a measurement:
// every id, string and number below is a placeholder chosen to exercise the parser.
function fixtureAnswerShape() {
  return {
    question: "fixture question",
    engagement_id: "eng-fixture",
    text: "fixture text [cite:obs:sha256:aaaa] and [cite:finding:fnd-fixture].",
    citations: [
      { kind: "observation", ref_id: "obs:sha256:aaaa", excerpt: "fixture excerpt" },
      { kind: "finding", ref_id: "finding:fnd-fixture", excerpt: null },
    ],
    refused: false,
    refusal_reason: null,
    retrieved: [
      {
        document: {
          doc_id: "obs:sha256:aaaa",
          kind: "observation",
          engagement_id: "eng-fixture",
          title: "fixture title",
          text: "fixture document text",
          metadata: { k: "v" },
        },
        score: 0.5,
        method: "hybrid",
      },
    ],
    grounding: { checked_entities: [], unsupported_entities: [], invalid_citations: [] },
    model: "fixture-model",
  };
}

describe("renderSegments", () => {
  it("returns plain text unchanged when there are no markers", () => {
    assert.deepEqual(renderSegments("no markers here"), [{ type: "text", text: "no markers here" }]);
    assert.deepEqual(renderSegments(""), []);
  });

  it("splits markers out and numbers ids by first appearance", () => {
    const segs = renderSegments("A [cite:obs:sha256:1] B [cite:finding:f2] C [cite:obs:sha256:1].");
    assert.deepEqual(segs, [
      { type: "text", text: "A " },
      { type: "cite", docId: "obs:sha256:1", n: 1 },
      { type: "text", text: " B " },
      { type: "cite", docId: "finding:f2", n: 2 },
      { type: "text", text: " C " },
      { type: "cite", docId: "obs:sha256:1", n: 1 },
      { type: "text", text: "." },
    ]);
    assert.deepEqual(citedIdsInOrder(segs), ["obs:sha256:1", "finding:f2"]);
  });

  it("keeps colons inside doc ids and handles adjacent and leading/trailing markers", () => {
    const segs = renderSegments("[cite:topology:sha256:ab][cite:path:0123]end[cite:chokepoint:fnd-9]");
    assert.deepEqual(
      segs.map((s) => (s.type === "cite" ? `${s.n}:${s.docId}` : `t:${s.text}`)),
      ["1:topology:sha256:ab", "2:path:0123", "t:end", "3:chokepoint:fnd-9"]
    );
  });

  it("splits comma-separated ids in one marker and drops empty markers", () => {
    const segs = renderSegments("x [cite: obs:a , finding:b] y [cite:] z");
    assert.deepEqual(segs, [
      { type: "text", text: "x " },
      { type: "cite", docId: "obs:a", n: 1 },
      { type: "cite", docId: "finding:b", n: 2 },
      { type: "text", text: " y  z" },
    ]);
  });

  it("leaves text that only looks like a marker alone", () => {
    assert.deepEqual(renderSegments("[citation needed] [cite obs:a]"), [
      { type: "text", text: "[citation needed] [cite obs:a]" },
    ]);
  });

  it("is stateless across calls (global regex lastIndex does not leak)", () => {
    const a = renderSegments("[cite:obs:a]");
    const b = renderSegments("[cite:obs:a]");
    assert.deepEqual(a, b);
  });
});

describe("isGrounded", () => {
  it("is true only when nothing is unsupported and no citation is invalid", () => {
    assert.equal(isGrounded({ unsupported_entities: [], invalid_citations: [] }), true);
    assert.equal(isGrounded({ unsupported_entities: ["CVE-0000-0000"], invalid_citations: [] }), false);
    assert.equal(isGrounded({ unsupported_entities: [], invalid_citations: ["obs:x"] }), false);
  });

  it("ignores checked_entities (they are what was checked, not what failed)", () => {
    const g = parseGrounding({ checked_entities: ["10.0.0.1"], unsupported_entities: [], invalid_citations: [] });
    assert.equal(isGrounded(g), true);
  });
});

describe("citation id -> evidence ref", () => {
  it("maps every assistant doc id kind", () => {
    assert.deepEqual(parseEvidenceId("obs:sha256:ab"), { raw: "obs:sha256:ab", kind: "observation", lookupId: "obs:sha256:ab" });
    assert.deepEqual(parseEvidenceId("finding:fnd-1"), { raw: "finding:fnd-1", kind: "finding", lookupId: "fnd-1" });
    assert.deepEqual(parseEvidenceId("topology:sha256:cd"), { raw: "topology:sha256:cd", kind: "topology", lookupId: "topology:sha256:cd" });
    assert.deepEqual(parseEvidenceId("path:0123abcd"), { raw: "path:0123abcd", kind: "path", lookupId: "path:0123abcd" });
    assert.deepEqual(parseEvidenceId("chokepoint:fnd-1"), { raw: "chokepoint:fnd-1", kind: "chokepoint", lookupId: "fnd-1" });
  });

  it("marks empty and unknown ids unknown", () => {
    assert.equal(parseEvidenceId("path:").kind, "unknown");
    assert.equal(parseEvidenceId("chokepoint:").kind, "unknown");
    assert.equal(parseEvidenceId("source:nvd").kind, "unknown");
  });

  it("short labels drop the prefix for paths and chokepoints", () => {
    assert.equal(shortEvidenceLabel(parseEvidenceId("path:0123abcd")), "0123abcd");
    assert.equal(shortEvidenceLabel(parseEvidenceId("chokepoint:fnd-1")), "fnd-1");
  });
});

describe("shape checks", () => {
  it("accepts the fixture Answer shape", () => {
    const a = parseAnswer(fixtureAnswerShape());
    assert.equal(a.citations.length, 2);
    assert.equal(a.citations[1].excerpt, null);
    assert.equal(a.retrieved[0].document.metadata.k, "v");
    assert.equal(a.refused, false);
    assert.equal(isGrounded(a.grounding), true);
  });

  it("does not need a serialized `grounded` field", () => {
    const raw = fixtureAnswerShape();
    assert.equal("grounded" in raw.grounding, false);
    assert.doesNotThrow(() => parseAnswer(raw));
  });

  it("accepts a refusal with an absent refusal_reason as null", () => {
    const raw = { ...fixtureAnswerShape(), refused: true, citations: [], retrieved: [] };
    delete raw.refusal_reason;
    const a = parseAnswer(raw);
    assert.equal(a.refused, true);
    assert.equal(a.refusal_reason, null);
  });

  it("rejects malformed answers", () => {
    assert.throws(() => parseAnswer(null), /expected an object/);
    assert.throws(() => parseAnswer({ ...fixtureAnswerShape(), model: undefined }), /Answer.model/);
    assert.throws(() => parseAnswer({ ...fixtureAnswerShape(), refused: "no" }), /refused/);
    assert.throws(() => parseAnswer({ ...fixtureAnswerShape(), grounding: {} }), /grounding.checked_entities/);
    const badScore = fixtureAnswerShape();
    badScore.retrieved[0].score = "0.5";
    assert.throws(() => parseAnswer(badScore), /score/);
    const badCite = fixtureAnswerShape();
    badCite.citations[0] = { kind: "observation" };
    assert.throws(() => parseAnswer(badCite), /citations\[0\]\.ref_id/);
  });

  it("checks PathNarration, IndexResult and AssistantStatus", () => {
    const n = parsePathNarration({
      path_id: "path:fixture",
      engagement_id: "eng-fixture",
      text: "fixture [cite:obs:a]",
      citations: [],
      grounding: { checked_entities: [], unsupported_entities: [], invalid_citations: ["obs:a"] },
      model: "fixture-model",
    });
    assert.equal(isGrounded(n.grounding), false);
    assert.throws(() => parsePathNarration({ path_id: "p" }), /PathNarration/);

    const idx = parseIndexResult({ engagement_id: "eng-fixture", indexed: 2, by_kind: { finding: 2 }, embed_model: "fixture-embed" });
    assert.deepEqual(idx.by_kind, { finding: 2 });
    assert.throws(() => parseIndexResult({ engagement_id: "e", indexed: 1, by_kind: { finding: "2" }, embed_model: "m" }), /by_kind/);

    const st = parseAssistantStatus({
      ollama_base_url: "http://localhost:11434",
      model: "fixture-model",
      embed_model: "fixture-embed",
      reachable: false,
      models_available: [],
      detail: "connection refused",
    });
    assert.equal(st.reachable, false);
    assert.equal(st.message, "connection refused");
    assert.throws(() => parseAssistantStatus({ ollama_base_url: "u", model: "m", embed_model: "e" }), /reachable/);
  });
});

describe("helpers", () => {
  it("modelListed matches exact names and bare names against :latest", () => {
    assert.equal(modelListed("m", ["m:latest"]), true);
    assert.equal(modelListed("m:8b", ["m:8b"]), true);
    assert.equal(modelListed("m:8b", ["m:latest"]), false);
    assert.equal(modelListed("m", []), false);
  });

  it("formats retrieval similarity to three decimals", () => {
    assert.equal(formatSimilarity(0.5), "0.500");
  });
});
