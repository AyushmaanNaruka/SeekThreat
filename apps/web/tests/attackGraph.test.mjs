import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseAttackGraphResult,
  parseEvidenceId,
  shortEvidenceLabel,
  groupPathsByGoal,
  classifyStep,
  assumptionFor,
  pathHasAssumption,
  nodeIndex,
  nodeLabel,
  ASSUMPTION_RULES,
  splitAssumedDescription,
} from "../lib/attackGraph.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");

// Real engine output: services.graph.engine.analyze + simulate_remediation over
// tests/fixtures/observations/*.json and lab/topology.yaml. Regenerate with
// tests/fixtures/gen_lab_attack_graph.py. Nothing in it is hand-written.
const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures/lab_attack_graph.json"), "utf8")
);
const graph = fixture.attack_graph;

/** Observation ids present in the repo's observation fixtures (what the engine read). */
function repoObservationIds() {
  const dir = path.join(repoRoot, "tests/fixtures/observations");
  const ids = new Set();
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const snap = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
    for (const o of snap.observations ?? []) ids.add(o.observation_id);
  }
  return ids;
}

/** name -> assumption text (folded) for every rule in core.yaml; null when none. */
function coreYamlRules() {
  const text = fs.readFileSync(path.join(repoRoot, "services/graph/rules/core.yaml"), "utf8");
  const rules = new Map();
  const blocks = text.split(/\n  - name: /).slice(1);
  for (const block of blocks) {
    const lines = block.split("\n");
    const name = lines[0].trim();
    let assumption = null;
    const idx = lines.findIndex((l) => /^ {4}assumption: >-\s*$/.test(l));
    if (idx >= 0) {
      const body = [];
      for (const l of lines.slice(idx + 1)) {
        if (!/^ {6}\S/.test(l)) break;
        body.push(l.trim());
      }
      assumption = body.join(" ");
    }
    rules.set(name, assumption);
  }
  return rules;
}

describe("parseAttackGraphResult", () => {
  it("accepts real engine output", () => {
    const parsed = parseAttackGraphResult(graph);
    assert.equal(parsed.paths.length, graph.paths.length);
    assert.ok(parsed.paths.length > 0, "fixture should contain paths");
  });

  it("paths are unranked: every score is null", () => {
    for (const p of graph.paths) assert.equal(p.score, null);
    assert.match(graph.ordering, /unranked/);
  });

  it("rejects an edge without evidence", () => {
    const bad = structuredClone(graph);
    bad.edges[0].evidence = [];
    assert.throws(() => parseAttackGraphResult(bad), /must cite evidence/);
  });

  it("rejects a missing paths array", () => {
    const bad = structuredClone(graph);
    delete bad.paths;
    assert.throws(() => parseAttackGraphResult(bad), /paths: expected an array/);
  });

  it("rejects non-objects", () => {
    assert.throws(() => parseAttackGraphResult(null));
    assert.throws(() => parseAttackGraphResult([]));
  });
});

describe("parseEvidenceId", () => {
  it("keeps the obs: prefix, since it is part of the observation id", () => {
    const ref = parseEvidenceId("obs:sha256:abc");
    assert.deepEqual(ref, { raw: "obs:sha256:abc", kind: "observation", lookupId: "obs:sha256:abc" });
  });

  it("strips finding: to get the finding id", () => {
    const ref = parseEvidenceId("finding:fnd-123", ["fnd-123"]);
    assert.equal(ref.kind, "finding");
    assert.equal(ref.lookupId, "fnd-123");
  });

  it("does not strip when the finding's own id starts with finding:", () => {
    const ref = parseEvidenceId("finding:abc", ["finding:abc"]);
    assert.equal(ref.kind, "finding");
    assert.equal(ref.lookupId, "finding:abc");
  });

  it("keeps the full topology id", () => {
    const ref = parseEvidenceId("topology:sha256:71f6");
    assert.equal(ref.kind, "topology");
    assert.equal(ref.lookupId, "topology:sha256:71f6");
  });

  it("marks unrecognized prefixes unknown instead of guessing", () => {
    assert.equal(parseEvidenceId("cve:CVE-2021-41773").kind, "unknown");
    assert.equal(parseEvidenceId("finding:").kind, "unknown");
    assert.equal(parseEvidenceId("").kind, "unknown");
  });

  it("shortens sha256 hashes for display only", () => {
    const ref = parseEvidenceId("obs:sha256:" + "a".repeat(64));
    assert.equal(shortEvidenceLabel(ref), "sha256:aaaaaaaaaaaa…");
    assert.equal(ref.lookupId, "obs:sha256:" + "a".repeat(64));
    assert.equal(shortEvidenceLabel(parseEvidenceId("finding:fnd-1")), "fnd-1");
  });

  it("every evidence id in real engine output is one of the three known kinds", () => {
    const obsIds = repoObservationIds();
    let counts = { observation: 0, finding: 0, topology: 0 };
    for (const e of graph.edges) {
      for (const id of e.evidence) {
        const ref = parseEvidenceId(id, e.finding_ids);
        assert.notEqual(ref.kind, "unknown", `unrecognized evidence id ${id}`);
        counts[ref.kind] += 1;
        if (ref.kind === "observation") {
          assert.ok(obsIds.has(ref.lookupId), `${ref.lookupId} is not a fixture observation id`);
        }
        if (ref.kind === "finding") {
          assert.ok(e.finding_ids.includes(ref.lookupId), `${ref.lookupId} not in edge finding_ids`);
        }
        if (ref.kind === "topology") {
          assert.equal(ref.lookupId, graph.topology_id);
          assert.equal(ref.lookupId, fixture.topology.topology_id);
        }
      }
    }
    assert.ok(counts.observation > 0 && counts.finding > 0 && counts.topology > 0, JSON.stringify(counts));
  });
});

describe("assumption rules mirror core.yaml", () => {
  const rules = coreYamlRules();

  it("parses every rule in core.yaml", () => {
    assert.ok(rules.size >= 7, `only parsed ${rules.size} rules`);
  });

  it("ASSUMPTION_RULES is exactly the core.yaml rules that declare an assumption", () => {
    const expected = [...rules].filter(([, a]) => a !== null).map(([n]) => n).sort();
    assert.deepEqual(Object.keys(ASSUMPTION_RULES).sort(), expected);
  });

  it("assumption text matches core.yaml verbatim", () => {
    for (const [name, text] of rules) {
      if (text !== null) assert.equal(ASSUMPTION_RULES[name], text, name);
    }
  });

  it("every rule cited by real engine output exists in core.yaml", () => {
    for (const e of graph.edges) assert.ok(rules.has(e.rule_name), e.rule_name);
  });
});

describe("classifyStep", () => {
  it("assumption rules are classed as assumptions whatever their confidence", () => {
    assert.equal(classifyStep({ rule_name: "credential_reuse_remote_login", confidence: "low" }), "assumption");
    assert.equal(classifyStep({ rule_name: "local_access_exposes_credentials", confidence: "high" }), "assumption");
    assert.ok(assumptionFor("credential_reuse_remote_login").startsWith("Not observed."));
  });

  it("other rules keep the edge's own confidence", () => {
    assert.equal(classifyStep({ rule_name: "entry_zone_service_access", confidence: "high" }), "high");
    assert.equal(classifyStep({ rule_name: "exploit_grants_code_execution", confidence: "low" }), "low");
    assert.equal(assumptionFor("entry_zone_service_access"), null);
  });

  it("does not treat inherited object keys as rules", () => {
    assert.equal(classifyStep({ rule_name: "toString", confidence: "high" }), "high");
    assert.equal(assumptionFor("constructor"), null);
  });

  it("assumption-rule edges in real output are low confidence", () => {
    const assumed = graph.edges.filter((e) => classifyStep(e) === "assumption");
    assert.ok(assumed.length > 0);
    for (const e of assumed) assert.equal(e.confidence, "low");
    assert.ok(graph.paths.some(pathHasAssumption));
  });
});

describe("splitAssumedDescription", () => {
  it("leaves descriptions without an assumption untouched", () => {
    assert.deepEqual(splitAssumedDescription("172.20.1.12:80/tcp was observed open"), {
      fact: "172.20.1.12:80/tcp was observed open",
      assumed: null,
    });
  });

  it("splits the engine-appended assumption from the observed part", () => {
    const r = splitAssumedDescription("ssh on 10.0.0.1:22/tcp reachable (shares zone x). Assumed, not observed: Not observed. X.");
    assert.equal(r.fact, "ssh on 10.0.0.1:22/tcp reachable (shares zone x)");
    assert.equal(r.assumed, "Not observed. X.");
  });

  it("every assumption-rule edge in real output carries its core.yaml assumption", () => {
    for (const e of graph.edges.filter((x) => classifyStep(x) === "assumption")) {
      const { assumed } = splitAssumedDescription(e.description);
      assert.equal(assumed, ASSUMPTION_RULES[e.rule_name], e.edge_id);
    }
  });

  it("non-assumption edges in real output carry no assumption text", () => {
    for (const e of graph.edges.filter((x) => classifyStep(x) !== "assumption")) {
      assert.equal(splitAssumedDescription(e.description).assumed, null, e.edge_id);
    }
  });
});

describe("groupPathsByGoal", () => {
  const groups = groupPathsByGoal(graph.paths, graph.nodes);

  it("puts every path in exactly one group, under its goal node", () => {
    const total = groups.reduce((n, g) => n + g.paths.length, 0);
    assert.equal(total, graph.paths.length);
    for (const g of groups) for (const p of g.paths) assert.equal(p.goal_node, g.goal_node);
    assert.equal(new Set(groups.map((g) => g.goal_node)).size, groups.length);
  });

  it("labels each group with the goal node's label", () => {
    const idx = nodeIndex(graph.nodes);
    for (const g of groups) {
      assert.equal(g.goal_known, true);
      assert.equal(g.goal_label, idx.get(g.goal_node).label);
      assert.equal(idx.get(g.goal_node).goal, true);
    }
  });

  it("orders groups by label, not by path count", () => {
    const labels = groups.map((g) => g.goal_label);
    assert.deepEqual(labels, [...labels].sort((a, b) => a.localeCompare(b, "en")));
  });

  it("keeps the server's path order inside a group", () => {
    for (const g of groups) {
      const serverOrder = graph.paths.filter((p) => p.goal_node === g.goal_node).map((p) => p.path_id);
      assert.deepEqual(g.paths.map((p) => p.path_id), serverOrder);
    }
  });

  it("falls back to the raw id for a goal missing from nodes", () => {
    const p = { ...graph.paths[0], goal_node: "exec:nowhere" };
    const [g] = groupPathsByGoal([p], graph.nodes);
    assert.equal(g.goal_label, "exec:nowhere");
    assert.equal(g.goal_known, false);
  });

  it("returns no groups for no paths", () => {
    assert.deepEqual(groupPathsByGoal([], graph.nodes), []);
  });
});

describe("nodeLabel", () => {
  it("uses the node label, or the id when unknown", () => {
    const idx = nodeIndex(graph.nodes);
    const n = graph.nodes[0];
    assert.equal(nodeLabel(idx, n.node_id), n.label);
    assert.equal(nodeLabel(idx, "missing"), "missing");
  });
});

describe("simulation fixture (real simulate_remediation output)", () => {
  it("reports removals consistent with the baseline", () => {
    const sim = fixture.simulation;
    assert.equal(sim.baseline_path_count, graph.paths.length);
    assert.equal(sim.remaining_path_count, sim.after.paths.length);
    assert.equal(sim.removed_path_ids.length, sim.baseline_path_count - sim.remaining_path_count);
    const cp = graph.chokepoints.find((c) => c.finding_id === sim.fixed_finding_ids[0]);
    assert.ok(cp);
    assert.deepEqual([...sim.removed_path_ids].sort(), [...cp.paths_broken].sort());
    parseAttackGraphResult(sim.after);
  });
});
