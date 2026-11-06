"""Regenerate apps/web/tests/fixtures/lab_attack_graph.json from the real engine.

Runs services.graph.engine.analyze (and simulate_remediation for the top-ranked
chokepoint) over tests/fixtures/observations/*.json, with findings built by
services.normalize.interim_bridge.findings_from_observations, against
lab/topology.yaml. Observations are re-homed to the topology's engagement id.
Nothing in the output is hand-written.

From the repo root:
    PYTHONPATH=. python apps/web/tests/fixtures/gen_lab_attack_graph.py         apps/web/tests/fixtures/lab_attack_graph.json
"""

import glob
import json
import sys
from datetime import datetime, timezone

import yaml

from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.topology import NetworkTopology
from services.graph.engine import analyze, simulate_remediation
from services.normalize.interim_bridge import findings_from_observations

obs: list[Observation] = []
for p in sorted(glob.glob("tests/fixtures/observations/*.json")):
    with open(p, encoding="utf-8") as fh:
        obs.extend(ScanResult.model_validate(json.load(fh)).observations)
with open("lab/topology.yaml", encoding="utf-8") as fh:
    topo = NetworkTopology.model_validate(yaml.safe_load(fh))
eng = topo.engagement_id
obs = [o.model_copy(update={"engagement_id": eng}) for o in obs]
findings = findings_from_observations(obs, datetime(2026, 11, 6, tzinfo=timezone.utc))
res = analyze(engagement_id=eng, observations=obs, findings=findings, topology=topo)
out = {"topology": topo.model_dump(mode="json"), "attack_graph": res.model_dump(mode="json")}
if res.chokepoints:
    sim = simulate_remediation(
        baseline=res,
        fixed_finding_ids=[res.chokepoints[0].finding_id],
        engagement_id=eng,
        observations=obs,
        findings=findings,
        topology=topo,
    )
    out["simulation"] = sim.model_dump(mode="json")
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as fh:
    json.dump(out, fh, sort_keys=True, separators=(",", ":"))
    fh.write("\n")
print(
    len(res.paths),
    len(res.edges),
    len(res.chokepoints),
    len(res.unclassified_findings),
    res.unzoned_addresses,
    res.truncated,
)
