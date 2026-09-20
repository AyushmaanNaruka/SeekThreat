# Observation fixtures

`ScanResult` snapshots (`RawArtifact` + the `Observation` tuples it parses to). This is
what lets Layers 2 through 4 be tested offline, on a laptop, in seconds, with no lab
running (`docs/02-architecture.md`, "Why an append-only fact store").

## Real captures

- **`lab_baseline.json`** — real `nmap -sV` output captured against the lab's `dvwa`
  (172.20.1.10) and `juiceshop` (172.20.1.11) containers, parsed by
  `services/scanners/nmap_xml.py`. Source XML: `tests/fixtures/nmap/lab_baseline.xml`.
  Covers the DMZ segment only, no vulnerability observations.

The real `tests/fixtures/nuclei/lab_baseline.jsonl` capture (dvwa's `CVE-2021-41773`, plus
an unrelated `CVE-2021-44228`/`nginx-version` pair against hosts outside this lab's IP
ranges) has not yet been folded into a matching `observations/` snapshot; it is exercised
directly by `tests/unit/test_nuclei_json.py`.

## Synthetic (hand-authored tool output run through the real parsers)

Docker Hub image pulls for the lab's other eight host images are currently failing on
the development machine (see DECISIONS.md D-018/D-019 for the underlying CDN issue), so
nobody can capture real scans of them yet. The files below stand in until real captures
replace them. Every host/port/service/CVE fact in them is copied verbatim from
`lab/ground_truth.yaml` — nothing is invented — and every file is produced by
`scripts/build_observation_fixtures.py`, which builds a `RawArtifact` exactly the way
`ScannerAdapter._artifact` does and feeds it to the real `parse_nmap_xml` /
`parse_nuclei_json` functions. No `Observation` in these files was constructed by hand.

**They are not real scanner captures.** Replace each one with a real capture (rerun
`scripts/build_observation_fixtures.py`'s equivalent against actual scan output) as soon
as the corresponding image can be pulled, and delete the synthetic source fixture it was
built from.

| Observations file | Source fixture | Segment | Hosts |
|---|---|---|---|
| `lab_dmz_extended.json` | `tests/fixtures/nmap/lab_dmz_extended.xml` | dmz | dmz-proxy (172.20.1.12), spring-gateway (172.20.1.13) |
| `lab_internal.json` | `tests/fixtures/nmap/lab_internal.xml` | internal | internal-api (172.20.2.10), jenkins-ci (172.20.2.25), internal-wiki (172.20.2.40), bastion-ssh (172.20.2.50) |
| `lab_data.json` | `tests/fixtures/nmap/lab_data.xml` | data | db-primary (172.20.3.10), cache-redis (172.20.3.20) |
| `lab_extended_nuclei.json` | `tests/fixtures/nuclei/lab_extended.jsonl` | dmz + internal | dmz-proxy, spring-gateway, internal-api, jenkins-ci, internal-wiki — `vuln_candidate` observations only |

Scans are grouped one file per network segment (mirroring how an operator would actually
run `nmap -sV` against this lab a segment at a time), except nuclei's HTTP template
matches, which are aggregated into one NDJSON run across the dmz/internal HTTP hosts —
the same shape a single `nuclei -l <targets>` invocation would produce.

Nuclei findings are deliberately limited to hosts nuclei could plausibly flag over HTTP:
the five HTTP-service hosts above. `bastion-ssh` (raw SSH), `db-primary` (raw PostgreSQL
wire protocol) and `cache-redis` (raw Redis wire protocol) are not HTTP services, so a
real nuclei HTTP-template run would not fingerprint them — no synthetic nuclei findings
were authored for those three.

## Coverage

Across `lab_baseline.json` + the four synthetic files above, all 10 hosts in
`lab/ground_truth.yaml` are covered by at least `HOST_UP`/`PORT_OPEN`/`SERVICE_VERSION`
observations, and 5 of the 8 HTTP-exposed CVEs have a matching `vuln_candidate`
observation. `tests/unit/test_observation_fixtures.py` asserts this cross-consistency
the same way `tests/unit/test_ground_truth.py` cross-checks `ground_truth.yaml` against
`docker-compose.yml`.
