# Attack Path Validity (Layer 3 engine)

> **FIXTURE-BASED, NOT A LAB RUN. The engine ran over tests/fixtures/observations/, in which 8 of 10 lab hosts are covered only by synthetic fixtures (hand-authored tool output run through the real parsers, per tests/fixtures/observations/README.md). These verdicts check the engine and the ground truth against those facts; they are not measurements of the lab.**

**Mode:** fixture-based (not a lab run)  
**Ground truth:** `lab/ground_truth.yaml` (hop lists: `evals/golden/attack_paths_expected.yaml`)  
**Topology:** `lab/topology.yaml` (`topology:sha256:71f641e935d9d577eded9eda`)  
**Rules digest:** `rules:sha256:56d64b9ef56ac5ecce4256dc`  
**Engine limits:** max_depth 12, max_paths 1000  
**Inputs:** 34 observations, 5 findings (interim bridge, detected_at fixed at 2026-01-01T00:00:00+00:00)  
**Hosts with only synthetic observations:** bastion-ssh, cache-redis, db-primary, dmz-proxy, internal-api, internal-wiki, jenkins-ci, spring-gateway

| Fixture | Provenance |
|---|---|
| `lab_baseline.json` | real |
| `lab_dmz_extended.json` | synthetic |
| `lab_internal.json` | synthetic |
| `lab_data.json` | synthetic |
| `lab_extended_nuclei.json` | synthetic |

## Matching rules

- **host_sequence**: engine machines mapped to ground-truth hosts by ip/secondary_ip; attacker node skipped; consecutive repeats collapsed
- **strict**: host sequence equals the expected host list exactly
- **lenient**: expected hosts appear in order; other hosts may appear anywhere
- **visited**: a host counts as visited at any capability, network access included

## Verdicts

Strict FOUND 2/3, lenient FOUND 2/3. Ground truth infeasible per topology: path-1.

| Path | Hosts | Feasible per topology | Strict | Lenient | Final host reached as |
|---|---|---|---|---|---|
| path-1 | dvwa -> internal-api -> db-primary | **no** | NOT FOUND (0) | NOT FOUND (0) | - |
| path-2 | spring-gateway -> jenkins-ci -> bastion-ssh -> cache-redis | yes | FOUND (1) | FOUND (1) | network_access |
| path-3 | dmz-proxy -> internal-wiki | yes | FOUND (1) | FOUND (4) | code_execution |

### path-1

path-1: strict NOT FOUND (0 paths), lenient NOT FOUND (0 paths). Reasons: hop dvwa -> internal-api unreachable per lab/topology.yaml (ground truth infeasible): dvwa (dmz) and internal-api (internal) share no zone and no flow connects them | hop internal-api -> db-primary unreachable per lab/topology.yaml (ground truth infeasible): internal-api (internal) and db-primary (data) share no zone and no flow connects them | no observed vulnerability on dvwa (172.20.1.10) in the fixtures (no vuln_candidate observation, so no finding), so the engine has no foothold there | no foothold on internal-api: CVE-2022-29361 unclassified: no capability rule matches its evidence (CWE-444, tag:cve, tag:cve2022, tag:smuggling, tag:werkzeug)

Feasibility (lab/topology.yaml):

- attacker -> dvwa: ok (dvwa is in attacker-entry zone dmz)
- dvwa -> internal-api: **INFEASIBLE** (dvwa (dmz) and internal-api (internal) share no zone and no flow connects them)
- internal-api -> db-primary: **INFEASIBLE** (internal-api (internal) and db-primary (data) share no zone and no flow connects them)

| Host | CVE | Finding in fixtures | Classified | Exploited on example |
|---|---|---|---|---|
| dvwa | CVE-2021-41773 | False | None | None |
| db-primary | CVE-2020-14349 | False | None | None |

Diagnosis:

- hop dvwa -> internal-api unreachable per lab/topology.yaml (ground truth infeasible): dvwa (dmz) and internal-api (internal) share no zone and no flow connects them
- hop internal-api -> db-primary unreachable per lab/topology.yaml (ground truth infeasible): internal-api (internal) and db-primary (data) share no zone and no flow connects them
- no observed vulnerability on dvwa (172.20.1.10) in the fixtures (no vuln_candidate observation, so no finding), so the engine has no foothold there
- no foothold on internal-api: CVE-2022-29361 unclassified: no capability rule matches its evidence (CWE-444, tag:cve, tag:cve2022, tag:smuggling, tag:werkzeug)

### path-2

path-2: strict FOUND (1 paths), lenient FOUND (1 paths); final host cache-redis reached as network_access; CVE-2022-22947 on spring-gateway exploited; CVE-2024-23897 on jenkins-ci exploited; CVE-2022-0543 on cache-redis NOT exploited on example path (no vuln_candidate observation reports CVE-2022-0543 on cache-redis in the fixtures)

Feasibility (lab/topology.yaml):

- attacker -> spring-gateway: ok (spring-gateway is in attacker-entry zone dmz)
- spring-gateway -> jenkins-ci: ok (spring-gateway and jenkins-ci share zone internal)
- jenkins-ci -> bastion-ssh: ok (jenkins-ci and bastion-ssh share zone internal)
- bastion-ssh -> cache-redis: ok (bastion-ssh and cache-redis share zone data)

| Host | CVE | Finding in fixtures | Classified | Exploited on example |
|---|---|---|---|---|
| spring-gateway | CVE-2022-22947 | True | True | True |
| jenkins-ci | CVE-2024-23897 | True | True | True |
| cache-redis | CVE-2022-0543 | False | None | False |

Example path `path:edc9f9b15b151632` (confidence low):

`attacker:dmz -> access:172.20.1.13:8080/tcp -> exec:spring-gateway -> access:172.20.2.25:8080/tcp -> read:host:172.20.2.25 -> creds:host:172.20.2.25 -> exec:bastion-ssh -> access:172.20.3.20:6379/tcp`

Rules: entry_zone_service_access, exploit_grants_code_execution, intra_zone_service_access, exploit_grants_file_read, local_access_exposes_credentials, credential_reuse_remote_login, intra_zone_service_access

### path-3

path-3: strict FOUND (1 paths), lenient FOUND (4 paths); final host internal-wiki reached as code_execution; CVE-2021-23017 on dmz-proxy exploited; CVE-2022-26134 on internal-wiki exploited

Feasibility (lab/topology.yaml):

- attacker -> dmz-proxy: ok (dmz-proxy is in attacker-entry zone dmz)
- dmz-proxy -> internal-wiki: ok (dmz-proxy and internal-wiki share zone internal)

| Host | CVE | Finding in fixtures | Classified | Exploited on example |
|---|---|---|---|---|
| dmz-proxy | CVE-2021-23017 | True | True | True |
| internal-wiki | CVE-2022-26134 | True | True | True |

Example path `path:2e2fafa46fdccf32` (confidence low):

`attacker:dmz -> access:172.20.1.12:80/tcp -> exec:dmz-proxy -> access:172.20.2.40:8090/tcp -> exec:host:172.20.2.40`

Rules: entry_zone_service_access, exploit_grants_code_execution, intra_zone_service_access, exploit_grants_code_execution

## Ground-truth contradictions (lab/ground_truth.yaml vs lab/topology.yaml)

Reported, not corrected. The owner decides whether the lab wiring or the ground truth changes.

| Host | Claim | Why it fails |
|---|---|---|
| internal-api | reachable_from dvwa | dvwa (dmz) and internal-api (internal) share no zone and no flow connects them |
| db-primary | reachable_from internal-api | internal-api (internal) and db-primary (data) share no zone and no flow connects them |
| cache-redis | reachable_from internal-api | internal-api (internal) and cache-redis (data) share no zone and no flow connects them |

## Engine output

- Total paths: 22 (truncated: False)
- By confidence: high 2, medium 0, low 20
- By goal kind: code_execution 10, network_access 12
- Paths ending in network access to a crown-jewel zone: 12
- Unzoned addresses: none

### Unclassified findings

| Host | CVEs | Reason |
|---|---|---|
| internal-api | CVE-2022-29361 | no capability rule matches its evidence (CWE-444, tag:cve, tag:cve2022, tag:smuggling, tag:werkzeug) |

### Chokepoints

| Rank | Host | CVEs | Paths broken | Goals cut |
|---|---|---|---|---|
| 1 | spring-gateway | CVE-2022-22947 | 11 | exec:spring-gateway |
| 2 | dmz-proxy | CVE-2021-23017 | 11 | exec:dmz-proxy |
| 3 | internal-wiki | CVE-2022-26134 | 8 | exec:host:172.20.2.40 |
| 4 | jenkins-ci | CVE-2024-23897 | 6 | - |

## Spurious-path analysis

Rule: on route = path's host sequence is a prefix of some expected host list. Off-route paths are not necessarily wrong; ground truth lists three chains, not every chain.

- On route: 5; off route: 17
- Goal hosts (paths ending there): bastion-ssh 6, cache-redis 6, db-primary 6, dmz-proxy 1, internal-wiki 2, spring-gateway 1
- Goal hosts not on any expected path: none

| Off-route host sequence | Paths |
|---|---|
| dmz-proxy -> bastion-ssh | 1 |
| dmz-proxy -> bastion-ssh -> cache-redis | 1 |
| dmz-proxy -> bastion-ssh -> db-primary | 1 |
| dmz-proxy -> internal-wiki -> bastion-ssh | 1 |
| dmz-proxy -> internal-wiki -> bastion-ssh -> cache-redis | 1 |
| dmz-proxy -> internal-wiki -> bastion-ssh -> db-primary | 1 |
| dmz-proxy -> jenkins-ci -> bastion-ssh | 1 |
| dmz-proxy -> jenkins-ci -> bastion-ssh -> cache-redis | 1 |
| dmz-proxy -> jenkins-ci -> bastion-ssh -> db-primary | 1 |
| spring-gateway -> bastion-ssh | 1 |
| spring-gateway -> bastion-ssh -> cache-redis | 1 |
| spring-gateway -> bastion-ssh -> db-primary | 1 |
| spring-gateway -> internal-wiki | 1 |
| spring-gateway -> internal-wiki -> bastion-ssh | 1 |
| spring-gateway -> internal-wiki -> bastion-ssh -> cache-redis | 1 |
| spring-gateway -> internal-wiki -> bastion-ssh -> db-primary | 1 |
| spring-gateway -> jenkins-ci -> bastion-ssh -> db-primary | 1 |
