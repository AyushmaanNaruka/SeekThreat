# Task 6 Walkthrough — Lab Expansion & Ground Truth Baseline (`lab/`)

> **Layer:** 1 (Collection) & Cross-cutting Evaluation Baseline  
> **Task:** 6 of 7  
> **Status:** ✅ Complete — 175/175 tests passing (+11 new automated ground truth & topology tests)  
> **Files touched:** 2 new files, 4 modified  

---

## 1. Goal

Expand the deliberately vulnerable test network from 2 containers to a comprehensive **10-host multi-tier network** partitioned across 3 isolated subnets (`dmz`, `internal`, `data`), and produce the authoritative [`lab/ground_truth.yaml`](file:///e:/SeekThreat/SeekThreat/lab/ground_truth.yaml) to serve as the evaluation baseline denominator for Track A (accuracy, precision, recall, F1) and Track B (attack path validity) metrics.

---

## 2. Files Delivered & Modified

| File | Type | Purpose |
|---|:---:|---|
| [`lab/docker-compose.yml`](file:///e:/SeekThreat/SeekThreat/lab/docker-compose.yml) | Modified | 10 vulnerable target containers + 1 auditor scanner container across 3 isolated subnets (`dmz`, `internal`, `data`). |
| [`lab/ground_truth.yaml`](file:///e:/SeekThreat/SeekThreat/lab/ground_truth.yaml) | New | Authoritative ground truth denominator recording 10 hosts, 10 CVEs with CVSS, 3 multi-hop attack paths, and false positives. |
| [`tests/unit/test_ground_truth.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_ground_truth.py) | New | 11 unit tests verifying schema, CIDRs, 8–12 host count, and cross-consistency with compose. |
| [`DECISIONS.md`](file:///e:/SeekThreat/SeekThreat/DECISIONS.md) | Modified | Added ADR **D-016** documenting lab topology, multi-hop chains, and ground truth schema. |
| [`docs/mayank_implementation/build.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/build.md) | Modified | Task 6 marked complete; checklist updated to 175/175 tests. |
| [`docs/mayank_implementation/level_1_status.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level_1_status.md) | Modified | Task 6 marked complete and test counts synchronized. |

---

## 3. Network Topology & Target Inventory

### 3.1 Network Subnets (All Isolated with `internal: true`)
- **`dmz` (`172.20.1.0/24`)**: Perimeter services facing external ingress and reachable by the scanner.
- **`internal` (`172.20.2.0/24`)**: Internal app tier, CI/CD, and knowledge base. Not directly reachable from external networks.
- **`data` (`172.20.3.0/24`)**: Crown jewel databases and memory caches.

### 3.2 10 Target Hosts & 1 Scanner Container

| Host | Segment(s) | IP(s) | Service & Version | Expected CVE / Flaw | CVSS | Role |
|---|---|---|---|---|:---:|---|
| **`dvwa`** | `dmz` | `172.20.1.10` | Apache 2.4.49, PHP 7.4 | CVE-2021-41773 | 7.5 | DMZ Web Application (SSRF pivot) |
| **`juiceshop`** | `dmz` | `172.20.1.11` | Node.js Express 4.17.1 | CVE-2020-7699 | 7.3 | Customer portal |
| **`dmz-proxy`** | `dmz`, `internal` | `172.20.1.12`, `172.20.2.12` | Nginx 1.18.0 | CVE-2021-23017 | 7.7 | Reverse proxy / dual-homed bridge |
| **`spring-gateway`** | `dmz`, `internal` | `172.20.1.13`, `172.20.2.13` | Spring Cloud Gateway 3.1.0 | CVE-2022-22947 | 9.8 | API Gateway with Actuator RCE |
| **`internal-api`** | `internal` | `172.20.2.10` | Werkzeug/Flask 2.0.1 | CVE-2022-29361 | 7.5 | Internal microservice |
| **`jenkins-ci`** | `internal` | `172.20.2.25` | Jenkins 2.441 | CVE-2024-23897 | 9.8 | CI/CD holding build credentials |
| **`internal-wiki`** | `internal` | `172.20.2.40` | Confluence 7.18.0 | CVE-2022-26134 | 9.8 | Internal documentation portal |
| **`bastion-ssh`** | `internal`, `data` | `172.20.2.50`, `172.20.3.50` | OpenSSH 8.2p1 | CVE-2020-15778 | 6.8 | SSH gateway between internal & data |
| **`db-primary`** | `data` | `172.20.3.10` | PostgreSQL 12.4 | CVE-2020-14349 | 7.2 | Main customer database |
| **`cache-redis`** | `data` | `172.20.3.20` | Redis 5.0.7 | CVE-2022-0543 | 10.0 | Memory cache with Lua escape RCE |
| **`scanner`** | `dmz` | `172.20.1.250` | Nmap / Nuclei | Auditor / Tool fixture runner | — | Isolated scanner container |

---

## 4. Multi-Hop Attack Path Design

The ground truth explicitly specifies 3 realistic attack paths designed for testing Layer 3 (Graph Engine):

1. **Attack Path 1 — SSRF Pivot to Crown Jewel Database (`path-1`, Severity: Critical)**:
   - External scanner probes `dvwa` (172.20.1.10).
   - Exploit CVE-2021-41773 path traversal / SSRF on `dvwa`.
   - Network reachability `dvwa` -> `internal-api` (172.20.2.10).
   - Exfiltrate database credentials leaked by `internal-api`.
   - Network reachability `internal-api` -> `db-primary` (172.20.3.10).
   - Exploit CVE-2020-14349 to dump crown jewel customer data.

2. **Attack Path 2 — API Gateway RCE to Internal CI to Data RCE (`path-2`, Severity: Critical)**:
   - External scanner discovers `spring-gateway` (172.20.1.13).
   - Exploit CVE-2022-22947 (SpEL code injection) for initial RCE on gateway.
   - Pivot across internal network to `jenkins-ci` (172.20.2.25).
   - Exploit CVE-2024-23897 on Jenkins CLI to read `/root/.ssh/id_rsa`.
   - SSH login to `bastion-ssh` (172.20.2.50) using exfiltrated key.
   - Pivot from bastion to `cache-redis` on data network (172.20.3.20).
   - Exploit CVE-2022-0543 Lua sandbox escape to achieve root RCE on database host.

3. **Attack Path 3 — Proxy Header Smuggling to Confluence Wiki RCE (`path-3`, Severity: High)**:
   - External scanner probes `dmz-proxy` (172.20.1.12).
   - Exploit CVE-2021-23017 or routing bypass to access `internal-wiki` (172.20.2.40).
   - Exploit CVE-2022-26134 unauthenticated OGNL injection on `internal-wiki`.
   - Full compromise and exfiltration of internal knowledge base.

---

## 5. Automated Verification & Guardrails

We created `tests/unit/test_ground_truth.py` containing 11 tests:
- **`test_top_level_metadata`**: Configuration name, non-empty description, created timestamp.
- **`test_network_subnets`**: Exactly 3 subnets (`dmz`, `internal`, `data`) with valid IPv4 `/24` CIDRs.
- **`test_host_count_within_specification`**: Asserts 8 <= count <= 12 (10 target hosts), unique host names, and unique IPs.
- **`test_host_ip_matches_segment`**: Asserts all host primary and secondary IPs fall strictly within declared subnet CIDRs.
- **`test_services_definition`**: Verifies ports are in range [1, 65535], valid service types, products, and version strings.
- **`test_expected_cves_schema`**: Asserts standard regex `CVE-\d{4}-\d+`, valid confidence tags (`certain`, `likely`, `possible`), CVSS scores [0.0, 10.0], and non-empty notes.
- **`test_expected_attack_paths`**: Asserts >= 3 multi-hop paths, valid severity rating, and >= 3 sequential steps per path.
- **`test_known_false_positives`**: Verifies scanner name, target host, and technical justification.
- **`test_docker_compose_networks_isolated`**: Asserts all 3 networks have `internal: true` and match IPAM subnets.
- **`test_all_ground_truth_hosts_in_compose`**: Asserts every single host, network attachment, and IP in `ground_truth.yaml` matches `docker-compose.yml`.
- **`test_scanner_service_configured`**: Validates the non-target auditor scanner container at `172.20.1.250`.

```bash
python -m pytest tests/ -v
# 175 passed in 5.74s
```

---

## 6. Next Steps

**Task 7** — Collection Web UI (`apps/web`):
- Engagement creation screen (define target IP/CIDR and authorizer).
- Scan trigger and live status progress screen ("scanners behind one UI, no command line").
