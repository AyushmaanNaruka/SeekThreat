"""Hand-built Finding test fixtures for Track 2 (Enrichment).

These fixtures decouple Track 2 development and testing from Track 1 scanner output.
Each finding satisfies packages.schema.models.finding.Finding invariants:
- Non-empty observation_ids list
- Timezone-aware detected_at datetime
- Proper scanner, asset_id, and engagement_id attributes
"""

from __future__ import annotations

from datetime import UTC, datetime

from packages.schema.models.finding import Finding

# Common engagement and asset IDs for baseline tests
ENGAGEMENT_ID = "eng-lab-baseline-001"
ASSET_DMZ_APACHE = "asset-dmz-dvwa"
ASSET_DMZ_GATEWAY = "asset-dmz-spring-gateway"
ASSET_INTERNAL_JENKINS = "asset-internal-jenkins"
ASSET_DMZ_JUICESHOP = "asset-dmz-juiceshop"
ASSET_DMZ_PROXY = "asset-dmz-proxy"

# Fixed UTC timestamp for deterministic test fixtures
FIXTURE_TIME = datetime(2026, 9, 20, 10, 0, 0, tzinfo=UTC)


FINDING_LOG4SHELL = Finding(
    finding_id="find-log4shell-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_INTERNAL_JENKINS,
    scanner="nuclei",
    cve_ids=["CVE-2021-44228"],
    title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
    description=(
        "Apache Log4j2 versions 2.0-beta9 to 2.14.1 JNDI features do not protect "
        "against attacker controlled LDAP and other JNDI related endpoints."
    ),
    observation_ids=["obs-nuclei-log4j-001", "obs-nmap-port8080-001"],
    detected_at=FIXTURE_TIME,
)

FINDING_APACHE_PATH_TRAVERSAL = Finding(
    finding_id="find-apache-traversal-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_DMZ_APACHE,
    scanner="nuclei",
    cve_ids=["CVE-2021-41773"],
    title="Apache HTTP Server 2.4.49 Path Traversal and RCE",
    description=(
        "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. "
        "An attacker could use a path traversal attack to map URLs to files outside directories."
    ),
    observation_ids=["obs-nuclei-cve2021-41773-001", "obs-nmap-port80-001"],
    detected_at=FIXTURE_TIME,
)

FINDING_SPRING_GATEWAY_RCE = Finding(
    finding_id="find-spring-gateway-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_DMZ_GATEWAY,
    scanner="nuclei",
    cve_ids=["CVE-2022-22947", "CVE-2022-22965"],
    title="Spring Cloud Gateway Code Injection and Spring4Shell",
    description=(
        "Applications using Spring Cloud Gateway are vulnerable to code injection "
        "when the Gateway Actuator endpoint is enabled, exposed and unsecured."
    ),
    observation_ids=["obs-nuclei-spring-001", "obs-nuclei-spring4shell-002"],
    detected_at=FIXTURE_TIME,
)

FINDING_NVD_UNENRICHED_RECENT = Finding(
    finding_id="find-jenkins-cli-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_INTERNAL_JENKINS,
    scanner="nuclei",
    cve_ids=["CVE-2024-23897"],
    title="Jenkins CLI Arbitrary File Read",
    description=(
        "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of "
        "its CLI command parser, allowing unauthenticated attackers to read arbitrary files."
    ),
    observation_ids=["obs-nuclei-jenkins-cli-001"],
    detected_at=FIXTURE_TIME,
)

FINDING_NON_KEV_MODERATE = Finding(
    finding_id="find-express-proto-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_DMZ_JUICESHOP,
    scanner="nuclei",
    cve_ids=["CVE-2020-7699"],
    title="express-fileupload Prototype Pollution",
    description=(
        "express-fileupload before 1.1.8 is vulnerable to Prototype Pollution "
        "via the parseNested parameter."
    ),
    observation_ids=["obs-nuclei-express-001"],
    detected_at=FIXTURE_TIME,
)

FINDING_HEURISTIC_NO_CVE = Finding(
    finding_id="find-weak-cipher-001",
    engagement_id=ENGAGEMENT_ID,
    asset_id=ASSET_DMZ_PROXY,
    scanner="nmap",
    cve_ids=[],
    title="Insecure TLS 1.0 / Weak Ciphers Enabled",
    description="The remote service accepts connections encrypted using obsolete TLS 1.0 protocol.",
    observation_ids=["obs-nmap-ssl-enum-001"],
    detected_at=FIXTURE_TIME,
)


def get_baseline_findings() -> list[Finding]:
    """Return all baseline test findings."""
    return [
        FINDING_LOG4SHELL,
        FINDING_APACHE_PATH_TRAVERSAL,
        FINDING_SPRING_GATEWAY_RCE,
        FINDING_NVD_UNENRICHED_RECENT,
        FINDING_NON_KEV_MODERATE,
        FINDING_HEURISTIC_NO_CVE,
    ]


def get_baseline_findings_by_id() -> dict[str, Finding]:
    """Return baseline test findings mapped by finding_id."""
    return {f.finding_id: f for f in get_baseline_findings()}
