"""Attack taxonomy: MITRE ATT&CK techniques, OWASP categories, CWEs, and the
seeded-weakness catalogue that ties them together.

This is the single source of truth shared by two subsystems:

* the **decoy layer**, which decides which fake weaknesses to expose, and
* the **auto-reporter**, which maps observed attacker behaviour to framework IDs.

Keeping one table means a report can never claim a technique the honeypot has
no corresponding weakness for, and the ground-truth labels used in evaluation
come from the same definitions the deception layer works from.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# MITRE ATT&CK (Enterprise) techniques relevant to web/API attack surfaces
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        base, _, sub = self.id.partition(".")
        path = f"{base}/{sub}" if sub else base
        return f"https://attack.mitre.org/techniques/{path}/"


def _t(*rows: tuple[str, str, str]) -> dict[str, Technique]:
    return {r[0]: Technique(id=r[0], name=r[1], tactic=r[2]) for r in rows}


TECHNIQUES: dict[str, Technique] = _t(
    # Reconnaissance
    ("T1595", "Active Scanning", "reconnaissance"),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance"),
    ("T1595.003", "Active Scanning: Wordlist Scanning", "reconnaissance"),
    ("T1592", "Gather Victim Host Information", "reconnaissance"),
    ("T1589", "Gather Victim Identity Information", "reconnaissance"),
    ("T1589.001", "Gather Victim Identity Information: Credentials", "reconnaissance"),
    ("T1589.002", "Gather Victim Identity Information: Email Addresses", "reconnaissance"),
    ("T1590", "Gather Victim Network Information", "reconnaissance"),
    # Initial access
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1078", "Valid Accounts", "initial-access"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "initial-access"),
    # Execution
    ("T1059", "Command and Scripting Interpreter", "execution"),
    # Credential access
    ("T1110", "Brute Force", "credential-access"),
    ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    ("T1110.003", "Brute Force: Password Spraying", "credential-access"),
    ("T1110.004", "Brute Force: Credential Stuffing", "credential-access"),
    ("T1212", "Exploitation for Credential Access", "credential-access"),
    ("T1552", "Unsecured Credentials", "credential-access"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access"),
    ("T1528", "Steal Application Access Token", "credential-access"),
    # Privilege escalation / defense evasion
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation"),
    ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    ("T1134", "Access Token Manipulation", "privilege-escalation"),
    ("T1211", "Exploitation for Defense Evasion", "defense-evasion"),
    ("T1027", "Obfuscated Files or Information", "defense-evasion"),
    ("T1090", "Proxy", "command-and-control"),
    # Discovery
    ("T1046", "Network Service Discovery", "discovery"),
    ("T1087", "Account Discovery", "discovery"),
    ("T1087.004", "Account Discovery: Cloud Account", "discovery"),
    ("T1069", "Permission Groups Discovery", "discovery"),
    ("T1518", "Software Discovery", "discovery"),
    ("T1083", "File and Directory Discovery", "discovery"),
    # Collection
    ("T1213", "Data from Information Repositories", "collection"),
    ("T1119", "Automated Collection", "collection"),
    ("T1530", "Data from Cloud Storage", "collection"),
    ("T1005", "Data from Local System", "collection"),
    # C2 / exfiltration / impact
    ("T1071", "Application Layer Protocol", "command-and-control"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    ("T1567", "Exfiltration Over Web Service", "exfiltration"),
    ("T1499", "Endpoint Denial of Service", "impact"),
    ("T1499.004", "Endpoint Denial of Service: Application or System Exploitation", "impact"),
    ("T1657", "Financial Theft", "impact"),
    ("T1565", "Data Manipulation", "impact"),
)

#: Ordering used when rendering an attack timeline in a report.
TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


# ---------------------------------------------------------------------------
# OWASP categories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OwaspCategory:
    id: str
    name: str
    family: str


def _o(family: str, *rows: tuple[str, str]) -> dict[str, OwaspCategory]:
    return {r[0]: OwaspCategory(id=r[0], name=r[1], family=family) for r in rows}


#: OWASP API Security Top 10 (2023) — the primary taxonomy for this project.
OWASP_API: dict[str, OwaspCategory] = _o(
    "api-2023",
    ("API1:2023", "Broken Object Level Authorization"),
    ("API2:2023", "Broken Authentication"),
    ("API3:2023", "Broken Object Property Level Authorization"),
    ("API4:2023", "Unrestricted Resource Consumption"),
    ("API5:2023", "Broken Function Level Authorization"),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "Server Side Request Forgery"),
    ("API8:2023", "Security Misconfiguration"),
    ("API9:2023", "Improper Inventory Management"),
    ("API10:2023", "Unsafe Consumption of APIs"),
)

#: OWASP Top 10 for web applications, carried over from the project's earlier
#: WAF work so report output stays comparable across both engines.
OWASP_WEB: dict[str, OwaspCategory] = _o(
    "web",
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
)

#: OWASP Top 10:2025 — the taxonomy named in the synopsis. Seeded weaknesses
#: still cite the stable 2021 letter-IDs internally; reports project those
#: onto 2025 IDs so an analyst can act against the current list.
OWASP_WEB_2025: dict[str, OwaspCategory] = _o(
    "web-2025",
    ("A01:2025", "Broken Access Control"),
    ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"),
    ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"),
    ("A06:2025", "Insecure Design"),
    ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"),
    ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
)

#: Projection from the 2021 letter-IDs onto the 2025 list. SSRF (A10:2021) is
#: not a 2025 Top 10 entry of its own; it is an access-control failure against
#: internal resources, so it maps to A01:2025.
WEB_TO_2025: dict[str, str] = {
    "A01": "A01:2025",
    "A02": "A04:2025",
    "A03": "A05:2025",
    "A04": "A06:2025",
    "A05": "A02:2025",
    "A06": "A03:2025",
    "A07": "A07:2025",
    "A08": "A08:2025",
    "A09": "A09:2025",
    "A10": "A01:2025",
}

CWES: dict[str, str] = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-204": "Observable Response Discrepancy",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-213": "Exposure of Sensitive Information Due to Incompatible Policies",
    "CWE-285": "Improper Authorization",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-489": "Active Debug Code",
    "CWE-566": "Authorization Bypass Through User-Controlled SQL Primary Key",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
}

SEVERITY_ORDER: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return 0


def max_severity(severities: Iterable[str]) -> str:
    best = "informational"
    for s in severities:
        if severity_rank(s) > severity_rank(best):
            best = s
    return best


# ---------------------------------------------------------------------------
# Seeded weaknesses: the fake vulnerability surface AegisTrap can expose
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Weakness:
    """One intentionally-interesting fake flaw in the decoy API.

    ``min_persona_rank`` implements the adaptive vulnerability surface: a
    weakness is only reachable once the profiler thinks the session is at least
    this capable. Rank 0 is ``BENIGN`` (nothing unlocked). Rank 1 is
    ``UNKNOWN`` (cheap reconnaissance bait). Rank 2 is ``ATTACKER`` (full
    seeded surface).
    """

    id: str
    title: str
    description: str
    owasp_api: str
    owasp_web: str
    cwe: str
    techniques: tuple[str, ...]
    severity: str
    min_persona_rank: int = 1
    #: Human-facing note for the defender-side report.
    defender_note: str = ""

    @property
    def owasp_api_name(self) -> str:
        cat = OWASP_API.get(self.owasp_api)
        return cat.name if cat else self.owasp_api

    @property
    def owasp_web_name(self) -> str:
        cat = OWASP_WEB.get(self.owasp_web)
        return cat.name if cat else self.owasp_web

    @property
    def cwe_name(self) -> str:
        return CWES.get(self.cwe, self.cwe)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "owasp_api": {"id": self.owasp_api, "name": self.owasp_api_name},
            "owasp_web": {"id": self.owasp_web, "name": self.owasp_web_name},
            "cwe": {"id": self.cwe, "name": self.cwe_name},
            "attack_techniques": [
                {
                    "id": tid,
                    "name": TECHNIQUES[tid].name,
                    "tactic": TECHNIQUES[tid].tactic,
                    "url": TECHNIQUES[tid].url,
                }
                for tid in self.techniques
                if tid in TECHNIQUES
            ],
        }


def _w(**kwargs: object) -> Weakness:
    weakness = Weakness(**kwargs)  # type: ignore[arg-type]
    if weakness.min_persona_rank < 1:
        raise ValueError(
            f"{weakness.id}: min_persona_rank must be >= 1 so that benign "
            "sessions are never served a reachable weakness"
        )
    return weakness


WEAKNESSES: dict[str, Weakness] = {
    w.id: w
    for w in [
        _w(
            id="IDOR_ACCOUNT",
            title="Broken object level authorization on account objects",
            description=(
                "GET /api/v1/accounts/{id} does not verify that the authenticated "
                "principal owns the requested account, so sequential IDs expose "
                "other customers' balances."
            ),
            owasp_api="API1:2023",
            owasp_web="A01",
            cwe="CWE-639",
            techniques=("T1190", "T1087", "T1213"),
            severity="high",
            min_persona_rank=2,
            defender_note="Enforce ownership checks in the account resolver, not the route.",
        ),
        _w(
            id="IDOR_TRANSACTION",
            title="Broken object level authorization on transaction history",
            description=(
                "Transaction listings are filtered by the account_id query "
                "parameter alone, allowing cross-tenant history disclosure."
            ),
            owasp_api="API1:2023",
            owasp_web="A01",
            cwe="CWE-639",
            techniques=("T1190", "T1213", "T1119"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="USER_ENUMERATION",
            title="Account enumeration via distinguishable auth errors",
            description=(
                "The login endpoint returns different error codes for unknown "
                "users and wrong passwords, confirming which emails exist."
            ),
            owasp_api="API2:2023",
            owasp_web="A07",
            cwe="CWE-204",
            techniques=("T1589.002", "T1087"),
            severity="medium",
            min_persona_rank=1,
        ),
        _w(
            id="NO_AUTH_LOCKOUT",
            title="No throttling or lockout on authentication",
            description=(
                "Credential attempts are unlimited and unthrottled, enabling "
                "password spraying and credential stuffing."
            ),
            owasp_api="API2:2023",
            owasp_web="A07",
            cwe="CWE-307",
            techniques=("T1110", "T1110.001", "T1110.003", "T1110.004"),
            severity="high",
            min_persona_rank=1,
        ),
        _w(
            id="JWT_ALG_NONE",
            title="Access token signature not verified",
            description=(
                "The token verifier accepts alg=none and unsigned tokens, so any "
                "principal can be impersonated by editing the payload."
            ),
            owasp_api="API2:2023",
            owasp_web="A02",
            cwe="CWE-347",
            techniques=("T1134", "T1528", "T1078"),
            severity="critical",
            min_persona_rank=2,
            defender_note="Pin the accepted algorithm list server-side.",
        ),
        _w(
            id="MASS_ASSIGNMENT",
            title="Mass assignment of privileged object properties",
            description=(
                "User-controlled JSON is merged into the persisted object, so "
                "fields like role or kyc_status can be set by the client."
            ),
            owasp_api="API3:2023",
            owasp_web="A04",
            cwe="CWE-915",
            techniques=("T1548", "T1068"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="EXCESSIVE_DATA_EXPOSURE",
            title="Excessive data exposure in object serialisation",
            description=(
                "Objects are serialised whole, leaking internal fields such as "
                "password hashes, risk scores, and internal notes."
            ),
            owasp_api="API3:2023",
            owasp_web="A01",
            cwe="CWE-213",
            techniques=("T1213", "T1552"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="NO_RATE_LIMIT",
            title="Unrestricted resource consumption",
            description=(
                "No per-client rate limiting or pagination ceiling, so listings "
                "can be harvested wholesale."
            ),
            owasp_api="API4:2023",
            owasp_web="A04",
            cwe="CWE-770",
            techniques=("T1119", "T1499"),
            severity="medium",
            # Uncapped pagination is a deep-surface reward, not ambient: every
            # other tier keeps its page ceiling so bulk enumeration stays cheap.
            min_persona_rank=2,
        ),
        _w(
            id="GRAPHQL_DEPTH_ABUSE",
            title="Unbounded GraphQL query depth and aliasing",
            description=(
                "The GraphQL endpoint enforces no depth, complexity, or alias "
                "limits, permitting amplification and resource exhaustion."
            ),
            owasp_api="API4:2023",
            owasp_web="A04",
            cwe="CWE-770",
            techniques=("T1499", "T1499.004"),
            severity="medium",
            min_persona_rank=2,
        ),
        _w(
            id="BFLA_ADMIN_ROUTE",
            title="Administrative functions reachable by non-admin principals",
            description=(
                "Routes under /api/v1/admin check only that a token is present, "
                "not that it carries an administrative role."
            ),
            owasp_api="API5:2023",
            owasp_web="A01",
            cwe="CWE-285",
            techniques=("T1190", "T1068", "T1069"),
            severity="critical",
            min_persona_rank=2,
            defender_note="Move the role check into shared middleware for the admin router.",
        ),
        _w(
            id="SENSITIVE_BUSINESS_FLOW",
            title="Unlimited access to a sensitive money-movement flow",
            description=(
                "Transfers can be initiated repeatedly with no velocity limits, "
                "step-up authentication, or business-rule ceiling."
            ),
            owasp_api="API6:2023",
            owasp_web="A04",
            cwe="CWE-770",
            techniques=("T1657", "T1565"),
            severity="critical",
            min_persona_rank=2,
        ),
        _w(
            id="SSRF_WEBHOOK",
            title="Server-side request forgery via webhook registration",
            description=(
                "Webhook callback URLs are fetched server-side without host "
                "allow-listing, reaching internal addresses and metadata services."
            ),
            owasp_api="API7:2023",
            owasp_web="A10",
            cwe="CWE-918",
            techniques=("T1190", "T1090", "T1552"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="VERBOSE_ERROR",
            title="Verbose error messages leaking internal detail",
            description=(
                "Unhandled conditions return driver-level messages, SQL "
                "fragments, and internal identifiers."
            ),
            owasp_api="API8:2023",
            owasp_web="A05",
            cwe="CWE-209",
            techniques=("T1592", "T1595.002"),
            severity="medium",
            min_persona_rank=1,
        ),
        _w(
            id="DEBUG_ENDPOINT",
            title="Debug endpoint left enabled in production",
            description=(
                "A diagnostics route echoes environment configuration and build "
                "metadata to unauthenticated callers."
            ),
            owasp_api="API8:2023",
            owasp_web="A05",
            cwe="CWE-489",
            techniques=("T1592", "T1518", "T1552"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="CORS_MISCONFIG",
            title="Permissive CORS policy with credentials",
            description=(
                "The service reflects arbitrary Origin values while allowing credentialed requests."
            ),
            owasp_api="API8:2023",
            owasp_web="A05",
            cwe="CWE-942",
            techniques=("T1190",),
            severity="medium",
            min_persona_rank=2,
        ),
        _w(
            id="GRAPHQL_INTROSPECTION",
            title="GraphQL introspection enabled publicly",
            description=(
                "The full schema, including internal-only types, is retrievable "
                "by any unauthenticated client."
            ),
            owasp_api="API9:2023",
            owasp_web="A05",
            cwe="CWE-200",
            techniques=("T1595.002", "T1592", "T1518"),
            severity="medium",
            min_persona_rank=1,
        ),
        _w(
            id="SHADOW_API_VERSION",
            title="Deprecated API version still routable",
            description=(
                "An older, unpatched /api/v0 surface remains live and lacks the "
                "authorization fixes applied to v1."
            ),
            owasp_api="API9:2023",
            owasp_web="A05",
            cwe="CWE-200",
            techniques=("T1595", "T1190"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="OPENAPI_EXPOSED",
            title="Machine-readable API inventory publicly exposed",
            description=(
                "The OpenAPI document is unauthenticated, handing attackers a "
                "complete route and parameter inventory."
            ),
            owasp_api="API9:2023",
            owasp_web="A05",
            cwe="CWE-200",
            techniques=("T1595", "T1592", "T1518"),
            severity="low",
            min_persona_rank=1,
        ),
        _w(
            id="HONEY_CREDENTIALS",
            title="Hard-coded credentials and live API keys in responses",
            description=(
                "Service responses embed static API keys and integration "
                "secrets usable against downstream systems."
            ),
            owasp_api="API8:2023",
            owasp_web="A02",
            cwe="CWE-798",
            techniques=("T1552", "T1552.001", "T1528"),
            severity="critical",
            min_persona_rank=2,
        ),
        _w(
            id="SQL_INJECTION",
            title="SQL injection in a filter parameter",
            description=(
                "Query parameters are concatenated into SQL, so boolean and "
                "error-based injection both succeed."
            ),
            owasp_api="API8:2023",
            owasp_web="A03",
            cwe="CWE-89",
            techniques=("T1190", "T1213", "T1212"),
            severity="critical",
            min_persona_rank=2,
        ),
        _w(
            id="NOSQL_INJECTION",
            title="NoSQL operator injection in a JSON body",
            description=(
                "JSON values reach the document store unsanitised, so operator "
                "objects such as $ne and $gt alter query semantics."
            ),
            owasp_api="API8:2023",
            owasp_web="A03",
            cwe="CWE-943",
            techniques=("T1190", "T1212"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="PATH_TRAVERSAL",
            title="Path traversal in a file-export parameter",
            description=(
                "A report-download parameter is joined onto a base path without "
                "normalisation, exposing arbitrary readable files."
            ),
            owasp_api="API8:2023",
            owasp_web="A01",
            cwe="CWE-22",
            techniques=("T1083", "T1005", "T1552.001"),
            severity="high",
            min_persona_rank=2,
        ),
        _w(
            id="COMMAND_INJECTION",
            title="OS command injection in an export helper",
            description=(
                "A statement-export routine interpolates user input into a shell command."
            ),
            owasp_api="API8:2023",
            owasp_web="A03",
            cwe="CWE-78",
            techniques=("T1059", "T1190"),
            severity="critical",
            min_persona_rank=2,
        ),
        _w(
            id="REFLECTED_XSS",
            title="Reflected cross-site scripting in an error echo",
            description=("User input is echoed into an HTML error page without encoding."),
            owasp_api="API8:2023",
            owasp_web="A03",
            cwe="CWE-79",
            techniques=("T1190",),
            severity="medium",
            min_persona_rank=2,
        ),
    ]
}


@dataclass
class WeaknessHit:
    """A weakness the honeypot actually exercised during a session."""

    weakness_id: str
    seq: int
    detail: str = ""
    evidence: dict[str, object] = field(default_factory=dict)

    @property
    def weakness(self) -> Weakness | None:
        return WEAKNESSES.get(self.weakness_id)


def techniques_for_weaknesses(weakness_ids: Iterable[str]) -> list[str]:
    """Flatten weakness IDs into a de-duplicated, tactic-ordered technique list."""
    collected: list[str] = []
    for wid in weakness_ids:
        weakness = WEAKNESSES.get(wid)
        if not weakness:
            continue
        for tid in weakness.techniques:
            if tid not in collected:
                collected.append(tid)
    return sort_techniques(collected)


def sort_techniques(technique_ids: Iterable[str]) -> list[str]:
    def key(tid: str) -> tuple[int, str]:
        tech = TECHNIQUES.get(tid)
        tactic_idx = TACTIC_ORDER.index(tech.tactic) if tech and tech.tactic in TACTIC_ORDER else 99
        return (tactic_idx, tid)

    return sorted({t for t in technique_ids if t in TECHNIQUES}, key=key)


def map_web_to_2025(web_ids: Iterable[str]) -> list[str]:
    """Project 2021 Top 10 letter-IDs onto the 2025 list, de-duplicated."""
    mapped: list[str] = []
    for web_id in web_ids:
        target = WEB_TO_2025.get(web_id, web_id if web_id in OWASP_WEB_2025 else "")
        if target and target not in mapped:
            mapped.append(target)
    return mapped


def owasp_for_weaknesses(weakness_ids: Iterable[str]) -> dict[str, list[str]]:
    api_ids: list[str] = []
    web_ids: list[str] = []
    cwe_ids: list[str] = []
    for wid in weakness_ids:
        weakness = WEAKNESSES.get(wid)
        if not weakness:
            continue
        for bucket, value in (
            (api_ids, weakness.owasp_api),
            (web_ids, weakness.owasp_web),
            (cwe_ids, weakness.cwe),
        ):
            if value not in bucket:
                bucket.append(value)
    return {
        "owasp_api": sorted(api_ids, key=_owasp_api_sort_key),
        "owasp_web": sorted(web_ids),
        "cwe": sorted(cwe_ids, key=lambda c: int(c.split("-")[1]) if "-" in c else 0),
    }


def _owasp_api_sort_key(cat_id: str) -> int:
    digits = "".join(ch for ch in cat_id.split(":")[0] if ch.isdigit())
    return int(digits) if digits else 99


def valid_technique_ids() -> frozenset[str]:
    return frozenset(TECHNIQUES)


def valid_owasp_api_ids() -> frozenset[str]:
    return frozenset(OWASP_API)


def describe_technique(technique_id: str) -> dict[str, str]:
    tech = TECHNIQUES.get(technique_id)
    if not tech:
        return {"id": technique_id, "name": "unknown technique", "tactic": "unknown", "url": ""}
    return {"id": tech.id, "name": tech.name, "tactic": tech.tactic, "url": tech.url}
