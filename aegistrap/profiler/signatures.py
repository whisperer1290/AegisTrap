"""Signature tables for attacker profiling.

Two kinds of signal live here:

1. **Client identity** — what the caller claims to be, and whether its header
   set is internally consistent with that claim.
2. **Payload tradecraft** — which attack families a payload belongs to, and how
   sophisticated the attempt is. Sophistication is the discriminator that
   separates a copy-pasted ``' OR 1=1--`` from a hand-tuned blind-injection
   probe, which is precisely the script-kiddie / skilled-human boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ClientClass(StrEnum):
    EMPTY = "empty"
    SCANNER = "scanner"
    LIBRARY = "library"
    BROWSER = "browser"
    AI_AGENT = "ai_agent"
    UNKNOWN = "unknown"


#: Well-known offensive tooling. Most of these announce themselves in the
#: User-Agent by default; operators who strip it fall through to the
#: behavioural signals instead.
# fmt: off
SCANNER_TOKENS: tuple[str, ...] = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "ffuf", "gobuster", "dirb",
    "dirbuster", "feroxbuster", "wfuzz", "nuclei", "acunetix", "netsparker",
    "qualys", "burp", "burpsuite", "zap", "zaproxy", "wpscan", "joomscan",
    "hydra", "medusa", "arachni", "whatweb", "sn1per", "dalfox", "commix",
    "xsstrike", "testssl", "nessus", "openvas", "skipfish", "arjun",
    "paramspider", "katana", "httpx-go", "jaeles", "crlfuzz", "sslyze",
)
# fmt: on

#: Generic HTTP clients. Common to hand-written scripts, cron jobs, and
#: low-effort attack scripts alike, so on their own they mean little.
# fmt: off
LIBRARY_TOKENS: tuple[str, ...] = (
    "curl", "wget", "python-requests", "python-httpx", "python-urllib",
    "aiohttp", "go-http-client", "java", "okhttp", "apache-httpclient",
    "libwww-perl", "httpie", "postmanruntime", "insomnia", "axios",
    "node-fetch", "guzzlehttp", "restsharp", "powershell", "winhttp", "ruby",
    "php", "lua-resty-http", "scrapy",
)
# fmt: on

#: Self-identifying LLM agents and agent frameworks.
# fmt: off
AI_AGENT_TOKENS: tuple[str, ...] = (
    "gptbot", "chatgpt", "openai", "anthropic", "claude", "claudebot",
    "langchain", "llamaindex", "autogpt", "agentgpt", "babyagi", "crewai",
    "autogen", "browser-use", "webvoyager", "llm-agent", "ai-agent",
    "perplexitybot", "cohere", "mistral", "deepseek", "gemini", "bard",
    "smolagent", "openhands", "swe-agent",
)

BROWSER_TOKENS: tuple[str, ...] = (
    "mozilla/5.0", "chrome/", "safari/", "firefox/", "edg/", "opr/", "webkit",
)

#: Headers a real browser sends that automated clients usually omit.
BROWSER_HEADERS: tuple[str, ...] = (
    "accept-language", "accept-encoding", "sec-fetch-site", "sec-fetch-mode",
    "sec-fetch-dest", "sec-ch-ua", "upgrade-insecure-requests", "referer",
)
# fmt: on

#: Paths that appear in off-the-shelf content-discovery wordlists. A burst of
#: these is a strong wordlist-scanning indicator (ATT&CK T1595.003).
WORDLIST_PATHS: frozenset[str] = frozenset(
    {
        ".env",
        ".git/config",
        ".git/head",
        ".ds_store",
        "wp-login.php",
        "wp-admin",
        "phpinfo.php",
        "phpmyadmin",
        "admin",
        "administrator",
        "backup.zip",
        "backup.sql",
        "dump.sql",
        "db.sql",
        "config.json",
        "config.yml",
        "credentials",
        "id_rsa",
        "server-status",
        "actuator",
        "actuator/env",
        "actuator/health",
        "swagger",
        "swagger-ui.html",
        "api-docs",
        "openapi.json",
        "graphiql",
        "console",
        "debug",
        "test.php",
        "shell.php",
        "cgi-bin",
        "web.config",
        "composer.json",
        "package.json",
        "robots.txt",
        "sitemap.xml",
        "crossdomain.xml",
        ".well-known/security.txt",
        "solr",
        "jenkins",
        "grafana",
        "kibana",
        "metrics",
        "telescope",
        "_profiler",
        "login",
        "signin",
        "register",
        "v1",
        "v2",
        "internal",
    }
)


@dataclass(frozen=True)
class PayloadSignature:
    """A payload pattern, its attack family, and how skilled it looks.

    ``sophistication`` is a 1-4 ordinal:

    1. copy-paste from a cheat sheet
    2. correct but textbook
    3. adapted to this target, or evasion-aware
    4. blind/inferential, chained, or requiring understanding of internals
    """

    name: str
    family: str
    pattern: re.Pattern[str]
    sophistication: int
    weakness_id: str = ""


def _p(
    name: str, family: str, regex: str, sophistication: int, weakness_id: str = ""
) -> PayloadSignature:
    return PayloadSignature(
        name=name,
        family=family,
        pattern=re.compile(regex, re.IGNORECASE),
        sophistication=sophistication,
        weakness_id=weakness_id,
    )


PAYLOAD_SIGNATURES: tuple[PayloadSignature, ...] = (
    # --- SQL injection ---
    # The closing quote is optional and both sides must be equal: real payloads
    # are usually left unbalanced (``' OR '1'='1``) so the injected quote pairs
    # with the one already in the query, while requiring equality keeps benign
    # text like "3 or 4 = 7" from matching.
    _p(
        "sqli_tautology",
        "sqli",
        r"(?:'|%27|\"|\s)\s*or\s+(?:'?(\d+)'?\s*=\s*'?\1'?|'([^']*)'\s*=\s*'?\2'?|true\b)",
        1,
        "SQL_INJECTION",
    ),
    _p("sqli_comment_terminator", "sqli", r"(?:'|%27)\s*(?:--|#|/\*)", 1, "SQL_INJECTION"),
    _p("sqli_union", "sqli", r"union[\s/*]+(?:all[\s/*]+)?select", 2, "SQL_INJECTION"),
    _p("sqli_order_by_probe", "sqli", r"order\s+by\s+\d{1,3}\s*(?:--|#|$)", 3, "SQL_INJECTION"),
    _p(
        "sqli_information_schema",
        "sqli",
        r"information_schema|pg_catalog|sysobjects|sqlite_master",
        3,
        "SQL_INJECTION",
    ),
    _p(
        "sqli_time_based",
        "sqli",
        r"(?:sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|dbms_pipe\.receive_message)",
        4,
        "SQL_INJECTION",
    ),
    _p(
        "sqli_conditional",
        "sqli",
        r"case\s+when|if\s*\(\s*\d+\s*=\s*\d+|and\s+\d+\s*=\s*\(select",
        4,
        "SQL_INJECTION",
    ),
    _p(
        "sqli_stacked",
        "sqli",
        r";\s*(?:drop|insert|update|delete|create|alter)\s+",
        3,
        "SQL_INJECTION",
    ),
    _p("sqli_comment_evasion", "sqli", r"/\*!?\d*\*/|un/\*\*/ion|se/\*\*/lect", 4, "SQL_INJECTION"),
    _p(
        "sqli_char_encoding",
        "sqli",
        r"char\s*\(\s*\d+\s*(?:,\s*\d+\s*)+\)|0x[0-9a-f]{8,}",
        3,
        "SQL_INJECTION",
    ),
    # --- NoSQL injection ---
    _p(
        "nosqli_operator",
        "nosqli",
        r"\$(?:ne|gt|gte|lt|lte|in|nin|regex|exists|where|expr)\b",
        3,
        "NOSQL_INJECTION",
    ),
    _p(
        "nosqli_js_where",
        "nosqli",
        r"\$where\s*:\s*[\"'].*(?:sleep|while|for)\s*\(",
        4,
        "NOSQL_INJECTION",
    ),
    # --- path traversal ---
    _p("traversal_plain", "traversal", r"(?:\.\./){2,}|(?:\.\.\\){2,}", 1, "PATH_TRAVERSAL"),
    _p(
        "traversal_encoded",
        "traversal",
        r"%2e%2e(?:%2f|%5c)|\.\.%2f|%252e%252e",
        3,
        "PATH_TRAVERSAL",
    ),
    _p(
        "traversal_filter_bypass",
        "traversal",
        r"\.\.\.\./|\.\.;/|\.\.%00/|%c0%ae%c0%ae",
        4,
        "PATH_TRAVERSAL",
    ),
    _p(
        "traversal_sensitive_target",
        "traversal",
        r"(?:etc/(?:passwd|shadow)|proc/self/environ|win\.ini|boot\.ini)",
        2,
        "PATH_TRAVERSAL",
    ),
    # --- command injection ---
    _p(
        "cmdi_separator",
        "cmdi",
        r"(?:;|\|\||&&|\|)\s*(?:id|whoami|uname|cat|ls|dir|curl|wget|nc)\b",
        2,
        "COMMAND_INJECTION",
    ),
    _p("cmdi_substitution", "cmdi", r"\$\([^)]{1,60}\)|`[^`]{1,60}`", 3, "COMMAND_INJECTION"),
    _p(
        "cmdi_newline",
        "cmdi",
        r"%0a\s*(?:id|whoami|cat|curl)|\\n\s*(?:id|whoami)",
        4,
        "COMMAND_INJECTION",
    ),
    # --- XSS ---
    _p("xss_script_tag", "xss", r"<\s*script|%3cscript", 1, "REFLECTED_XSS"),
    _p("xss_event_handler", "xss", r"on(?:error|load|click|mouseover)\s*=", 2, "REFLECTED_XSS"),
    _p("xss_svg_vector", "xss", r"<\s*svg|<\s*img[^>]+onerror|javascript:", 2, "REFLECTED_XSS"),
    _p(
        "xss_filter_bypass",
        "xss",
        r"<\s*/?\s*[a-z]+\s*/\s*on\w+|&#x?\d+;.*<|String\.fromCharCode",
        4,
        "REFLECTED_XSS",
    ),
    # --- template / expression injection ---
    _p(
        "ssti_expression", "ssti", r"\{\{\s*\d+\s*[*+]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}", 3
    ),
    _p("ssti_object_walk", "ssti", r"__class__|__globals__|__subclasses__|T\(java\.lang", 4),
    _p("log4shell", "ssti", r"\$\{jndi:(?:ldap|rmi|dns)", 3),
    # --- SSRF ---
    _p(
        "ssrf_metadata",
        "ssrf",
        r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
        4,
        "SSRF_WEBHOOK",
    ),
    _p(
        "ssrf_loopback",
        "ssrf",
        r"(?:https?|gopher|file|dict)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])",
        3,
        "SSRF_WEBHOOK",
    ),
    _p(
        "ssrf_internal_host",
        "ssrf",
        r"://(?:[\w.-]+\.)?(?:internal|local|intranet|consul|kubernetes)\b",
        4,
        "SSRF_WEBHOOK",
    ),
    _p("ssrf_scheme_abuse", "ssrf", r"(?:file|gopher|dict|ftp|ldap)://", 3, "SSRF_WEBHOOK"),
    # --- authentication / token abuse ---
    _p("jwt_alg_none", "auth", r"\"alg\"\s*:\s*\"none\"|eyJhbGciOiJub25lIg", 4, "JWT_ALG_NONE"),
    _p("jwt_present", "auth", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}", 2),
    _p(
        "default_credentials",
        "auth",
        r"(?:admin|root|test)['\"]?\s*[:=]\s*['\"]?(?:admin|root|password|123456|test)\b",
        1,
        "NO_AUTH_LOCKOUT",
    ),
    # --- authorization abuse ---
    _p(
        "mass_assignment_role",
        "authz",
        r"\"(?:role|is_admin|isAdmin|admin|scopes?|permissions?|kyc_status)\"\s*:",
        3,
        "MASS_ASSIGNMENT",
    ),
    _p(
        "privilege_value",
        "authz",
        r"\"(?:role|group)\"\s*:\s*\"(?:admin|superuser|root|owner)\"",
        3,
        "MASS_ASSIGNMENT",
    ),
    # --- GraphQL abuse ---
    _p(
        "graphql_introspection",
        "graphql",
        r"__schema|__type\s*\(|IntrospectionQuery",
        2,
        "GRAPHQL_INTROSPECTION",
    ),
    _p(
        "graphql_alias_amplification",
        "graphql",
        r"(?:\b\w+\s*:\s*\w+\s*\{[^}]*\}\s*){6,}",
        4,
        "GRAPHQL_DEPTH_ABUSE",
    ),
    _p("graphql_batching", "graphql", r"^\s*\[\s*\{\s*\"query\"", 3, "GRAPHQL_DEPTH_ABUSE"),
    # --- deserialisation / misc ---
    _p("deserialisation", "deser", r"rO0AB|aced0005|O:\d+:\"|__reduce__|pickle\.loads", 4),
    _p("xxe", "xxe", r"<!ENTITY|<!DOCTYPE[^>]+SYSTEM", 4),
    _p("crlf_injection", "crlf", r"%0d%0a|\\r\\n(?:Set-Cookie|Location)", 3),
    _p("open_redirect", "redirect", r"(?:redirect|next|return_?url|callback)=(?:https?%3a|//)", 2),
    _p(
        "prompt_injection",
        "prompt",
        r"ignore (?:all )?(?:previous|prior) instructions|system prompt|you are now|disregard (?:the )?above",
        3,
    ),
)

#: Encoding wrappers, counted to gauge evasion effort.
ENCODING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url_encoding", re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)),
    ("double_url_encoding", re.compile(r"%25[0-9a-f]{2}", re.IGNORECASE)),
    ("unicode_escape", re.compile(r"\\u00[0-9a-f]{2}", re.IGNORECASE)),
    ("html_entity", re.compile(r"&#x?[0-9a-f]{2,6};", re.IGNORECASE)),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")),
    ("hex_literal", re.compile(r"0x[0-9a-f]{6,}", re.IGNORECASE)),
    ("case_mixing", re.compile(r"\b(?:[a-z][A-Z]){3,}")),
)


def classify_client(user_agent: str, header_names: set[str]) -> ClientClass:
    """Bucket a client from its User-Agent, sanity-checked against headers."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return ClientClass.EMPTY
    if any(token in ua for token in AI_AGENT_TOKENS):
        return ClientClass.AI_AGENT
    if any(token in ua for token in SCANNER_TOKENS):
        return ClientClass.SCANNER
    if any(token in ua for token in BROWSER_TOKENS):
        # A browser UA with none of the headers a browser always sends is a
        # spoof, which is itself a deliberate-evasion signal.
        lowered = {h.lower() for h in header_names}
        if len(lowered & set(BROWSER_HEADERS)) >= 2:
            return ClientClass.BROWSER
        return ClientClass.LIBRARY
    if any(token in ua for token in LIBRARY_TOKENS):
        return ClientClass.LIBRARY
    return ClientClass.UNKNOWN


@dataclass
class PayloadMatch:
    name: str
    family: str
    sophistication: int
    weakness_id: str
    excerpt: str


def scan_payload(text: str, *, max_matches: int = 12) -> list[PayloadMatch]:
    """Match a request blob against the payload catalogue."""
    if not text:
        return []
    matches: list[PayloadMatch] = []
    seen: set[str] = set()
    for sig in PAYLOAD_SIGNATURES:
        found = sig.pattern.search(text)
        if not found or sig.name in seen:
            continue
        seen.add(sig.name)
        matches.append(
            PayloadMatch(
                name=sig.name,
                family=sig.family,
                sophistication=sig.sophistication,
                weakness_id=sig.weakness_id,
                excerpt=found.group(0)[:120],
            )
        )
        if len(matches) >= max_matches:
            break
    return matches


def count_encoding_layers(text: str) -> int:
    if not text:
        return 0
    return sum(1 for _, pattern in ENCODING_PATTERNS if pattern.search(text))


def looks_like_wordlist_path(path: str) -> bool:
    normalised = path.strip("/").lower()
    if normalised in WORDLIST_PATHS:
        return True
    tail = normalised.rsplit("/", 1)[-1] if "/" in normalised else normalised
    return tail in WORDLIST_PATHS
