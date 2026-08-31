"""AegisTrap: an LLM-powered adaptive API honeypot.

Emulates a stateful REST/GraphQL business API, profiles attacker skill in
real time, adapts its exposed vulnerability surface to that profile, and
auto-generates MITRE ATT&CK / OWASP-mapped incident reports.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
