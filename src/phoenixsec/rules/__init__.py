"""Rules package — public API."""

from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.engine import EngineResult, RuleEngine
from phoenixsec.rules.registry import RuleRegistry, rule

# Import all built-in rules to ensure they register automatically via @rule
from phoenixsec.rules import (
    ast_rules,
    broken_auth,
    command_injection,
    csrf,
    iac,
    insecure_deserialization,
    ldap_injection,
    misconfiguration,
    nosql_injection,
    open_redirect,
    path_traversal,
    secrets,
    sqli,
    ssrf,
    weak_crypto,
    xpath_injection,
    xss,
    xxe,
)

__all__ = [
    "BaseRule",
    "RuleContext",
    "RuleRegistry",
    "rule",
    "RuleEngine",
    "EngineResult",
]
