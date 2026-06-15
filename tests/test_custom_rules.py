from __future__ import annotations

from pathlib import Path

from phoenixsec.core.custom_rules import load_custom_rules
from phoenixsec.rules.registry import RuleRegistry


def test_load_custom_rules(tmp_path: Path) -> None:
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()

    rule_file = rules_dir / "my_custom_rule.py"
    rule_file.write_text(
        "from phoenixsec.rules.base_rule import BaseRule\n"
        "from phoenixsec.rules.registry import rule\n"
        "from phoenixsec.models.vulnerability import Severity\n"
        "from phoenixsec.models.finding import VulnerabilityType\n"
        "\n"
        "@rule\n"
        "class MyCustomRule(BaseRule):\n"
        "    rule_id = 'CUST-001'\n"
        "    name = 'My Custom Rule'\n"
        "    description = 'Test custom rule'\n"
        "    severity = Severity.HIGH\n"
        "    category = VulnerabilityType.SQL_INJECTION\n"
        "    language = 'python'\n"
        "    def scan(self, code, file_path):\n"
        "        return None\n",
        encoding="utf-8",
    )

    load_custom_rules(rules_dir)

    registry = RuleRegistry.global_instance()
    rule_inst = registry.get_by_id("CUST-001")
    assert rule_inst is not None
    assert rule_inst.name == "My Custom Rule"

    # Clean up the registered rule
    registry.unregister(rule_inst)
