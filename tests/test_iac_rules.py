"""
Tests for rules/iac.py — Dockerfile and Terraform security rules.
"""

from __future__ import annotations

import pytest

import phoenixsec.rules.iac  # noqa: F401
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.iac import (
    DockerfileUnpinnedTagRule,
    DockerfileUserRootRule,
    DockerfileEnvSecretsRule,
    TerraformOpenIngressRule,
    TerraformPublicS3BucketRule,
)


class TestDockerfileRules:
    def test_unpinned_tag_rule(self) -> None:
        rule = DockerfileUnpinnedTagRule()
        
        # 1. Unpinned or latest tags
        code_unpinned = "FROM node\nRUN npm install\n"
        findings = rule.scan_all(code_unpinned, "Dockerfile")
        assert len(findings) == 1
        assert findings[0].line_number == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].vulnerability_type == VulnerabilityType.MISCONFIGURATION

        code_latest = "FROM ubuntu:latest\nRUN apt-get update\n"
        findings = rule.scan_all(code_latest, "Dockerfile")
        assert len(findings) == 1

        # 2. Pinned tags (should be clean)
        code_pinned = "FROM python:3.12-slim\n"
        assert len(rule.scan_all(code_pinned, "Dockerfile")) == 0

        code_digest = "FROM ubuntu@sha256:451234567890abcdef\n"
        assert len(rule.scan_all(code_digest, "Dockerfile")) == 0

    def test_user_root_rule(self) -> None:
        rule = DockerfileUserRootRule()

        # 1. No user specified (defaults to root)
        code_no_user = "FROM node:20\nCOPY . .\n"
        findings = rule.scan_all(code_no_user, "Dockerfile")
        assert len(findings) == 1
        assert "root" in findings[0].sink

        # 2. Explicitly switched to root
        code_explicit_root = "FROM node:20\nUSER root\n"
        findings = rule.scan_all(code_explicit_root, "Dockerfile")
        assert len(findings) == 1
        assert findings[0].line_number == 2

        # 3. Dedicated non-root user (should be clean)
        code_clean = "FROM node:20\nUSER node\n"
        assert len(rule.scan_all(code_clean, "Dockerfile")) == 0

    def test_env_secrets_rule(self) -> None:
        rule = DockerfileEnvSecretsRule()

        # 1. Secret stored in env variable
        code_secret = "FROM ubuntu\nENV API_KEY=sk-proj-123456\n"
        findings = rule.scan_all(code_secret, "Dockerfile")
        assert len(findings) == 1
        assert findings[0].line_number == 2
        assert findings[0].vulnerability_type == VulnerabilityType.HARDCODED_SECRET

        code_password = "FROM ubuntu\nENV DB_PASSWORD secretpass\n"
        findings = rule.scan_all(code_password, "Dockerfile")
        assert len(findings) == 1

        # 2. Clean env variables
        code_clean = "FROM ubuntu\nENV PORT 8080\nENV NODE_ENV production\n"
        assert len(rule.scan_all(code_clean, "Dockerfile")) == 0


class TestTerraformRules:
    def test_open_ingress_rule(self) -> None:
        rule = TerraformOpenIngressRule()

        # 1. SSH open to anywhere
        code_ssh_open = (
            "resource \"aws_security_group\" \"allow_ssh\" {\n"
            "  ingress {\n"
            "    from_port   = 22\n"
            "    to_port     = 22\n"
            "    protocol    = \"tcp\"\n"
            "    cidr_blocks = [\"0.0.0.0/0\"]\n"
            "  }\n"
            "}\n"
        )
        findings = rule.scan_all(code_ssh_open, "main.tf")
        assert len(findings) == 1
        assert findings[0].line_number == 6
        assert "SSH" in findings[0].sink
        assert findings[0].severity == Severity.HIGH

        # 2. Port 80 open to anywhere (should be clean)
        code_http_open = (
            "resource \"aws_security_group\" \"allow_http\" {\n"
            "  ingress {\n"
            "    from_port   = 80\n"
            "    to_port     = 80\n"
            "    cidr_blocks = [\"0.0.0.0/0\"]\n"
            "  }\n"
            "}\n"
        )
        assert len(rule.scan_all(code_http_open, "main.tf")) == 0

    def test_public_s3_bucket_rule(self) -> None:
        rule = TerraformPublicS3BucketRule()

        # 1. Public ACL
        code_public = (
            "resource \"aws_s3_bucket\" \"b\" {\n"
            "  bucket = \"my-tf-test-bucket\"\n"
            "  acl    = \"public-read\"\n"
            "}\n"
        )
        findings = rule.scan_all(code_public, "main.tf")
        assert len(findings) == 1
        assert findings[0].line_number == 3
        assert findings[0].severity == Severity.HIGH

        # 2. Private ACL (should be clean)
        code_private = (
            "resource \"aws_s3_bucket\" \"b\" {\n"
            "  bucket = \"my-tf-test-bucket\"\n"
            "  acl    = \"private\"\n"
            "}\n"
        )
        assert len(rule.scan_all(code_private, "main.tf")) == 0


class TestRuleRegistryIntegration:
    def test_rules_register_under_correct_languages(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        
        dkr_rules = [r.rule_id for r in reg.get_rules("dockerfile")]
        assert "IAC-DKR-001" in dkr_rules
        assert "IAC-DKR-002" in dkr_rules
        assert "IAC-DKR-003" in dkr_rules

        tf_rules = [r.rule_id for r in reg.get_rules("terraform")]
        assert "IAC-TF-001" in tf_rules
        assert "IAC-TF-002" in tf_rules
