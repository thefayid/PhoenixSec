from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.rules.engine import RuleEngine

log = get_logger(__name__)


class AgenticRedTeamer:
    """Agentic Proof-of-Exploit (Red Teamer) for verifying vulnerabilities."""

    def __init__(self, rule_engine: RuleEngine | None = None, config=None) -> None:
        self._rule_engine = rule_engine or RuleEngine()
        from phoenixsec.core.config import load_config

        self._config = config or load_config()

    def _query_gemini(self, prompt: str) -> str:
        """Query the Google Gemini API to generate an exploit."""
        api_key = os.environ.get("PHOENIXSEC_AI_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise PhoenixSecError(
                "Missing PHOENIXSEC_AI_KEY or GEMINI_API_KEY environment variable."
            )

        base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        model_name = (
            self._config.red_teamer.model
            if "gemini" in self._config.red_teamer.model
            else "gemini-1.5-flash"
        )
        url = f"{base_url}/{model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "text/plain"},
        }

        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                candidates = res_data.get("candidates", [])
                if not candidates:
                    raise PhoenixSecError("Gemini API returned no candidates.")

                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if not text:
                    raise PhoenixSecError("Gemini API returned empty text response.")

                # Extract code if wrapped in markdown fences
                match = re.search(r"```(?:[a-zA-Z]+)?\n(.*?)```", text, re.DOTALL)
                if match:
                    return match.group(1).strip()

                return text.strip()
        except Exception as exc:
            raise PhoenixSecError(f"Agentic Red Teamer API Call failed: {exc}") from exc

    def attempt_exploit(self, finding: Finding, code: str, file_path: Path) -> tuple[bool, str]:
        """Attempt to prove a vulnerability by generating and running an exploit test.

        Returns
        -------
        tuple[bool, str]
            (True if proven, proof details/output string)
        """
        if file_path.suffix.lower() != ".py":
            # Currently only supporting Python for dynamic testing
            return False, "Unsupported language for dynamic proof-of-exploit."

        prompt = (
            "You are an automated Red Teamer and Security Engineer. "
            "Your task is to write a self-contained `pytest` script that PROVES a vulnerability exists "
            "in the provided source code. If the test passes (or fails in a specific way that demonstrates the exploit), "
            "the vulnerability is proven.\n\n"
            f"Vulnerability Details:\n"
            f"- Type: {finding.vulnerability_type.value}\n"
            f"- Line Number: {finding.line_number}\n"
            f"- Sink: {finding.sink or 'N/A'}\n"
            f"- Source: {finding.source or 'N/A'}\n\n"
            "Source Code (`target_module.py`):\n"
            "```python\n"
            f"{code}\n"
            "```\n\n"
            "Instructions:\n"
            "1. Write a `pytest` test file.\n"
            "2. Import the vulnerable function or class from the source code. The source file will be "
            "saved as `target_module.py` in the same directory as the test.\n"
            "3. Construct a malicious payload (e.g., SQL injection string, XSS payload, path traversal string) "
            "that exploits the described vulnerability.\n"
            "4. Call the vulnerable function with the payload.\n"
            "5. Add assertions to prove the exploit worked. For example, if it's SQL injection, assert "
            "that the query returned unauthorized data or raised a syntax error indicative of injection. "
            "If it's command injection, assert that a mocked `os.system` was called with the payload.\n"
            "6. Provide ONLY the Python test code. No explanations. Ensure it is robust and catches exceptions if necessary."
        )

        try:
            test_code = self._query_gemini(prompt)
        except PhoenixSecError as exc:
            return False, f"Failed to generate exploit: {exc}"

        # AST Safety Check to prevent executing malicious code
        import ast

        try:
            tree = ast.parse(test_code)
            allowed_imports = {
                "pytest",
                "target_module",
                "typing",
                "json",
                "unittest",
                "math",
                "re",
                "os",
                "sys",
                "subprocess",
                "requests",
                "urllib",
                "socket",
            }
            for node in ast.walk(tree):
                # Restrict imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] not in allowed_imports:
                            return False, f"Unsafe exploit code: disallowed import '{alias.name}'"
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.split(".")[0] not in allowed_imports:
                        return False, f"Unsafe exploit code: disallowed import from '{node.module}'"

                # Check for direct calls or reference to dangerous API operations
                elif isinstance(node, ast.Call):
                    # Prohibit dangerous builtins
                    if isinstance(node.func, ast.Name):
                        if node.func.id in {"eval", "exec", "compile", "__import__", "open"}:
                            return (
                                False,
                                f"Unsafe exploit code: dangerous builtin call '{node.func.id}'",
                            )
                    # Check calls on attributes (e.g. os.system, subprocess.run)
                    elif isinstance(node.func, ast.Attribute):
                        # Find object being called
                        obj_name = ""
                        if isinstance(node.func.value, ast.Name):
                            obj_name = node.func.value.id

                        attr_name = node.func.attr

                        # Disallow process execution APIs completely
                        if obj_name == "os" and attr_name in {
                            "system",
                            "popen",
                            "spawnl",
                            "spawnle",
                            "spawnlp",
                            "spawnlpe",
                            "spawnv",
                            "spawnve",
                            "spawnvp",
                            "spawnvpe",
                            "execl",
                            "execle",
                            "execlp",
                            "execlpe",
                            "execv",
                            "execve",
                            "execvp",
                            "execvpe",
                            "remove",
                            "unlink",
                            "rmdir",
                            "removedirs",
                            "chmod",
                            "chown",
                        }:
                            return (
                                False,
                                f"Unsafe exploit code: disallowed execution call 'os.{attr_name}'",
                            )

                        if obj_name == "subprocess" and attr_name in {
                            "run",
                            "Popen",
                            "call",
                            "check_call",
                            "check_output",
                            "getstatusoutput",
                            "getoutput",
                        }:
                            return (
                                False,
                                f"Unsafe exploit code: disallowed execution call 'subprocess.{attr_name}'",
                            )

                        # Restrict requests or urllib calls to only safe hosts (e.g., local hostnames)
                        if obj_name == "requests" or (
                            obj_name == "urllib" and attr_name == "request"
                        ):
                            # Simple validation of first string arg (the URL)
                            if node.args and isinstance(node.args[0], ast.Constant):
                                url_val = str(node.args[0].value)
                                # Only allow local endpoints/hosts
                                if not any(x in url_val for x in ("127.0.0.1", "localhost", "::1")):
                                    return (
                                        False,
                                        f"Unsafe exploit code: outbound connection to '{url_val}' is disallowed",
                                    )

                        if obj_name == "socket" and attr_name in {"connect", "connect_ex"}:
                            if (
                                node.args
                                and isinstance(node.args[0], ast.Tuple)
                                and len(node.args[0].elts) > 0
                            ):
                                host_node = node.args[0].elts[0]
                                if isinstance(host_node, ast.Constant):
                                    host_val = str(host_node.value)
                                    if not any(
                                        x in host_val for x in ("127.0.0.1", "localhost", "::1")
                                    ):
                                        return (
                                            False,
                                            f"Unsafe exploit code: socket connection to '{host_val}' is disallowed",
                                        )
        except Exception as parse_err:
            return False, f"Unsafe exploit code: failed to validate syntax tree: {parse_err}"

        # Setup sandbox/temp directory
        temp_dir = file_path.parent / ".phoenix_sandbox"
        temp_dir.mkdir(exist_ok=True)

        target_module_path = temp_dir / "target_module.py"
        test_file_path = temp_dir / "test_exploit.py"

        try:
            target_module_path.write_text(code, encoding="utf-8")
            test_file_path.write_text(test_code, encoding="utf-8")

            # Run pytest
            import sys

            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_file_path), "-v"],
                cwd=str(temp_dir),
                capture_output=True,
                text=True,
                timeout=self._config.red_teamer.timeout_seconds,
            )

            # Analyze output
            # A successful exploit test could either PASS (if the test asserts the exploit worked)
            # or FAIL with a specific exception (e.g. if the vulnerable code crashes on the payload)
            # We look for indications that the test executed successfully and the assertions passed.
            output = result.stdout + "\n" + result.stderr
            if result.returncode == 0:
                return (
                    True,
                    f"Exploit test passed. Payload successfully triggered vulnerability.\n\nTest Code:\n{test_code}\n\nOutput:\n{output}",
                )
            else:
                return (
                    False,
                    f"Exploit test failed or errored out. Could not conclusively prove vulnerability.\n\nTest Code:\n{test_code}\n\nOutput:\n{output}",
                )

        except subprocess.TimeoutExpired:
            return False, "Exploit test timed out."
        except Exception as exc:
            return False, f"Error running exploit test: {exc}"
        finally:
            # Cleanup
            try:
                if target_module_path.exists():
                    target_module_path.unlink()
                if test_file_path.exists():
                    test_file_path.unlink()
                if temp_dir.exists() and not any(temp_dir.iterdir()):
                    temp_dir.rmdir()
            except Exception:
                pass
