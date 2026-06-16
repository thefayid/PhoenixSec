from __future__ import annotations

import contextlib
import json
import os
import py_compile
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.engine import RuleEngine

log = get_logger(__name__)


class AIPatcher:
    """Fallback patch generation using LLM API, with verification and rollback."""

    def __init__(self, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine()

    def _find_venv_bin(self, bin_name: str) -> Path | None:
        """Find executable dynamically in venv folders or current Python prefix."""
        import sys

        # Check current sys.prefix first
        prefix = Path(sys.prefix)
        for folder in ("Scripts", "bin"):
            for ext in ("", ".exe", ".cmd"):
                candidate = prefix / folder / f"{bin_name}{ext}"
                if candidate.is_file():
                    return candidate

        # Check local .venv folder
        for folder in ("Scripts", "bin"):
            for ext in ("", ".exe", ".cmd"):
                candidate = Path(".venv") / folder / f"{bin_name}{ext}"
                if candidate.is_file():
                    return candidate

        return None

    def generate_patch(self, code: str, finding: Finding) -> str:
        """Call the Google Gemini API to generate a secure patch for the vulnerability.

        Parameters
        ----------
        code : str
          The original source code.
        finding : Finding
          The vulnerability finding to remediate.

        Returns
        -------
        str
          The patched source code.
        """
        api_key = os.environ.get("PHOENIXSEC_AI_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise PhoenixSecError(
                "Missing PHOENIXSEC_AI_KEY or GEMINI_API_KEY environment variable."
            )

        file_name = Path(finding.file_path).name if finding.file_path else "source_file"
        prompt = (
            "You are a secure software engineering assistant. Your task is to fix "
            "a security vulnerability in the provided source code.\n\n"
            f"Vulnerability Details:\n"
            f"- File: {file_name}\n"
            f"- Type: {finding.vulnerability_type.value}\n"
            f"- Line Number: {finding.line_number}\n"
            f"- Sink: {finding.sink or 'N/A'}\n"
            f"- Source: {finding.source or 'N/A'}\n"
            f"- Recommendation: {finding.recommendation}\n\n"
            "Here is the original source code:\n"
            "```\n"
            f"{code}\n"
            "```\n\n"
            "Instructions:\n"
            "1. Output ONLY the complete corrected/patched source code for the file.\n"
            "2. Fix the specified vulnerability. Do not introduce syntax errors, "
            "new vulnerabilities, or break existing behavior.\n"
            "3. Retain all other imports, structure, and unrelated logic.\n"
            "4. Do NOT wrap code in markdown block wrappers unless the raw response "
            "consists ONLY of the code block itself. Do NOT write conversational text, "
            "introduction, or explanations.\n"
        )

        base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        url = f"{base_url}/gemini-1.5-flash:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "text/plain"},
        }

        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )

        max_retries = 3
        backoff = 2.0
        for attempt in range(max_retries + 1):
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
            except urllib.error.HTTPError as exc:
                # Retry on 429 (Too Many Requests) or 5xx (Server Error)
                is_retryable = exc.code == 429 or (500 <= exc.code < 600)
                if is_retryable and attempt < max_retries:
                    sleep_time = backoff * (2**attempt)
                    log.warning(
                        f"AI Patch Generation API HTTP error {exc.code}: {exc.reason}. "
                        f"Retrying in {sleep_time}s... (Attempt {attempt + 1}/{max_retries + 1})"
                    )
                    time.sleep(sleep_time)
                    continue
                log.error(f"AI Patch Generation API call failed on HTTP error: {exc}")
                raise PhoenixSecError(f"AI Patch API Call failed: {exc}") from exc
            except urllib.error.URLError as exc:
                # Connection / Timeout error
                if attempt < max_retries:
                    sleep_time = backoff * (2**attempt)
                    log.warning(
                        f"AI Patch Generation API connection error: {exc.reason}. "
                        f"Retrying in {sleep_time}s... (Attempt {attempt + 1}/{max_retries + 1})"
                    )
                    time.sleep(sleep_time)
                    continue
                log.error(f"AI Patch Generation API call failed: {exc}")
                raise PhoenixSecError(f"AI Patch API Call failed: {exc}") from exc
            except Exception as exc:
                log.error(f"AI Patch Generation API call failed with unexpected error: {exc}")
                raise PhoenixSecError(f"AI Patch API Call failed: {exc}") from exc

    def validate_patch(
        self, original_code: str, patched_code: str, file_path: Path, finding: Finding
    ) -> bool:
        """Validate the patch using syntax compilation, re-scanning, and test execution.

        Parameters
        ----------
        original_code : str
          The clean code before patching.
        patched_code : str
          The new code suggested by the LLM.
        file_path : Path
          Target file path.
        finding : Finding
          The original finding being resolved.

        Returns
        -------
        bool
          True if all validations pass, False otherwise.
        """
        temp_file = file_path.parent / f".tmp_{file_path.name}"
        try:
            # 1. Syntax Compilation Check (Python only for now)
            if file_path.suffix.lower() == ".py":
                temp_file.write_text(patched_code, encoding="utf-8")
                try:
                    py_compile.compile(str(temp_file), doraise=True)
                except py_compile.PyCompileError as exc:
                    log.warning(
                        f"AI Patch Validation: Syntax check failed on {file_path.name}: {exc}"
                    )
                    return False

            # 2. Re-Scan Validation
            # Verify the original finding is resolved and no new
            # HIGH/CRITICAL severities are introduced.
            # Use scan_code since we don't want Semgrep executing on a
            # non-existent temp file on disk, or we can read the temp file.
            lang = "python" if file_path.suffix.lower() == ".py" else "java"
            res_orig = self._rule_engine.scan_code(
                original_code, file_path=str(file_path), language=lang
            )
            findings_before = res_orig.findings
            res = self._rule_engine.scan_code(patched_code, file_path=str(file_path), language=lang)
            findings_after = res.findings

            # Check if original vulnerability is still there (matching type and close lines)
            still_vulnerable = False
            for f in findings_after:
                same_type = f.vulnerability_type == finding.vulnerability_type
                line_dist = abs((f.line_number or 0) - (finding.line_number or 0)) <= 5
                if same_type and line_dist:
                    still_vulnerable = True
                    break

            if still_vulnerable:
                log.warning(
                    f"AI Patch Validation: Patch failed to resolve "
                    f"vulnerability in {file_path.name}."
                )
                return False

            # Check if new high/critical issues introduced
            for f in findings_after:
                if f.severity >= Severity.HIGH:
                    # Ignore if the same finding existed in the original code
                    # (with a line tolerance of 20)
                    existed = False
                    for fb in findings_before:
                        if (
                            fb.vulnerability_type == f.vulnerability_type
                            and fb.rule_id == f.rule_id
                        ):
                            line_before = fb.line_number or 0
                            line_after = f.line_number or 0
                            if abs(line_after - line_before) <= 20:
                                existed = True
                                break
                    if existed:
                        continue

                    log.warning(
                        f"AI Patch Validation: Patch introduced new vulnerability "
                        f"{f.vulnerability_type} ({f.severity.name}) in {file_path.name}."
                    )
                    return False

            # 3. Test Suite Execution Check
            # Prevent infinite recursion if running under pytest and
            # subprocess.run is not mocked.
            is_pytest = "PYTEST_CURRENT_TEST" in os.environ
            is_mocked = hasattr(subprocess.run, "assert_called")
            if is_pytest and not is_mocked:
                log.info(
                    "AI Patch Validation: Pytest run detected. "
                    "Skipping subprocess test validation to prevent recursion."
                )
                return True

            # Check for configured test command or env variable PHOENIXSEC_TEST_CMD
            test_cmd_env = os.environ.get("PHOENIXSEC_TEST_CMD")
            if not test_cmd_env:
                log.info(
                    "AI Patch Validation: No test command configured via PHOENIXSEC_TEST_CMD. "
                    "Skipping step 3 (test execution)."
                )
                return True

            import shlex

            cmd_args = shlex.split(test_cmd_env, posix=(os.name == "posix"))

            # Write patched code temporarily to the actual file for running tests
            file_path.write_text(patched_code, encoding="utf-8")

            log.info(f"AI Patch Validation: Running test command '{' '.join(cmd_args)}'")
            # Run test process
            test_res = subprocess.run(cmd_args, capture_output=True, check=False)
            if test_res.returncode != 0:
                log.warning(
                    f"AI Patch Validation: Test suite failed with code "
                    f"{test_res.returncode}. Stderr: {test_res.stderr.decode().strip()}"
                )
                return False

            return True

        except Exception as exc:
            log.error(f"AI Patch Validation encountered exception: {exc}")
            return False
        finally:
            if temp_file.is_file():
                with contextlib.suppress(Exception):
                    temp_file.unlink()

    def patch_with_fallback(
        self, file_path: Path, findings: list[Finding]
    ) -> tuple[bool, str, bool]:
        """Apply rule-based patch, falling back to AI patch generation if needed.

        Parameters
        ----------
        file_path : Path
          File path to patch.
        findings : list[Finding]
          List of findings detected in this file.

        Returns
        -------
        tuple[bool, str, bool]
          Tuple of (success, patched_code, is_ai_patch).
        """
        # Read original code
        original_code = file_path.read_text(encoding="utf-8")

        # 1. Try rule-based patching
        from phoenixsec.core.patcher import Patcher

        patcher = Patcher()
        rule_patched, summary, changed_lines = patcher.patch(original_code, findings)

        if changed_lines:
            log.info(f"AI Patch fallback: Rule-based patch succeeded for {file_path.name}.")
            # Write to file temporarily to test
            try:
                # Validate the rule-based patch as well to be safe
                val_ok = self.validate_patch(original_code, rule_patched, file_path, findings[0])
                if val_ok:
                    file_path.write_text(rule_patched, encoding="utf-8")
                    return True, rule_patched, False
            except Exception as exc:
                log.warning(f"AI Patch fallback: Validation of rule-based patch failed: {exc}")

            # Revert to original before fallback
            file_path.write_text(original_code, encoding="utf-8")

        # 2. Fall back to AI patch generation
        log.info(
            f"AI Patch fallback: Rule-based patching failed or was invalid for "
            f"{file_path.name}. Querying AI..."
        )
        last_patched = original_code

        # Patch finding by finding (using the latest code state)
        for finding in findings:
            try:
                patched = self.generate_patch(last_patched, finding)
                # Validate this patch
                val_ok = self.validate_patch(original_code, patched, file_path, finding)
                if val_ok:
                    last_patched = patched
                else:
                    log.warning(
                        f"AI Patch fallback: AI patch rejected for finding at line "
                        f"{finding.line_number}."
                    )
                    # Revert to last good state (or original)
                    file_path.write_text(original_code, encoding="utf-8")
                    return False, original_code, False
            except Exception as exc:
                log.error(f"AI Patch fallback failed for finding: {exc}")
                file_path.write_text(original_code, encoding="utf-8")
                return False, original_code, False

        # Successfully patched all findings!
        file_path.write_text(last_patched, encoding="utf-8")
        return True, last_patched, True
