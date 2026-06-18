from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
import hashlib
from pathlib import Path
import typer

from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)



class GitHubPRAutomation:
    """Automates Git branch, commit, push, and GitHub PR creation for patches."""

    def create_pull_request(
        self,
        file_path: str | Path,
        patched_code: str,
        vulnerability_type: str,
        recommendation: str,
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        base_branch: str = "main",
        ai_generated: bool = False,
        auto_confirm: bool = False,
    ) -> str | None:
        """Remediate a vulnerability, commit the fix to a new branch, and open a PR."""
        # Resolve config from params or env vars
        token = token or os.environ.get("PHOENIXSEC_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        owner = owner or os.environ.get("PHOENIXSEC_GITHUB_OWNER") or os.environ.get("GITHUB_OWNER")
        repo = repo or os.environ.get("PHOENIXSEC_GITHUB_REPO") or os.environ.get("GITHUB_REPO")

        if not token or not owner or not repo:
            from rich.console import Console
            console = Console()
            console.print(
                "[yellow]Patch applied locally. Set PHOENIXSEC_GITHUB_TOKEN, PHOENIXSEC_GITHUB_OWNER, "
                "and PHOENIXSEC_GITHUB_REPO to enable automatic PR creation.[/yellow]"
            )
            return None

        file_path_resolved = Path(file_path).resolve()
        file_name = file_path_resolved.name

        if not auto_confirm:
            from rich.console import Console
            console = Console()
            console.print("[bold yellow]⚠️ This will create a new git branch and commit in this repository.[/bold yellow]")
            if not typer.confirm("Do you want to proceed with GitHub PR automation?"):
                console.print("[yellow]PR automation cancelled by user.[/yellow]")
                return None

        # Create branch name
        vuln_slug = re.sub(r"[^a-zA-Z0-9]", "-", vulnerability_type.lower())[:50].strip('-')
        file_slug = re.sub(r"[^a-zA-Z0-9]", "-", file_name.lower())[:30].strip('-')
        content_hash = hashlib.sha256(patched_code.encode("utf-8")).hexdigest()[:7]
        branch_prefix = "phoenixsec-ai-fix" if ai_generated else "phoenixsec-fix"
        branch_name = f"{branch_prefix}-{vuln_slug}-{file_slug}-{content_hash}"

        log.info(f"PR Automation: starting fix on branch {branch_name}")

        try:
            # Find the git root directory by walking up parents
            git_root = file_path_resolved.parent
            for parent in [file_path_resolved.parent] + list(file_path_resolved.parent.parents):
                if (parent / ".git").is_dir():
                    git_root = parent
                    break
            
            cwd = str(git_root)

            # Query the GitHub API to check if an open PR with the head branch already exists
            existing_pr_url = None
            try:
                pulls_url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open"
                headers = {
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "PhoenixSec-Bot",
                }
                get_req = urllib.request.Request(pulls_url, headers=headers, method="GET")
                with urllib.request.urlopen(get_req) as response:
                    pulls_data = json.loads(response.read().decode("utf-8"))
                    if isinstance(pulls_data, list):
                        for pr in pulls_data:
                            ref = pr.get("head", {}).get("ref")
                            if ref == branch_name:
                                existing_pr_url = pr.get("html_url")
                                log.info(
                                    f"PR Automation: Found existing open PR {existing_pr_url} for branch {branch_name}"
                                )
                                break
            except Exception as exc:
                log.warning(f"Failed to query existing PRs: {exc}")

            # 1. Initialize git repo if not present
            git_dir = git_root / ".git"
            if not git_dir.is_dir():
                log.debug("PR Automation: Git repo not found, running 'git init'.")
                try:
                    subprocess.run(["git", "init"], cwd=cwd, check=True, capture_output=True)
                    # Make initial commit if newly initialized
                    subprocess.run(["git", "add", "."], cwd=cwd, check=True, capture_output=True)
                    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=cwd, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    raise PhoenixSecError(f"Could not initialize git repository: {e.stderr.decode().strip()}") from e

            # Configure basic git user name and email locally if not set
            subprocess.run(
                ["git", "config", "user.name", "PhoenixSec Bot"],
                cwd=cwd,
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "bot@phoenixsec.dev"],
                cwd=cwd,
                check=False,
                capture_output=True,
            )

            # 2. Checkout to new branch or existing branch
            try:
                subprocess.run(
                    ["git", "checkout", "-B", branch_name], cwd=cwd, check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                raise PhoenixSecError(
                    f"Could not switch to branch {branch_name} — you may have uncommitted local changes. "
                    "Commit or stash them first."
                ) from e

            # 3. Write patched code to the file (it's already patched locally, but we ensure it's written in this branch)
            file_path_resolved.write_text(patched_code, encoding="utf-8")

            try:
                rel_path = file_path_resolved.relative_to(git_root).as_posix()
            except ValueError:
                rel_path = file_name

            # 4. Stage and commit changes
            try:
                subprocess.run(["git", "add", rel_path], cwd=cwd, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise PhoenixSecError("Could not stage patched file for commit.") from e

            title_prefix = "PhoenixSec AI Fix" if ai_generated else "PhoenixSec Fix"
            commit_msg = f"{title_prefix}: Resolved {vulnerability_type} in {rel_path}"
            try:
                subprocess.run(
                    ["git", "commit", "-m", commit_msg], cwd=cwd, check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                # If there's nothing to commit, it will fail here. But we just patched the file, so it should be fine.
                err_msg = e.stderr.decode().strip() or e.stdout.decode().strip()
                if "nothing to commit" not in err_msg.lower():
                    raise PhoenixSecError(f"Could not commit patched file: {err_msg}") from e

            # 5. Push branch to remote (optional/ignored if no remote setup)
            try:
                subprocess.run(
                    ["git", "push", "origin", branch_name], cwd=cwd, check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode().strip()
                log.warning(f"Git push failed (possibly no remote origin): {err_msg}")
                raise PhoenixSecError(f"Could not push branch to remote origin: {err_msg}") from e

            # If an open PR already exists, return its URL and skip duplicate PR creation
            if existing_pr_url:
                log.info(f"Existing PR found. Returning existing PR URL: {existing_pr_url}")
                return existing_pr_url

            # 6. Open Pull Request via GitHub REST API
            pr_title = f"{title_prefix}: Resolved {vulnerability_type} in {file_name}"

            body_header = "### 🛡️ PhoenixSec Automatic Security Patch\n\n"
            if ai_generated:
                body_header += (
                    "> [!CAUTION]\n"
                    "> **AI-Generated Patch**: This patch was generated by an AI model "
                    "and automatically validated via syntax compiling, a scanner re-scan, "
                    "and local unit tests. Please review carefully before merging.\n\n"
                )

            pr_body = (
                body_header + f"**Vulnerability Type:** {vulnerability_type}\n"
                f"**Target File:** `{file_name}`\n\n"
                "#### 📝 Remediation Explanation:\n"
                f"{recommendation}\n\n"
                "---\n"
                "*This Pull Request was generated automatically by PhoenixSec.*"
            )

            url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "User-Agent": "PhoenixSec-Bot",
            }
            payload = {"title": pr_title, "head": branch_name, "base": base_branch, "body": pr_body}

            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
            )

            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                pr_html_url = res_data.get("html_url")
                log.info(f"Successfully created GitHub PR: {pr_html_url}")
                return pr_html_url

        except PhoenixSecError:
            raise
        except Exception as exc:
            log.error(f"GitHub PR automation failed: {exc}")
            raise PhoenixSecError(f"GitHub PR automation failed: {exc}") from exc

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        """Post review comments on a GitHub Pull Request at specific file paths and line numbers.

        Parameters
        ----------
        pr_number : int
            The pull request number.
        findings : list[Finding]
            Vulnerabilities detected.
        owner : str, optional
            GitHub repository owner (defaults to env var).
        repo : str, optional
            GitHub repository name (defaults to env var).
        token : str, optional
            GitHub PAT token (defaults to env var).
        scan_root : str | Path, optional
            Path to resolve relative paths for files.

        Returns
        -------
        int
            Number of successfully posted comments.
        """
        token = token or os.environ.get("PHOENIXSEC_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        owner = owner or os.environ.get("PHOENIXSEC_GITHUB_OWNER") or os.environ.get("GITHUB_OWNER")
        repo = repo or os.environ.get("PHOENIXSEC_GITHUB_REPO") or os.environ.get("GITHUB_REPO")

        if not token or not owner or not repo:
            log.warning(
                "GitHub owner, repo, or token not set. Skipping posting Pull Request comments."
            )
            return 0

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }

        # 1. Fetch latest commit SHA from the PR
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as response:
                pr_data = json.loads(response.read().decode("utf-8"))
                commit_id = pr_data.get("head", {}).get("sha")
            if not commit_id:
                log.error(f"Could not retrieve head commit SHA for PR #{pr_number}")
                return 0
        except Exception as exc:
            log.error(f"Failed to retrieve PR info: {exc}")
            return 0

        # Resolve scan root to make paths relative
        root_path = Path(scan_root).resolve() if scan_root else Path.cwd().resolve()
        comments_posted = 0

        # 2. Post a comment for each finding
        for f in findings:
            if not f.line_number:
                continue

            file_path_resolved = Path(f.file_path).resolve()
            try:
                rel_path = file_path_resolved.relative_to(root_path).as_posix()
            except ValueError:
                rel_path = file_path_resolved.name

            # Format comment body
            badge = "🔴" if f.severity >= Severity.HIGH else "🟡"
            comment_body = (
                f"### {badge} PhoenixSec Alert: {f.vulnerability_type.value}\n\n"
                f"**Severity:** `{f.severity.name}` | "
                f"**Confidence:** `{int(f.confidence_score * 100)}%` | "
                f"**Rule ID:** `{f.rule_id}`\n\n"
                f"#### 📝 Recommendation:\n"
                f"{f.recommendation}\n\n"
                f"---\n"
                f"*PhoenixSec Static Analysis Pipeline*"
            )

            payload = {
                "body": comment_body,
                "commit_id": commit_id,
                "path": rel_path,
                "line": f.line_number,
                "side": "RIGHT",
            }

            try:
                comment_url = (
                    f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
                )
                comment_req = urllib.request.Request(
                    comment_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(comment_req) as response:
                    log.info(f"Successfully posted PR review comment on {rel_path}:{f.line_number}")
                    comments_posted += 1
            except Exception as exc:
                log.warning(f"Failed to post comment on {rel_path}:{f.line_number}: {exc}")

        return comments_posted
