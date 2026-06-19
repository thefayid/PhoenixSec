from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


class BaseVCSAutomation:
    """Base class for VCS (Version Control System) Pull Request / Merge Request automation."""

    platform_name: str = "VCS"
    provider_slug: str = "vcs"

    def resolve_credentials(
        self, token: str | None, owner: str | None, repo: str | None
    ) -> tuple[str | None, str | None, str | None]:
        """Resolve access token, repository owner, and name from parameters or environment."""
        raise NotImplementedError

    def _print_credential_warning(self) -> None:
        """Print warning when required credentials are missing."""
        raise NotImplementedError

    def check_existing_pr(
        self, branch_name: str, owner: str, repo: str, token: str
    ) -> str | None:
        """Query the remote API to check if an open PR/MR already exists for this branch."""
        raise NotImplementedError

    def open_pr(
        self,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        owner: str,
        repo: str,
        token: str,
    ) -> str | None:
        """Open a new Pull Request or Merge Request via the VCS REST API."""
        raise NotImplementedError

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        """Post review comments on the PR/MR at specific file paths and line numbers."""
        raise NotImplementedError

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
        """Remediate a vulnerability, commit the fix to a new branch, and open a PR/MR."""
        token, owner, repo = self.resolve_credentials(token, owner, repo)

        if not token or not owner or not repo:
            self._print_credential_warning()
            return None

        file_path_resolved = Path(file_path).resolve()
        file_name = file_path_resolved.name

        if not auto_confirm:
            import sys

            import typer
            from rich.console import Console
            console = Console()

            if not sys.stdin.isatty():
                console.print(
                    f"[yellow]Non-interactive environment detected and --yes not passed — skipping {self.platform_name} PR automation. "
                    f"Patch was still applied locally. Pass --yes to enable PR automation in CI/non-interactive contexts.[/yellow]"
                )
                return None

            console.print(
                "[bold yellow]⚠️ This will create a new git branch and commit in this repository.[/bold yellow]"
            )
            try:
                if not typer.confirm(f"Do you want to proceed with {self.platform_name} PR automation?"):
                    console.print("[yellow]PR automation cancelled by user.[/yellow]")
                    return None
            except typer.Abort:
                console.print("\n[yellow]PR automation cancelled by user.[/yellow]")
                return None

        # Create branch name
        vuln_slug = re.sub(r"[^a-zA-Z0-9]", "-", vulnerability_type.lower())[:50].strip('-')
        file_slug = re.sub(r"[^a-zA-Z0-9]", "-", file_name.lower())[:30].strip('-')
        content_hash = hashlib.sha256(patched_code.encode("utf-8")).hexdigest()[:7]
        branch_prefix = "phoenixsec-ai-fix" if ai_generated else "phoenixsec-fix"
        branch_name = f"{branch_prefix}-{vuln_slug}-{file_slug}-{content_hash}"

        log.info(f"{self.platform_name} PR Automation: starting fix on branch {branch_name}")

        try:
            # Find the git root directory by walking up parents
            git_root = file_path_resolved.parent
            for parent in [file_path_resolved.parent] + list(file_path_resolved.parent.parents):
                if (parent / ".git").is_dir():
                    git_root = parent
                    break

            cwd = str(git_root)

            # Query the VCS API to check if an open PR/MR with the head branch already exists
            existing_pr_url = self.check_existing_pr(branch_name, owner, repo, token)

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

            # 3. Write patched code to the file
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
                err_msg = e.stderr.decode().strip() or e.stdout.decode().strip()
                if "nothing to commit" not in err_msg.lower():
                    raise PhoenixSecError(f"Could not commit patched file: {err_msg}") from e

            # 5. Push branch to remote (soft-fail if no remote setup)
            try:
                subprocess.run(
                    ["git", "push", "origin", branch_name], cwd=cwd, check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode().strip()
                log.warning(f"Git push failed (possibly no remote origin): {err_msg}")
                from rich.console import Console
                console = Console()
                console.print(
                    f"[yellow]Fix committed locally on branch {branch_name}, but could not push to remote 'origin' "
                    f"(no remote configured or no push access). Set up a remote to enable automatic PR creation.[/yellow]"
                )
                return None

            # If an open PR already exists, return its URL and skip duplicate PR creation
            if existing_pr_url:
                log.info(f"Existing PR/MR found. Returning existing URL: {existing_pr_url}")
                return existing_pr_url

            # 6. Open Pull Request / Merge Request via VCS API
            pr_title = f"{title_prefix}: Resolved {vulnerability_type} in {file_name}"

            body_header = f"### 🛡️ PhoenixSec Automatic Security Patch ({self.platform_name})\n\n"
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
                f"*This Pull Request was generated automatically by PhoenixSec.*"
            )

            return self.open_pr(branch_name, base_branch, pr_title, pr_body, owner, repo, token)

        except PhoenixSecError:
            raise
        except Exception as exc:
            log.error(f"{self.platform_name} PR automation failed: {exc}")
            raise PhoenixSecError(f"{self.platform_name} PR automation failed: {exc}") from exc


class GitHubAutomation(BaseVCSAutomation):
    """VCS Automation implementation for GitHub."""

    platform_name = "GitHub"
    provider_slug = "github"

    def resolve_credentials(
        self, token: str | None, owner: str | None, repo: str | None
    ) -> tuple[str | None, str | None, str | None]:
        token = token or os.environ.get("PHOENIXSEC_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        owner = owner or os.environ.get("PHOENIXSEC_GITHUB_OWNER") or os.environ.get("GITHUB_OWNER")
        repo = repo or os.environ.get("PHOENIXSEC_GITHUB_REPO") or os.environ.get("GITHUB_REPO")
        return token, owner, repo

    def _print_credential_warning(self) -> None:
        from rich.console import Console
        console = Console()
        console.print(
            "[yellow]Patch applied locally. Set PHOENIXSEC_GITHUB_TOKEN, PHOENIXSEC_GITHUB_OWNER, "
            "and PHOENIXSEC_GITHUB_REPO to enable automatic PR creation.[/yellow]"
        )

    def check_existing_pr(
        self, branch_name: str, owner: str, repo: str, token: str
    ) -> str | None:
        try:
            pulls_url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PhoenixSec-Bot",
            }
            req = urllib.request.Request(pulls_url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as response:
                pulls_data = json.loads(response.read().decode("utf-8"))
                if isinstance(pulls_data, list):
                    for pr in pulls_data:
                        ref = pr.get("head", {}).get("ref")
                        if ref == branch_name:
                            return pr.get("html_url")
        except Exception as exc:
            log.warning(f"Failed to query existing GitHub PRs: {exc}")
        return None

    def open_pr(
        self,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        owner: str,
        repo: str,
        token: str,
    ) -> str | None:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }
        payload = {"title": title, "head": branch_name, "base": base_branch, "body": body}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("html_url")

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        token, owner, repo = self.resolve_credentials(token, owner, repo)

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

        # Fetch latest commit SHA from the PR
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

        root_path = Path(scan_root).resolve() if scan_root else Path.cwd().resolve()
        comments_posted = 0

        # Post a comment for each finding
        for f in findings:
            if not f.line_number:
                continue

            file_path_resolved = Path(f.file_path).resolve()
            try:
                rel_path = file_path_resolved.relative_to(root_path).as_posix()
            except ValueError:
                rel_path = file_path_resolved.name

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
                with urllib.request.urlopen(comment_req):
                    log.info(f"Successfully posted PR review comment on {rel_path}:{f.line_number}")
                    comments_posted += 1
            except Exception as exc:
                log.warning(f"Failed to post comment on {rel_path}:{f.line_number}: {exc}")

        return comments_posted


class GitLabAutomation(BaseVCSAutomation):
    """VCS Automation implementation for GitLab."""

    platform_name = "GitLab"
    provider_slug = "gitlab"

    def resolve_credentials(
        self, token: str | None, owner: str | None, repo: str | None
    ) -> tuple[str | None, str | None, str | None]:
        token = token or os.environ.get("PHOENIXSEC_GITLAB_TOKEN") or os.environ.get("GITLAB_TOKEN")
        owner = owner or os.environ.get("PHOENIXSEC_GITLAB_OWNER") or os.environ.get("GITLAB_OWNER")
        repo = repo or os.environ.get("PHOENIXSEC_GITLAB_REPO") or os.environ.get("GITLAB_REPO")
        return token, owner, repo

    def _print_credential_warning(self) -> None:
        from rich.console import Console
        console = Console()
        console.print(
            "[yellow]Patch applied locally. Set PHOENIXSEC_GITLAB_TOKEN, PHOENIXSEC_GITLAB_OWNER, "
            "and PHOENIXSEC_GITLAB_REPO to enable automatic GitLab MR creation.[/yellow]"
        )

    def check_existing_pr(
        self, branch_name: str, owner: str, repo: str, token: str
    ) -> str | None:
        try:
            import urllib.parse
            project_path = f"{owner}/{repo}"
            encoded_path = urllib.parse.quote_plus(project_path)
            url = f"https://gitlab.com/api/v4/projects/{encoded_path}/merge_requests?state=opened&source_branch={branch_name}"
            headers = {
                "PRIVATE-TOKEN": token,
                "User-Agent": "PhoenixSec-Bot",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as response:
                mrs_data = json.loads(response.read().decode("utf-8"))
                if isinstance(mrs_data, list) and len(mrs_data) > 0:
                    return mrs_data[0].get("web_url")
        except Exception as exc:
            log.warning(f"Failed to query existing GitLab MRs: {exc}")
        return None

    def open_pr(
        self,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        owner: str,
        repo: str,
        token: str,
    ) -> str | None:
        import urllib.parse
        project_path = f"{owner}/{repo}"
        encoded_path = urllib.parse.quote_plus(project_path)
        url = f"https://gitlab.com/api/v4/projects/{encoded_path}/merge_requests"
        headers = {
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }
        payload = {
            "source_branch": branch_name,
            "target_branch": base_branch,
            "title": title,
            "description": body,
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("web_url")

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        token, owner, repo = self.resolve_credentials(token, owner, repo)
        if not token or not owner or not repo:
            log.warning(
                "GitLab owner, repo, or token not set. Skipping posting GitLab comments."
            )
            return 0

        import urllib.parse
        project_path = f"{owner}/{repo}"
        encoded_path = urllib.parse.quote_plus(project_path)
        headers = {
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }

        root_path = Path(scan_root).resolve() if scan_root else Path.cwd().resolve()
        comments_posted = 0

        for f in findings:
            if not f.line_number:
                continue

            file_path_resolved = Path(f.file_path).resolve()
            try:
                rel_path = file_path_resolved.relative_to(root_path).as_posix()
            except ValueError:
                rel_path = file_path_resolved.name

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
                "body": f"**File:** `{rel_path}` Line {f.line_number}\n\n{comment_body}"
            }

            try:
                url = f"https://gitlab.com/api/v4/projects/{encoded_path}/merge_requests/{pr_number}/notes"
                req = urllib.request.Request(
                    url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
                )
                with urllib.request.urlopen(req):
                    log.info(f"Successfully posted GitLab comment on {rel_path}:{f.line_number}")
                    comments_posted += 1
            except Exception as exc:
                log.warning(f"Failed to post GitLab comment: {exc}")

        return comments_posted


class BitbucketAutomation(BaseVCSAutomation):
    """VCS Automation implementation for Bitbucket Cloud."""

    platform_name = "Bitbucket"
    provider_slug = "bitbucket"

    def resolve_credentials(
        self, token: str | None, owner: str | None, repo: str | None
    ) -> tuple[str | None, str | None, str | None]:
        token = token or os.environ.get("PHOENIXSEC_BITBUCKET_TOKEN") or os.environ.get("BITBUCKET_TOKEN")
        owner = owner or os.environ.get("PHOENIXSEC_BITBUCKET_OWNER") or os.environ.get("BITBUCKET_OWNER")
        repo = repo or os.environ.get("PHOENIXSEC_BITBUCKET_REPO") or os.environ.get("BITBUCKET_REPO")
        return token, owner, repo

    def _print_credential_warning(self) -> None:
        from rich.console import Console
        console = Console()
        console.print(
            "[yellow]Patch applied locally. Set PHOENIXSEC_BITBUCKET_TOKEN, PHOENIXSEC_BITBUCKET_OWNER, "
            "and PHOENIXSEC_BITBUCKET_REPO to enable automatic Bitbucket PR creation.[/yellow]"
        )

    def check_existing_pr(
        self, branch_name: str, owner: str, repo: str, token: str
    ) -> str | None:
        try:
            url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}/pullrequests?state=OPEN"
            headers = {
                "Authorization": f"Bearer {token}",
                "User-Agent": "PhoenixSec-Bot",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode("utf-8"))
                if "values" in data:
                    for pr in data["values"]:
                        if pr.get("source", {}).get("branch", {}).get("name") == branch_name:
                            return pr.get("links", {}).get("html", {}).get("href")
        except Exception as exc:
            log.warning(f"Failed to query existing Bitbucket PRs: {exc}")
        return None

    def open_pr(
        self,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        owner: str,
        repo: str,
        token: str,
    ) -> str | None:
        url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}/pullrequests"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }
        payload = {
            "title": title,
            "description": body,
            "source": {
                "branch": {
                    "name": branch_name
                }
            },
            "destination": {
                "branch": {
                    "name": base_branch
                }
            }
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("links", {}).get("html", {}).get("href")

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        token, owner, repo = self.resolve_credentials(token, owner, repo)
        if not token or not owner or not repo:
            log.warning(
                "Bitbucket owner, repo, or token not set. Skipping posting Bitbucket comments."
            )
            return 0

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "PhoenixSec-Bot",
        }

        root_path = Path(scan_root).resolve() if scan_root else Path.cwd().resolve()
        comments_posted = 0

        for f in findings:
            if not f.line_number:
                continue

            file_path_resolved = Path(f.file_path).resolve()
            try:
                rel_path = file_path_resolved.relative_to(root_path).as_posix()
            except ValueError:
                rel_path = file_path_resolved.name

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

            # Post inline comment in Bitbucket
            payload = {
                "content": {
                    "raw": comment_body
                },
                "inline": {
                    "path": rel_path,
                    "to": f.line_number
                }
            }

            try:
                url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}/pullrequests/{pr_number}/comments"
                req = urllib.request.Request(
                    url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
                )
                with urllib.request.urlopen(req):
                    log.info(f"Successfully posted Bitbucket comment on {rel_path}:{f.line_number}")
                    comments_posted += 1
            except Exception as exc:
                log.warning(f"Failed to post Bitbucket comment: {exc}")

        return comments_posted


class GitHubPRAutomation:
    """Automates Git branch, commit, push, and PR/MR creation for patches (GitHub, GitLab, or Bitbucket)."""

    def __init__(self, provider: str | None = None):
        self._provider = provider
        self._impl = None

    @staticmethod
    def detect_provider() -> str:
        # 1. Environment override
        env_prov = os.environ.get("PHOENIXSEC_VCS_PROVIDER")
        if env_prov:
            return env_prov.lower()

        # 2. Check credentials set in environment
        if os.environ.get("PHOENIXSEC_GITLAB_TOKEN") or os.environ.get("GITLAB_TOKEN"):
            return "gitlab"
        if os.environ.get("PHOENIXSEC_BITBUCKET_TOKEN") or os.environ.get("BITBUCKET_TOKEN"):
            return "bitbucket"
        if os.environ.get("PHOENIXSEC_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"):
            return "github"

        # 3. Detect via .git/config directly to avoid subprocess and mocks issues in tests
        try:
            git_root = Path.cwd().resolve()
            for parent in [git_root] + list(git_root.parents):
                config_file = parent / ".git" / "config"
                if config_file.is_file():
                    content = config_file.read_text(encoding="utf-8", errors="ignore")
                    for line in content.splitlines():
                        if "url =" in line or "url=" in line:
                            url = line.lower()
                            if "gitlab" in url:
                                return "gitlab"
                            elif "bitbucket" in url:
                                return "bitbucket"
                            elif "github" in url:
                                return "github"
                    break
        except Exception:
            pass

        return "github"

    def _get_impl_lazy(self) -> BaseVCSAutomation:
        if self._impl is None:
            provider_name = self._provider or self.detect_provider()
            if provider_name == "gitlab":
                self._impl = GitLabAutomation()
            elif provider_name == "bitbucket":
                self._impl = BitbucketAutomation()
            else:
                self._impl = GitHubAutomation()
        return self._impl

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
        impl = self._get_impl_lazy()
        return impl.create_pull_request(
            file_path=file_path,
            patched_code=patched_code,
            vulnerability_type=vulnerability_type,
            recommendation=recommendation,
            owner=owner,
            repo=repo,
            token=token,
            base_branch=base_branch,
            ai_generated=ai_generated,
            auto_confirm=auto_confirm,
        )

    def post_pr_comments(
        self,
        pr_number: int,
        findings: list[Finding],
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        scan_root: str | Path | None = None,
    ) -> int:
        impl = self._get_impl_lazy()
        return impl.post_pr_comments(
            pr_number=pr_number,
            findings=findings,
            owner=owner,
            repo=repo,
            token=token,
            scan_root=scan_root,
        )
