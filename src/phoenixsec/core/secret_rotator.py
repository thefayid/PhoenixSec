import re
import secrets
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType

log = get_logger(__name__)


class MockCloudSecretRotator:
    """Simulates integration with Cloud Providers to revoke and rotate secrets."""

    def __init__(self, workspace_root: Path | None = None) -> None:
        self.workspace_root = workspace_root or Path.cwd()

    def identify_provider(self, secret_value: str) -> str | None:
        """Heuristically identify the cloud provider based on secret format."""
        if secret_value.startswith("AKIA") and len(secret_value) == 20:
            return "AWS"
        if secret_value.startswith("ghp_") or secret_value.startswith("github_pat_"):
            return "GitHub"
        if secret_value.startswith("sk_live_") or secret_value.startswith("sk_test_"):
            return "Stripe"
        return None

    def revoke_and_rotate(self, finding: Finding, file_content: str) -> tuple[bool, str]:
        """Attempt to revoke the leaked secret and generate a new one.

        Returns:
            (success_bool, details_str)
        """
        if finding.vulnerability_type != VulnerabilityType.HARDCODED_SECRET:
            return False, "Not a hardcoded secret."

        # Extract the literal secret from the source code based on line number
        # A simple regex extraction just for demonstration purposes.
        lines = file_content.splitlines()
        if finding.line_number is None or finding.line_number > len(lines):
            return False, "Invalid line number."

        target_line = lines[finding.line_number - 1]

        # Look for typical string assignments
        match = re.search(r'[\'"]([A-Za-z0-9_]{10,})[\'"]', target_line)
        if not match:
            return False, "Could not reliably extract secret value from line."

        secret_value = match.group(1)
        provider = self.identify_provider(secret_value)

        if not provider:
            return False, f"Could not identify cloud provider for secret: {secret_value[:4]}***"

        # Simulating API Calls
        details = []
        details.append(
            f"🔍 Identified {provider} credential in {finding.file_path}:{finding.line_number}"
        )
        details.append(f"🌐 Initiating {provider} API connection (Simulated)...")
        details.append(
            f"❌ Revoking compromised credential: {secret_value[:4]}...{secret_value[-4:]}"
        )

        # Generate new mock key
        new_key = ""
        env_key = ""
        if provider == "AWS":
            new_key = f"AKIA{secrets.token_hex(8).upper()}"
            env_key = "AWS_ACCESS_KEY_ID"
        elif provider == "GitHub":
            new_key = f"ghp_{secrets.token_urlsafe(26)}"
            env_key = "GITHUB_TOKEN"
        elif provider == "Stripe":
            new_key = f"sk_live_{secrets.token_urlsafe(24)}"
            env_key = "STRIPE_API_KEY"

        details.append(f"✅ Provisioned new {provider} credential: {new_key[:4]}...{new_key[-4:]}")

        # Inject into .env
        env_path = self.workspace_root / ".env"
        env_entry = f"{env_key}={new_key}\n"

        try:
            if env_path.exists():
                content = env_path.read_text(encoding="utf-8")
                if env_key in content:
                    # Replace existing
                    new_content = re.sub(
                        f"^{env_key}=.*$", env_entry.strip(), content, flags=re.MULTILINE
                    )
                    env_path.write_text(new_content, encoding="utf-8")
                else:
                    with env_path.open("a", encoding="utf-8") as f:
                        f.write(env_entry)
            else:
                env_path.write_text(env_entry, encoding="utf-8")

            details.append(f"🔒 Automatically injected new credential into {env_path.name}")
        except Exception as e:
            details.append(f"⚠️ Failed to update .env file: {e}")
            return False, "\n".join(details)

        return True, "\n".join(details)
