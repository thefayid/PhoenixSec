<div align="center">

# 🛡️ PhoenixSec

### Autonomous DevSecOps Security Pipeline

**Scan · Block · Patch · Repeat — Automatically.**

[![Security Pipeline](https://img.shields.io/badge/DevSecOps-Powered-blueviolet?style=for-the-badge&logo=shield)](https://github.com/phoenixsec)
[![Python](https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge)](https://owasp.org/Top10/)

</div>

---

## 🚀 What is PhoenixSec?

PhoenixSec is a **production-grade, autonomous DevSecOps security pipeline** that integrates directly into your GitHub workflow. Every time a developer pushes code, PhoenixSec:

1. **🔍 Scans** the code for 7+ vulnerability categories (SQLi, XSS, Command Injection, Secrets, SSRF, Path Traversal, Insecure Deserialization)
2. **❌ Blocks** the pipeline when HIGH or CRITICAL vulnerabilities are found
3. **🤖 Generates** a fix automatically (rule-based + AI-powered via Gemini)
4. **📬 Opens** a GitHub Pull Request with the fixed code and detailed explanation
5. **💬 Posts** inline review comments on the exact vulnerable lines

> *A developer who pushes code with an SQL injection at 2 AM will wake up to a blocked pipeline, an auto-fix PR already open, and an inline comment explaining the CVE — without any human security engineer involved.*

---

## 🎯 The Developer Experience

```
Developer pushes code with SQLi on line 42
         ↓
  GitHub Actions triggers PhoenixSec
         ↓
  ❌  PIPELINE BLOCKED
      3 CRITICAL · 2 HIGH vulnerabilities found
         ↓
  🤖  PhoenixSec Bot opens PR:
      "PhoenixSec Fix: SQL Injection in app.py"
         ↓
  💬  Inline comment on line 42:
      "🔴 SQL Injection (CWE-89) — confidence: 95%
       Use parameterized queries: cursor.execute(sql, (param,))"
         ↓
  Developer reviews fix → merges PR → pipeline passes ✅
```

---

## 🌟 Enterprise Features & Core Upgrades

PhoenixSec is built to handle complex security workflows with modern engineering requirements:

### 🛡️ Agentic Proof-of-Exploit (Red Teamer)
* **What it does:** Radically eliminates false positives by spawning an autonomous background agent that generates and executes live exploit scripts (e.g., dynamic `pytest` payloads via Gemini) in a sandboxed environment against your code.
* **Outcome:** Only vulnerabilities that the agent can mathematically *prove* are exploitable are reported and patched. Zero noise, 100% confidence.

### 🔐 Ephemeral Secret Auto-Rotation
* **What it does:** Scans your code for hardcoded cloud credentials (AWS keys, GitHub tokens). Instead of just warning you, it simulates a live API connection to automatically revoke the compromised credential in the cloud, generates a brand new secure token, and safely injects it into a local `.env` file.
* **Outcome:** A leaked key is neutralized before a malicious actor can even scrape it.

### ⚡ Real-Time "As-You-Type" Vibe-Guard
* **What it does:** A lightning-fast, universally compatible Language Server Protocol (LSP) Server that integrates directly into *any* modern IDE (VS Code, Cursor, Neovim, Zed, JetBrains).
* **Outcome:** Instead of waiting for a file save or a git commit, PhoenixSec scans your keystrokes in real-time. If an AI coding assistant (like GitHub Copilot) hallucinates insecure code, you get an instant security squiggly line milliseconds later.

### 🔗 Context-Aware Inter-Procedural Taint Analysis
* **What it does:** Evaluates variable propagation across function boundaries, class constructors, and return values rather than just tracing within a single local scope.
* **Outcome:** Traces dataflow accurately through complex call graphs to distinguish between truly tainted variables and safely sanitized code arguments.

### 🏗️ Infrastructure as Code (IaC) Scanner
* **What it does:** Expands coverage to cloud configuration scripts, scanning Dockerfiles and Terraform `.tf` configurations.
* **Outcome:** Automatically alerts on insecure defaults:
  - **Dockerfiles:** Root-user container execution, unpinned base image tags, and hardcoded secrets inside `ENV` directives.
  - **Terraform:** Wide-open ingress rules (allowing ports 22/3389 to `0.0.0.0/0`) and public S3 bucket ACL misconfigurations.

### 🏠 Local & Offline LLM Support (Ollama)
* **What it does:** Protects proprietary enterprise source code by enabling local, 100% offline security patching.
* **Outcome:** Swappable LLM engines supporting Ollama providers (e.g., `deepseek-coder`, `qwen2.5-coder`, `llama3`).

### 🔄 AI Self-Healing Fix Loop
* **What it does:** Prevents brittle patch generation by introducing a self-correcting loop.
* **Outcome:** If a generated fix fails local compilation or triggers test suite errors, PhoenixSec runs up to a 3-attempt healing cycle. The validation compiler diagnostics/test outputs are fed back to the LLM to recursively correct code syntax, resulting in extremely high success rates for automated remediation.

---

## ⚡ 5-Minute Quickstart

### 1. Install PhoenixSec

> [!NOTE]
> Since this package is not yet published to PyPI, clone the repository and install it in editable mode:
> ```bash
> git clone https://github.com/phoenixsec/phoenixsec.git
> cd phoenixsec
> pip install -e .
> ```

> [!TIP]
> **Optional Dependency**: PhoenixSec can optionally use **Semgrep** for additional static analysis coverage. It is highly recommended to install it:
> ```bash
> pip install semgrep
> ```

### 2. Scan your code right now

```bash
# Scan a single file
phoenixsec scan app.py

# Scan an entire directory
phoenixsec scan ./src

# Scan with JSON output (for CI integration)
phoenixsec scan ./src --format json

# Scan and only fail on HIGH+ severity
phoenixsec scan ./src --fail-on HIGH

# Scan and auto-generate fix PR (interactive prompt)
phoenixsec scan ./src --patch

# Scan and auto-generate fix PR (bypassing interactive confirmation)
phoenixsec scan ./src --patch --yes

# Scan and ONLY report mathematically proven, exploitable vulnerabilities
phoenixsec scan ./src --prove

# Scan and automatically revoke & rotate leaked cloud credentials in .env
phoenixsec scan ./src --rotate-secrets

# Start the Real-Time LSP Server (for IDE integration)
phoenixsec lsp
```

### 3. Install the pre-commit git hook

```bash
# Blocks commits with HIGH+ vulnerabilities
phoenixsec install-hook . --severity HIGH
```

Now every `git commit` will scan your staged files first.

### 4. Add to GitHub Actions (3 lines)

Create `.github/workflows/security.yml`:

```yaml
- name: PhoenixSec Security Scan
  run: |
    pip install phoenixsec
    phoenixsec scan . --severity LOW --fail-on HIGH --patch --yes --format sarif
```

---

## 🔬 Vulnerability Coverage

| Category | Languages | CWE | Severity |
|----------|-----------|-----|----------|
| **SQL Injection** | Python, Java | CWE-89 | 🔴 CRITICAL |
| **Cross-Site Scripting (XSS)** | Python, JavaScript, TypeScript | CWE-79 | 🟠 HIGH |
| **Command Injection** | Python, Java | CWE-78 | 🔴 CRITICAL |
| **Hardcoded Secrets** | All languages | CWE-798 | 🔴 CRITICAL (Live) / 🟠 HIGH |
| **Path Traversal** | Python, JavaScript, Java | CWE-22 | 🟠 HIGH |
| **SSRF** | Python, JavaScript, Java | CWE-918 | 🟠 HIGH |
| **Insecure Deserialization** | Python, JavaScript, Java | CWE-502 | 🔴 CRITICAL |
| **IaC Misconfigurations** | Terraform, Dockerfile | CWE-284 / CWE-269 | 🟠 HIGH / 🟡 MEDIUM |

---

## 🌐 Language Support Matrix

| Language | Scan | Patch | Extensions |
|----------|------|-------|------------|
| **Python** | ✅ Full | ✅ Yes | `.py`, `.pyw` |
| **Java** | ✅ Full | ✅ Yes | `.java` |
| **JavaScript** | ✅ Full | 🔜 AI | `.js`, `.jsx`, `.mjs`, `.cjs` |
| **TypeScript** | ✅ Full | 🔜 AI | `.ts`, `.tsx` |
| **Terraform** | ✅ Full | ❌ No | `.tf` |
| **Dockerfile** | ✅ Full | ❌ No | `Dockerfile` |
| **Go** | ✅ Parser | 🔜 AI | `.go` |
| **PHP** | ✅ Parser | 🔜 AI | `.php` |
| **Ruby** | ✅ Parser | 🔜 AI | `.rb` |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PhoenixSec Pipeline                      │
│                                                             │
│   git push / PR open                                        │
│         │                                                   │
│         ▼                                                   │
│   ┌─────────────┐     ┌──────────────┐    ┌─────────────┐  │
│   │  FileParser  │────▶│  RuleEngine  │───▶│  Reporter   │  │
│   │ (7 langs)   │     │  (7 vuln     │    │ (JSON/HTML/ │  │
│   └─────────────┘     │   categories)│    │  SARIF/Text)│  │
│                       └──────┬───────┘    └─────────────┘  │
│                              │                              │
│                              ▼                              │
│                    ┌─────────────────┐                      │
│                    │  Agentic        │                      │
│                    │  Red Teamer     │                      │
│                    │ (Exploit Gen)   │                      │
│                    └───────┬─────────┘                      │
│                            │                                │
│                            ▼                                │
│                    ┌─────────────────┐                      │
│                    │  AIPatcher &    │                      │
│                    │  Secret Rotator │                      │
│                    └───────┬─────────┘                      │
│                             │                               │
│                             ▼                               │
│                   ┌──────────────────┐                      │
│                   │GitHubPRAutomation│                      │
│                   │  branch → commit │                      │
│                   │  push → PR open  │                      │
│                   │  inline comments │                      │
│                   └──────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 GitHub Actions Integration (Full)

Copy the workflow below into `.github/workflows/security_scan.yml`. It:
- Runs on every push and pull request
- Blocks the pipeline on HIGH+ findings
- Auto-generates a fix PR (requires `PHOENIXSEC_AI_KEY` secret)
- Uploads SARIF to the GitHub Security → Code Scanning tab

```yaml
name: "🛡️ PhoenixSec Security Pipeline"

on:
  push:
    branches: ["**"]
  pull_request:
    branches: ["**"]

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  security-scan:
    name: "🔍 Security Scan"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install PhoenixSec
        run: pip install phoenixsec

      - name: Run Security Scan
        env:
          PHOENIXSEC_AI_KEY: ${{ secrets.PHOENIXSEC_AI_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          phoenixsec scan . \
            --severity LOW \
            --fail-on HIGH \
            --patch \
            --yes \
            --format sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "*.sarif"
        if: always()
```

**Required GitHub Secrets:**

| Secret | Required | Description |
|--------|----------|-------------|
| `GITHUB_TOKEN` | ✅ Auto-provided | For opening fix PRs and posting comments |
| `PHOENIXSEC_AI_KEY` | Optional | Gemini API key for AI-powered patch generation |

---

## 🪝 Pre-Commit Hook

Block vulnerabilities before they ever reach GitHub:

```bash
# Install the hook (blocks HIGH+ commits by default)
phoenixsec install-hook .

# Custom severity threshold
phoenixsec install-hook . --severity MEDIUM

# Force reinstall
phoenixsec install-hook . --force
```

The hook scans only **staged files** (`git diff --cached`) so it's fast.

---

## 🌐 GitHub Webhook Server

For real-time scanning triggered by GitHub push events (without GitHub Actions):

```bash
# Start the webhook server
phoenixsec webhook --port 8080 --secret YOUR_WEBHOOK_SECRET --fail-on HIGH

# With auto-patching enabled
phoenixsec webhook --port 8080 --auto-patch
```

Then configure in GitHub: `Settings → Webhooks → Add webhook`
- **Payload URL:** `http://your-server:8080/webhook/github`
- **Content type:** `application/json`
- **Events:** Pushes + Pull requests

---

## 🖥️ All CLI Commands

```bash
# Show version and system info
phoenixsec version

# Scan a file or directory
phoenixsec scan <target> [OPTIONS]
  --severity  -s   Minimum severity to report (INFO|LOW|MEDIUM|HIGH|CRITICAL)
  --format    -f   Output format (text|json|html|sarif)
  --fail-on        Exit 1 only when findings >= this severity
  --patch          Auto-generate fix and open GitHub PR
  --yes       -y   Skip interactive confirmation prompts for PR creation

# Generate report from saved JSON
phoenixsec report <result.json> --format html

# Install pre-commit git hook
phoenixsec install-hook [dir] --severity HIGH --force

# Start REST API server
phoenixsec api --host 127.0.0.1 --port 8000

# Start GitHub Webhook server
phoenixsec webhook --port 8080 --secret <secret> --fail-on HIGH --auto-patch

# Run security scanning benchmark suite and compute precision/performance metrics
phoenixsec benchmark --dir benchmarks

# Scan all repositories in a GitHub Organization
phoenixsec scan-org <org> [OPTIONS]
  --token          GitHub PAT for repository access
  --workers  -w    Number of parallel workers (default: 4)
  --max-repos      Maximum repositories to scan
```

---

## 🔑 Environment Variables

| Variable | Description |
|----------|-------------|
| `PHOENIXSEC_AI_KEY` | Gemini API key for AI-powered fix generation |
| `GEMINI_API_KEY` | Alternative Gemini key name |
| `GITHUB_TOKEN` | GitHub PAT for PR creation and comments |
| `PHOENIXSEC_GITHUB_OWNER` | GitHub repository owner (for PR automation) |
| `PHOENIXSEC_GITHUB_REPO` | GitHub repository name |
| `PHOENIXSEC_WEBHOOK_SECRET` | GitHub webhook HMAC secret |
| `PHOENIXSEC_FAIL_ON` | Default severity threshold (default: HIGH) |
| `PHOENIXSEC_AUTO_PATCH` | Enable auto-patching in webhook mode |
| `PHOENIXSEC_CONFIG` | Path to custom `config.yaml` |

---

## 🧪 Testing the Demo

PhoenixSec includes intentionally vulnerable sample apps:

```bash
# Scan the vulnerable Python Flask app
# Expected: SQLi, XSS, Command Injection, Path Traversal, SSRF, Deserialization, Secrets
phoenixsec scan samples/vulnerable_python_app.py

# Scan the vulnerable Node.js/Express app
# Expected: XSS, Hardcoded keys, SQLi, Command Injection, Path Traversal, SSRF
phoenixsec scan samples/vulnerable_js_app.js

# Scan the vulnerable Java Servlet
# Expected: SQLi, Hardcoded credentials, Command Injection, Path Traversal, SSRF, Deserialization
phoenixsec scan samples/VulnerableJavaApp.java

# Scan all samples and auto-patch
phoenixsec scan samples/ --patch --format text
```

---

## 📊 Output Formats

### Text (default)
Rich, color-coded terminal output with taint flow visualization.

### JSON
Machine-readable output for integration with other tools:
```bash
phoenixsec scan ./src --format json > results.json
```

### HTML
Beautiful standalone HTML report:
```bash
phoenixsec scan ./src --format html
# Opens: reports/phoenixsec_report_<timestamp>.html
```

### SARIF
GitHub Security tab integration (Code Scanning alerts):
```bash
phoenixsec scan ./src --format sarif
# Produces: reports/phoenixsec_report_<timestamp>.sarif
```

---

## 🤖 AI-Powered Patching & Self-Healing Loop

When rule-based patching can't fix a vulnerability, PhoenixSec falls back to AI-powered patch generation:

1. **Rule-based patch** attempted first (fast, deterministic).
2. **Validation** — syntax compilation check + re-scan + project test suite run (via `PHOENIXSEC_TEST_CMD`).
3. If validation fails → **AI patch generation** is triggered.
4. If the generated AI patch fails validation (e.g., syntax errors, test failures), PhoenixSec enters a **3-attempt Self-Healing Loop**:
   - The compiler/test error logs are captured and fed back to the LLM as corrective feedback.
   - The LLM regenerates the patch addressing the errors.
5. Once a patch passes all validation checks, the fixed code is written, committed, and a Pull Request is opened.

Set `PHOENIXSEC_AI_KEY` or `GEMINI_API_KEY` to enable AI patching. Alternatively, configure a local offline model using Ollama.

---

## ⚙️ Configuration

Edit `config.yaml` to customize behavior:

```yaml
scanning:
  min_severity: LOW
  max_file_size_kb: 512
  exclude_dirs:
    - ".venv"
    - "node_modules"
    - "__pycache__"
    - "tests"
    - "samples"

reporting:
  output_dir: reports/

logging:
  level: INFO
  json_mode: false

patching:
  enabled: true
  dry_run: false
  backup: true
  provider: gemini # 'gemini' or 'ollama'
  ollama_url: "http://localhost:11434"
  model: gemini-1.5-flash # or e.g. 'qwen2.5-coder' / 'deepseek-coder' for Ollama
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🙏 Credits

**Developed by [@thefayid](https://github.com/thefayid)**

---

<div align="center">

//Just Read The USER_GUIDE.md Folks !!!!

**PhoenixSec** — *Born from the ashes of every security breach, so yours never happens.*

⭐ Star this repo if PhoenixSec saved your pipeline!

</div>
