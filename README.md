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
| **Hardcoded Secrets** | All languages | CWE-798 | 🟠 HIGH |
| **Path Traversal** | Python, JavaScript, Java | CWE-22 | 🟠 HIGH |
| **SSRF** | Python, JavaScript, Java | CWE-918 | 🟠 HIGH |
| **Insecure Deserialization** | Python, JavaScript, Java | CWE-502 | 🔴 CRITICAL |

---

## 🌐 Language Support Matrix

| Language | Scan | Patch | Extensions |
|----------|------|-------|------------|
| **Python** | ✅ Full | ✅ Yes | `.py`, `.pyw` |
| **Java** | ✅ Full | ✅ Yes | `.java` |
| **JavaScript** | ✅ Full | 🔜 AI | `.js`, `.jsx`, `.mjs`, `.cjs` |
| **TypeScript** | ✅ Full | 🔜 AI | `.ts`, `.tsx` |
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
│                    │  AIPatcher      │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │Rule-based │  │                      │
│                    │  │Patcher    │  │                      │
│                    │  └─────┬─────┘  │                      │
│                    │        │ fails  │                      │
│                    │  ┌─────▼─────┐  │                      │
│                    │  │ Gemini AI │  │                      │
│                    │  │ Fallback  │  │                      │
│                    │  └───────────┘  │                      │
│                    └────────┬────────┘                      │
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

## 🤖 AI-Powered Patching

When rule-based patching can't fix a vulnerability, PhoenixSec falls back to Gemini AI:

1. **Rule-based patch** attempted first (fast, deterministic)
2. **Validation** — syntax check + re-scan + test suite run
3. If validation fails → **Gemini AI** generates a fix
4. AI patch validated the same way
5. Fixed code committed and PR opened

Set `PHOENIXSEC_AI_KEY` or `GEMINI_API_KEY` to enable AI patching.

---

## ⚙️ Configuration

Edit `config.yaml` to customize behaviour:

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
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🙏 Credits

**Developed by [@thefayid](https://github.com/thefayid)**

---

<div align="center">

**PhoenixSec** — *Born from the ashes of every security breach, so yours never happens.*

⭐ Star this repo if PhoenixSec saved your pipeline!

</div>
