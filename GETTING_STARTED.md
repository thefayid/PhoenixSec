# 🚀 Getting Started with PhoenixSec

Welcome! **PhoenixSec** is a production-grade, autonomous DevSecOps pipeline designed to scan your code for vulnerabilities, automatically generate secure patches (using rule-based logic or AI), and open fix Pull Requests/Merge Requests.

This guide will walk you through what PhoenixSec is, how to set it up in under 5 minutes, and how to automate it in your local and CI/CD development environments.

---

## 📖 What is PhoenixSec?

PhoenixSec acts as an automated security engineer on your team. It fits into your workflow in three steps:

```
[ 🔍 1. Scan ]         ->  [ 🛠️ 2. Self-Healing Patch ] ->  [ 📬 3. PR/MR Auto-Fix ]
Locally or in CI/CD        Deterministic or AI-powered      GitHub, GitLab, or Bitbucket
```

Unlike traditional scanners that only dump warning logs, **PhoenixSec solves the problem** by compiling, validating, and testing fixes before presenting them as ready-to-merge Pull Requests.

---

## ⚡ 5-Minute Quickstart

### 1. Prerequisites
Ensure you have the following installed on your system:
* **Python 3.12 or newer**
* **Git**
* (Optional) **Semgrep** (highly recommended for extra vulnerability rules coverage):
  ```bash
  pip install semgrep
  ```

### 2. Installation
Since PhoenixSec is currently in active development, clone the repository and install it in editable mode inside a virtual environment:

```bash
# Clone the repository
git clone https://github.com/thefayid/PhoenixSec.git
cd PhoenixSec

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Install the package in editable mode
pip install -e .
```

Verify your installation by running:
```bash
phoenixsec version
```

---

## 🛠️ Configuration & Environment Setup

PhoenixSec automatically resolves configuration using standard API tokens.

### Setup API Tokens

| Provider | Purpose | Environment Variable |
|:---|:---|:---|
| **Gemini AI** | AI Patch Generation & Self-Healing | `PHOENIXSEC_AI_KEY` or `GEMINI_API_KEY` |
| **GitHub** | PR Automation & Inline Comments | `PHOENIXSEC_GITHUB_TOKEN` |
| **GitLab** | Merge Request Automation & Notes | `PHOENIXSEC_GITLAB_TOKEN` |
| **Bitbucket** | Pull Request Automation & Comments | `PHOENIXSEC_BITBUCKET_TOKEN` |

For local testing, export your variables in your shell profile or create a `.env` file:
```bash
# Example for GitHub + Gemini AI
export PHOENIXSEC_AI_KEY="your-gemini-api-key"
export PHOENIXSEC_GITHUB_TOKEN="your-github-personal-access-token"
export PHOENIXSEC_GITHUB_OWNER="your-username"
export PHOENIXSEC_GITHUB_REPO="your-repo-name"
```

---

## 🚀 3 Ways to Integrate & Automate

### Option A: Local Interactive Scanning & Patching (Manual)
Run scans on demand against files or directories and review proposed fixes interactively:

```bash
# Scan a folder and prompt to apply patches
phoenixsec scan ./src --patch
```

* **How it works:** When a vulnerability is found, PhoenixSec runs validation checks. If a patch passes compile checks and local unit tests, it renders a **colorized unified git diff** in your terminal and prompts:
  `Apply this patch? [y/N]`.
* If you select `y`, the patch is applied locally. If git credentials are set, it automatically checks out a branch, commits the fix, pushes to your remote origin, and opens a PR/MR.

---

### Option B: Local Git Pre-Commit Hook (Semi-Automated)
Stop vulnerabilities from ever leaving your local machine. Install a pre-commit hook that scans only your **staged files** (`git diff --cached`) during `git commit`:

```bash
# Blocks commits if HIGH or CRITICAL severity vulnerabilities are found
phoenixsec install-hook . --severity HIGH
```

If a security flaw is detected, your commit is aborted, keeping your git history clean. You can fix the issue or run `phoenixsec scan --patch` to remediate it.

### Option C: Real-Time IDE Integration (Vibe-Guard via LSP)
PhoenixSec ships with a lightning-fast Language Server Protocol (LSP) Server out of the box. This provides real-time, as-you-type security squiggly lines in **any modern IDE** (VS Code, Cursor, Neovim, Zed, JetBrains, Emacs).

```bash
# Starts the background Language Server (communicate via stdio)
phoenixsec lsp
```
*Configure your IDE's LSP client to point to this executable. PhoenixSec will now intercept hallucinations and vulnerable code milliseconds after you type them, without ever needing to save a file!*

---

### Option D: CI/CD Pipeline Integration (Fully Automated)
Trigger automatic scans on every push, block failing pipelines, and automatically open auto-fix PRs.

#### 1. GitHub Actions
Create `.github/workflows/security.yml`:
```yaml
name: 🛡️ PhoenixSec Security Scan

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main" ]

permissions:
  contents: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install PhoenixSec
        run: pip install git+https://github.com/thefayid/PhoenixSec.git
      - name: Run Scan & Auto-Fix
        env:
          PHOENIXSEC_AI_KEY: ${{ secrets.PHOENIXSEC_AI_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          phoenixsec scan . --fail-on HIGH --patch --yes
```

#### 2. GitLab CI/CD
Create `.gitlab-ci.yml`:
```yaml
stages:
  - security

phoenixsec-scan:
  stage: security
  image: python:3.12
  variables:
    PHOENIXSEC_VCS_PROVIDER: "gitlab"
  before_script:
    - pip install git+https://github.com/thefayid/PhoenixSec.git
  script:
    # Runs scan, fails on HIGH+, automatically creates Merge Requests and review notes in GitLab
    - phoenixsec scan . --fail-on HIGH --patch --yes
  only:
    - merge_requests
    - main
```

#### 3. Bitbucket Pipelines
Create `bitbucket-pipelines.yml`:
```yaml
pipelines:
  default:
    - step:
        name: PhoenixSec Security Scan
        image: python:3.12
        script:
          - pip install git+https://github.com/thefayid/PhoenixSec.git
          - export PHOENIXSEC_VCS_PROVIDER="bitbucket"
          - phoenixsec scan . --fail-on HIGH --patch --yes
```

---

## ⚙️ Advanced Customization (`config.yaml`)

Create a `config.yaml` file in the root of your project to customize settings:

```yaml
scanning:
  min_severity: LOW           # Report findings at or above this level
  max_file_size_kb: 512       # Skip very large files
  exclude_dirs:               # Directories to completely ignore
    - ".venv"
    - "node_modules"
    - "tests"
    - "samples"

patching:
  enabled: true
  dry_run: false              # If true, tests the patch validation without applying
  backup: true                # Create a .bak backup file before patching
  provider: gemini            # 'gemini' for AI or 'ollama' for 100% local scanning
  ollama_url: "http://localhost:11434"
  model: gemini-1.5-flash     # Model name (e.g. 'qwen2.5-coder' / 'deepseek-coder' for Ollama)
```

---

## 🧪 Try the Interactive Demo!

To see PhoenixSec in action without modifying your production code:

1. Look in the `samples/` directory at the vulnerable code (e.g. `samples/vulnerable_python_app.py` containing SQL Injection and command injection vulnerabilities).
2. Run an interactive patch scan:
   ```bash
   phoenixsec scan samples/vulnerable_python_app.py --patch
   ```
3. Inspect the colorized diff preview in your terminal showing the secure parameterization fix.
4. Confirm with `y` to apply the fix locally!

---

## 🛡️ Beyond Scanning: The Phoenix Revolution Features

### 1. Agentic Proof-of-Exploit (Red Teamer)
Tired of false positives? Tell PhoenixSec to *prove* a vulnerability exists by dynamically generating and executing an exploit payload in a sandbox:
```bash
phoenixsec scan samples/vulnerable_python_app.py --prove
```
*Requires `GEMINI_API_KEY`. PhoenixSec will only report the vulnerability if its autonomous agent can successfully hack it!*

### 2. Ephemeral Secret Auto-Rotation
Leaked an AWS Key or a GitHub Token? Don't just alert—fix it:
```bash
phoenixsec scan samples/vulnerable_python_app.py --rotate-secrets
```
*PhoenixSec will simulate connecting to the cloud provider, revoking the compromised key, generating a new one, and injecting it directly into your local `.env` file.*
