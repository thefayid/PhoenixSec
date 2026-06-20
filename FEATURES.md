# 🛡️ PhoenixSec — Feature Documentation

PhoenixSec is an autonomous, production-grade DevSecOps security pipeline designed to scan, analyze, prove, and patch vulnerabilities in your code. Below is a detailed catalog of the features implemented in this project.

---

## 🔍 Core Security Scanning
PhoenixSec scans codebase files for critical vulnerabilities, supporting multiple detection methodologies (regex matching, custom AST visitors, and Semgrep integrations).
* **Vulnerability Coverage**:
  * **SQL Injection (CWE-89)**: Detects dynamic query construction using string formatters or concatenations. Supports Python and Java query executors.
  * **Command Injection (CWE-78)**: Finds raw commands passed to shell executors (e.g. `subprocess.run`, `os.system`) without validation.
  * **Cross-Site Scripting / XSS (CWE-79)**: Flags unescaped variable render outputs in templates and HTML targets.
  * **Hardcoded Secrets (CWE-798)**: Identifies cleartext cloud keys (AWS keys, GitHub tokens, OpenAI keys, etc.).
  * **Path Traversal (CWE-22)**: Flags concatenations or direct inputs mapped into file path resolvers.
  * **SSRF (CWE-918)**: Identifies user-controlled inputs flowing into HTTP fetch requests.
  * **Insecure Deserialization (CWE-502)**: Flags unsafe parsing operations (e.g. `pickle.loads`, `yaml.load`).
* **Infrastructure as Code (IaC) Scans**:
  * **Dockerfiles**: Flags root container executions, unpinned base tags, and secrets in ENV directives.
  * **Terraform**: Detects wide-open security groups (e.g., port 22 open to `0.0.0.0/0`) and public bucket ACL misconfigurations.

---

## 🤖 Agentic Proof-of-Exploit (Red Teamer)
To eliminate false positives, the **Agentic Red Teamer (ART)** attempts to verify scan findings in real-time.
* **Autonomous Hacking**: Spawns an agent that writes exploit payloads targeting the identified source code.
* **Safe Sandbox Testing**: Executes payloads locally in a sandboxed test suite environment.
* **Taint verification**: Verifications using requests or sockets are allowed but restricted strictly to localhost/loopback (`127.0.0.1`, `localhost`, `::1`) to prevent external command execution or unauthorized data exfiltration.

---

## 🔐 Ephemeral Secret Auto-Rotation
Provides runtime protection against committed credentials:
* **Active Verification**: Verifies if the credential is alive by pinging the cloud provider's API.
* **Automatic Revocation**: Issues revocation requests to neutralize the leaked token.
* **Secure Replacement**: Generates a new secure token, rotates it, and automatically updates the local `.env` configuration.

---

## ⚡ As-You-Type Vibe-Guard (LSP Server)
A high-performance Language Server Protocol (LSP) server designed for integration into standard IDEs (VS Code, Cursor, Neovim, JetBrains).
* **Real-time Diagnostics**: Analyzes keystrokes in real-time to alert developers on insecure code patterns immediately.
* **IDE Code Actions**: Provides automated quick-fix integrations to remediate code issues directly inside the editor.

---

## 🔄 Self-Healing Patch Loop
Ensures that auto-generated patches don't break developer builds:
* **Validation Compiler**: Automatically runs syntax compilation checks (`py_compile`) and scans the proposed patch.
* **Healing Loop**: If a patch fails validation or breaks the test suite, PhoenixSec runs up to a 3-attempt self-healing cycle, providing LLMs with compile/test diagnostics to recursively correct the code.

---

## 🏠 Local & Offline LLM Support (Ollama)
Enterprise configurations can protect proprietary source code by running the patch generation locally.
* **Ollama Integration**: Seamless support for local model engines (e.g., `qwen2.5-coder`, `deepseek-coder`).
* **API Fallback**: Gracefully falls back from Gemini to local Ollama providers if API keys are missing.

---

## 🔁 GitHub Actions & PR Automation
* **Inline PR Comments**: Automatically comments on the exact vulnerable line inside GitHub Pull Requests.
* **Automatic Fix Branches**: Creates a fix branch, commits the verified patch, and opens a Pull Request automatically.
* **Flexible Gate Control**: Configurable severity threshold (e.g., `--fail-on HIGH`) to block builds.
