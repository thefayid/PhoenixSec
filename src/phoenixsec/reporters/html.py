"""
HtmlReporter — Generates professional, interactive HTML security scan reports.
"""

from __future__ import annotations

from pathlib import Path

from phoenixsec.core.config import ReportingConfig
from phoenixsec.core.exceptions import ReportError
from phoenixsec.interfaces.base_reporter import BaseReporter
from phoenixsec.models.report import Report
from phoenixsec.models.scan_result import ScanResult
from phoenixsec.reporters.json_reporter import JsonReporter


class HtmlReporter(BaseReporter):
    """Generates a premium static HTML dashboard for security scan results."""

    name = "HtmlReporter"
    format_id = "html"

    def __init__(self, config: ReportingConfig | None = None) -> None:
        super().__init__(config or ReportingConfig())

    def generate(self, result: ScanResult | Report, output_path: Path) -> Path:
        """Render the scan result or report into an HTML file.

        Parameters
        ----------
        result:
            The ScanResult or Report instance to render.
        output_path:
            File destination path.

        Returns
        -------
        Path
            The absolute path to the written HTML file.
        """
        resolved = self._prepare_output_path(output_path)

        # Get uniform JSON dict layout using JsonReporter
        json_reporter = JsonReporter(self._config)
        report_data = json_reporter.generate_dict(result)

        html_content = self.render_html(report_data)

        try:
            resolved.write_text(html_content, encoding="utf-8")
        except OSError as exc:
            raise ReportError(
                f"Failed to write HTML report to {resolved}: {exc}",
                context={"path": str(resolved)},
            ) from exc
        return resolved

    def render_html(self, data: dict) -> str:
        """Format the report dictionary into an interactive HTML string."""
        total = data["total_findings"]
        critical = data["critical"]
        high = data["high"]
        medium = data["medium"]
        low = data["low"]
        info = data["info"]
        target = data["scan_target"]
        scanner = data["scanner_name"]
        timestamp = data["scan_timestamp"]
        summary = data.get("summary", {})
        risk_level = summary.get("risk_level", "CLEAR")
        risk_score = summary.get("risk_score", 0)

        # Compute compliance status
        standards = ["OWASP Top 10", "PCI-DSS v4.0", "SOC 2", "ISO 27001", "HIPAA"]
        compliance_counts = {std: 0 for std in standards}
        for f in data.get("findings", []):
            f_compliance = f.get("compliance", {}) or {}
            for std in standards:
                if std in f_compliance:
                    compliance_counts[std] += 1

        compliance_html = ""
        for std in standards:
            violations = compliance_counts[std]
            if violations == 0:
                status_text = "Compliant"
                status_color = "var(--success)"
                badge = "✅"
            else:
                status_text = (
                    f"Non-Compliant ({violations} violation{'s' if violations > 1 else ''})"
                )
                status_color = "var(--critical)"
                badge = "❌"

            compliance_html += f"""
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--panel-border); border-radius: 8px; padding: 1rem; display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">{badge}</span>
                <div>
                    <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.1rem;">{std}</h4>
                    <span style="color: {status_color}; font-size: 0.85rem; font-weight: 600;">{status_text}</span>
                </div>
            </div>
            """

        # Risk level color mappings
        risk_color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "CLEAR": "#10b981",
        }
        risk_color = risk_color_map.get(risk_level, "#10b981")

        # HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhoenixSec Security Scan Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --panel-bg: #111827;
            --panel-border: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-purple: #8b5cf6;
            --accent-cyan: #06b6d4;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #6b7280;
            --success: #10b981;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--panel-border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        .logo-section h1 {{
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ec4899, #8b5cf6, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.25rem;
        }}

        .logo-section p {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .meta-section {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .meta-section div span {{
            color: var(--text-main);
            font-weight: 600;
        }}

        /* Dashboard Overview Grid */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        @media (max-width: 768px) {{
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
            header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }}
            .meta-section {{
                text-align: left;
            }}
        }}

        .card {{
            background-color: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 1.5rem;
        }}

        .stats-summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            height: 100%;
        }}

        .stat-box {{
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.03);
            padding: 1rem;
            transition: transform 0.2s, border-color 0.2s;
        }}

        .stat-box:hover {{
            transform: translateY(-2px);
        }}

        .stat-box.critical-box {{ border-left: 4px solid var(--critical); }}
        .stat-box.high-box {{ border-left: 4px solid var(--high); }}
        .stat-box.medium-box {{ border-left: 4px solid var(--medium); }}
        .stat-box.low-box {{ border-left: 4px solid var(--low); }}
        .stat-box.info-box {{ border-left: 4px solid var(--info); }}

        .stat-num {{
            font-size: 2rem;
            font-weight: 800;
            line-height: 1.2;
            margin-bottom: 0.25rem;
        }}

        .critical-box .stat-num {{ color: var(--critical); }}
        .high-box .stat-num {{ color: var(--high); }}
        .medium-box .stat-num {{ color: var(--medium); }}
        .low-box .stat-num {{ color: var(--low); }}
        .info-box .stat-num {{ color: var(--info); }}

        .stat-label {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}

        /* Risk Meter Panel */
        .risk-panel {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 9999px;
            font-weight: 800;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 1rem;
            color: #fff;
        }}

        .risk-score {{
            font-size: 3rem;
            font-weight: 900;
            margin: 0.5rem 0 0.25rem 0;
        }}

        /* Findings List */
        .findings-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--panel-border);
            padding-bottom: 0.5rem;
        }}

        .findings-title {{
            font-size: 1.25rem;
            font-weight: 700;
        }}

        .finding-item {{
            background-color: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}

        .finding-summary {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            cursor: pointer;
            user-select: none;
            transition: background-color 0.2s;
        }}

        .finding-summary:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .sev-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #fff;
        }}

        .sev-critical {{ background-color: var(--critical); }}
        .sev-high {{ background-color: var(--high); }}
        .sev-medium {{ background-color: var(--medium); }}
        .sev-low {{ background-color: var(--low); }}
        .sev-info {{ background-color: var(--info); }}

        .finding-name {{
            font-weight: 600;
            font-size: 1rem;
        }}

        .finding-loc {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        .finding-summary-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        .chevron {{
            width: 20px;
            height: 20px;
            transition: transform 0.2s;
        }}

        .finding-details {{
            display: none;
            padding: 1.5rem;
            border-top: 1px solid var(--panel-border);
            background: rgba(0, 0, 0, 0.15);
        }}

        .details-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        @media (max-width: 768px) {{
            .details-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .detail-group label {{
            display: block;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}

        .detail-group p {{
            font-size: 0.95rem;
        }}

        .code-container {{
            margin-top: 1rem;
            border-radius: 6px;
            border: 1px solid var(--panel-border);
            overflow: hidden;
        }}

        .code-header {{
            background: rgba(255, 255, 255, 0.02);
            padding: 0.5rem 1rem;
            font-size: 0.75rem;
            color: var(--text-muted);
            border-bottom: 1px solid var(--panel-border);
            display: flex;
            justify-content: space-between;
        }}

        pre {{
            margin: 0;
            padding: 1rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            background: #080c14;
        }}

        /* Taint Flow Diagram */
        .taint-flow {{
            margin-top: 1rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 6px;
            border: 1px solid var(--panel-border);
            padding: 1rem;
        }}

        .taint-step {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem;
            border-radius: 4px;
        }}

        .taint-step.source {{
            background: rgba(239, 68, 68, 0.08);
            border-left: 3px solid var(--critical);
        }}

        .taint-step.sink {{
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid var(--success);
        }}

        .taint-arrow {{
            display: flex;
            justify-content: center;
            color: var(--text-muted);
            font-size: 1.2rem;
            margin: 0.25rem 0;
        }}

        .references-list {{
            list-style: none;
            margin-top: 0.5rem;
        }}

        .references-list li {{
            margin-bottom: 0.25rem;
        }}

        .references-list a {{
            color: var(--accent-cyan);
            text-decoration: none;
            font-size: 0.85rem;
        }}

        .references-list a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-section">
                <h1>PhoenixSec</h1>
                <p>Autonomous DevSecOps Security Pipeline Report</p>
            </div>
            <div class="meta-section">
                <div>Target: <span>{target}</span></div>
                <div>Scanner: <span>{scanner}</span></div>
                <div>Timestamp: <span>{timestamp}</span></div>
            </div>
        </header>

        <section class="dashboard-grid">
            <div class="card">
                <div class="stats-summary">
                    <div class="stat-box critical-box">
                        <span class="stat-num">{critical}</span>
                        <span class="stat-label">Critical</span>
                    </div>
                    <div class="stat-box high-box">
                        <span class="stat-num">{high}</span>
                        <span class="stat-label">High</span>
                    </div>
                    <div class="stat-box medium-box">
                        <span class="stat-num">{medium}</span>
                        <span class="stat-label">Medium</span>
                    </div>
                    <div class="stat-box low-box">
                        <span class="stat-num">{low}</span>
                        <span class="stat-label">Low</span>
                    </div>
                    <div class="stat-box info-box">
                        <span class="stat-num">{info}</span>
                        <span class="stat-label">Info</span>
                    </div>
                </div>
            </div>
            <div class="card risk-panel">
                <span class="stat-label">Risk Profile</span>
                <span class="risk-score" style="color: {risk_color}">{risk_score}</span>
                <span class="risk-badge" style="background-color: {risk_color}">{risk_level}</span>
            </div>
        </section>

        <section class="card" style="margin-bottom: 2rem;">
            <h3 style="margin-bottom: 1rem; font-size: 1.1rem; font-weight: 700; color: var(--text-main); text-transform: uppercase; letter-spacing: 0.05em;">Compliance Standings</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                {compliance_html}
            </div>
        </section>

        <section class="findings-section">
            <div class="findings-header">
                <span class="findings-title">Scan Findings ({total})</span>
            </div>

            <div class="findings-list">"""

        # Generate findings HTML list dynamically
        findings = data.get("findings", [])
        if not findings:
            html_template += """
                <div class="card" style="text-align: center; padding: 3rem;">
                    <span style="font-size: 3rem; display: block; margin-bottom: 1rem;">🎉</span>
                    <h3>No vulnerabilities detected or matching the criteria.</h3>
                </div>"""
        else:
            for idx, f in enumerate(findings):
                f_id = f.get("id", f"finding-{idx}")
                sev = f.get("severity", "INFO").upper()
                cwe = f.get("cwe_id") or "N/A"
                conf = f.get("confidence", 0.50)
                conf_pct = int(conf * 100) if isinstance(conf, (int, float)) else 50
                rule_id = f.get("rule_id", "N/A")
                title = f.get("title", f.get("vulnerability", "Unknown Issue"))
                file_path = f.get("file_path", "unknown")
                line_no = f.get("line_number")
                location = f"{Path(file_path).name}:{line_no}" if line_no else Path(file_path).name
                snippet = f.get("code_snippet")
                remediation = f.get("remediation", f.get("recommendation", "N/A"))
                references = f.get("references", [])

                source = f.get("source")
                sink = f.get("sink")

                cwe_str = (
                    f"CWE-{cwe}"
                    if isinstance(cwe, int) or (isinstance(cwe, str) and not cwe.startswith("CWE-"))
                    else cwe
                )

                compliance_badges = ""
                comp_map = f.get("compliance", {}) or {}
                if comp_map:
                    badge_items = []
                    for std, req in comp_map.items():
                        badge_items.append(
                            f'<span style="background: rgba(139, 92, 246, 0.1); border: 1px solid var(--accent-purple); color: #c084fc; font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; margin-right: 0.5rem; margin-top: 0.25rem; display: inline-block;">{std}: {req}</span>'
                        )
                    compliance_badges = "".join(badge_items)

                snippet_html = ""
                if snippet:
                    snippet_html = f"""
                    <div class="code-container">
                        <div class="code-header">
                            <span>{Path(file_path).name}</span>
                            <span>Line {line_no}</span>
                        </div>
                        <pre><code>{snippet}</code></pre>
                    </div>"""

                taint_html = ""
                if source or sink:
                    taint_html = f"""
                    <div class="detail-group" style="grid-column: span 2;">
                        <label>Taint Flow Diagram</label>
                        <div class="taint-flow">
                            <div class="taint-step source">
                                <strong>[Source]</strong> {source or "User input variable"}
                            </div>
                            <div class="taint-arrow">│<br>▼</div>
                            <div class="taint-step sink">
                                <strong>[Sink]</strong> {sink or "Execution point"}
                            </div>
                        </div>
                    </div>"""

                refs_html = ""
                if references:
                    refs_html = """
                    <div class="detail-group" style="grid-column: span 2;">
                        <label>References</label>
                        <ul class="references-list">"""
                    for r in references:
                        refs_html += f'<li><a href="{r}" target="_blank">{r}</a></li>'
                    refs_html += "</ul></div>"

                html_template += f"""
                <div class="finding-item">
                    <div class="finding-summary" onclick="toggleDetails('{f_id}')">
                        <div class="finding-title-group">
                            <span class="sev-badge sev-{sev.lower()}">{sev}</span>
                            <span class="finding-name">{title}</span>
                            <span class="finding-loc">{location}</span>
                        </div>
                        <div class="finding-summary-right">
                            <span>CWE: {cwe_str}</span>
                            <span>Confidence: {conf_pct}%</span>
                            <svg class="chevron" id="chevron-{f_id}" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                            </svg>
                        </div>
                    </div>
                    <div class="finding-details" id="details-{f_id}">
                        <div class="details-grid">
                            <div class="detail-group">
                                <label>Rule ID</label>
                                <p>{rule_id}</p>
                            </div>
                            <div class="detail-group">
                                <label>Full Path</label>
                                <p style="word-break: break-all;">{file_path}</p>
                            </div>
                            <div class="detail-group" style="grid-column: span 2;">
                                <label>Remediation Advice</label>
                                <p>{remediation}</p>
                            </div>
                            <div class="detail-group" style="grid-column: span 2;">
                                <label>Compliance Standards</label>
                                <div style="margin-top: 0.25rem;">
                                    {compliance_badges or '<span style="color: var(--text-muted); font-size: 0.85rem;">No compliance mappings available for this vulnerability.</span>'}
                                </div>
                            </div>
                            {taint_html}
                            {refs_html}
                        </div>
                        {snippet_html}
                    </div>
                </div>"""

        html_template += """
            </div>
        </section>
    </div>

    <script>
        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            const chevron = document.getElementById('chevron-' + id);
            if (details.style.display === 'block') {
                details.style.display = 'none';
                chevron.style.transform = 'rotate(0deg)';
            } else {
                details.style.display = 'block';
                chevron.style.transform = 'rotate(180deg)';
            }
        }
    </script>
</body>
</html>"""

        return html_template
