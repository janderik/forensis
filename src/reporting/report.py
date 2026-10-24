"""Forensic report generation in HTML and JSON formats."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportError(Exception):
    """Raised on report generation failures."""

    pass


class ReportGenerator:
    """Generates structured forensic reports in HTML and JSON formats.

    Reports include case metadata, evidence details, findings with
    severity, and supporting artifacts.
    """

    def __init__(
        self,
        case_name: str = "Untitled Case",
        case_id: str = "",
        examiner: str = "",
        description: str = "",
    ) -> None:
        self.case_name = case_name
        self.case_id = case_id or str(uuid.uuid4())[:8]
        self.examiner = examiner
        self.description = description
        self.created_at = datetime.now(timezone.utc)
        self._findings: List[Dict] = []
        self._evidence: List[Dict] = []
        self._hashes: List[Dict] = []

    def add_finding(self, finding: Dict) -> None:
        """Add a finding to the report.

        Finding dict should contain:
            - title (str): Short finding name
            - description (str): Detailed description
            - severity (str): critical/high/medium/low/info
            - category (str): e.g. 'Memory', 'Disk', 'Timeline', 'Network'
            - artifacts (list): List of supporting artifact dicts
            - timestamp (str): ISO timestamp (optional)
        """
        if "timestamp" not in finding:
            finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "id" not in finding:
            finding["id"] = str(uuid.uuid4())[:12]
        self._findings.append(finding)

    def add_evidence(self, evidence: Dict) -> None:
        """Add an evidence item to the report.

        Evidence dict should contain:
            - path (str): Path to evidence file
            - type (str): Type of evidence (e.g. 'disk_image', 'memory_dump')
            - size (int): Size in bytes (optional)
            - hash (dict): Hash dict with algorithm keys (optional)
            - acquisition_date (str): ISO timestamp (optional)
        """
        if "id" not in evidence:
            evidence["id"] = str(uuid.uuid4())[:12]
        self._evidence.append(evidence)

    def add_hash(self, alg: str, value: str, file_path: str = "") -> None:
        """Add a hash entry to the report."""
        self._hashes.append(
            {
                "algorithm": alg,
                "value": value,
                "file_path": file_path,
            }
        )

    @property
    def data(self) -> Dict[str, Any]:
        """Build the complete report data structure."""
        return {
            "report": {
                "title": f"Forensic Report: {self.case_name}",
                "case_id": self.case_id,
                "case_name": self.case_name,
                "examiner": self.examiner,
                "description": self.description,
                "created": self.created_at.isoformat(),
                "generator": "Forensis v1.0.0",
            },
            "summary": {
                "total_findings": len(self._findings),
                "evidence_count": len(self._evidence),
                "critical_findings": sum(
                    1 for f in self._findings if f.get("severity") == "critical"
                ),
                "high_findings": sum(
                    1 for f in self._findings if f.get("severity") == "high"
                ),
                "medium_findings": sum(
                    1 for f in self._findings if f.get("severity") == "medium"
                ),
                "low_findings": sum(
                    1 for f in self._findings if f.get("severity") == "low"
                ),
            },
            "evidence": self._evidence,
            "findings": self._findings,
            "hashes": self._hashes,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report to JSON."""
        return json.dumps(self.data, indent=indent, default=str)

    def save_json(self, output_path: str) -> str:
        """Save report to a JSON file."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info("Report saved to %s", output_path)
        return output_path

    def save_html(self, output_path: str) -> str:
        """Save report to an HTML file with styled formatting."""
        html = self._generate_html()
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("HTML report saved to %s", output_path)
        return output_path

    def _generate_html(self) -> str:
        """Generate a self-contained HTML report with embedded CSS."""
        data = self.data
        report = data["report"]
        summary = data["summary"]
        findings = data["findings"]
        evidence_list = data["evidence"]
        hashes = data["hashes"]

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        findings_rows = ""
        for f in findings:
            color = severity_colors.get(f.get("severity", "info"), "#6c757d")
            artifacts_html = ""
            for a in f.get("artifacts", []):
                artifacts_html += (
                    f"<tr><td>{a.get('name', '')}</td>"
                    f"<td>{a.get('path', '')}</td>"
                    f"<td>{a.get('value', '')}</td></tr>"
                )

            findings_rows += f"""
            <div class="finding severity-{f.get('severity', 'info')}">
                <div class="finding-header" style="border-left: 4px solid {color};">
                    <span class="severity-badge" style="background: {color};">{f.get('severity', 'info').upper()}</span>
                    <strong>{f.get('title', 'Untitled Finding')}</strong>
                    <span class="finding-category">{f.get('category', 'General')}</span>
                </div>
                <div class="finding-body">
                    <p>{f.get('description', '')}</p>
                    {f'<table class="artifacts"><tr><th>Name</th><th>Path</th><th>Value</th></tr>{artifacts_html}</table>' if artifacts_html else ''}
                </div>
            </div>"""

        evidence_rows = ""
        for e in evidence_list:
            evidence_rows += f"""
            <tr>
                <td>{e.get('type', 'Unknown')}</td>
                <td>{e.get('path', '')}</td>
                <td>{e.get('size', 'N/A')}</td>
            </tr>"""

        hash_rows = ""
        for h in hashes:
            hash_rows += f"""
            <tr>
                <td>{h.get('algorithm', '')}</td>
                <td style="font-family: monospace; font-size: 0.85em;">{h.get('value', '')}</td>
                <td>{h.get('file_path', '')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report['title']}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #212529; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 24px; }}
.header h1 {{ font-size: 1.8em; margin-bottom: 4px; }}
.header .meta {{ opacity: 0.85; font-size: 0.9em; }}
.summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
.card .number {{ font-size: 2em; font-weight: 700; }}
.card .label {{ font-size: 0.85em; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }}
.card.critical .number {{ color: #dc3545; }}
.card.high .number {{ color: #fd7e14; }}
.card.medium .number {{ color: #ffc107; }}
.card.low .number {{ color: #28a745; }}
.card.total .number {{ color: #1a1a2e; }}
.section {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }}
.section-header {{ background: #f1f3f5; padding: 14px 20px; border-bottom: 1px solid #dee2e6; font-weight: 600; font-size: 1.1em; }}
.section-body {{ padding: 20px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
th {{ background: #f8f9fa; font-weight: 600; font-size: 0.85em; text-transform: uppercase; color: #495057; }}
.finding {{ margin-bottom: 16px; border: 1px solid #e9ecef; border-radius: 6px; overflow: hidden; }}
.finding-header {{ padding: 12px 16px; background: #f8f9fa; display: flex; align-items: center; gap: 10px; }}
.severity-badge {{ padding: 2px 10px; border-radius: 12px; color: white; font-size: 0.75em; font-weight: 600; letter-spacing: 0.5px; }}
.finding-category {{ margin-left: auto; color: #6c757d; font-size: 0.85em; }}
.finding-body {{ padding: 12px 16px; }}
.artifacts {{ margin-top: 8px; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔍 {report['title']}</h1>
    <div class="meta">
      Case ID: {report['case_id']} &middot; Examiner: {report['examiner']} &middot;
      Generated: {report['created']}
    </div>
    <div class="meta">{report['description']}</div>
  </div>

  <div class="summary-cards">
    <div class="card total"><div class="number">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
    <div class="card critical"><div class="number">{summary['critical_findings']}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="number">{summary['high_findings']}</div><div class="label">High</div></div>
    <div class="card medium"><div class="number">{summary['medium_findings']}</div><div class="label">Medium</div></div>
    <div class="card low"><div class="number">{summary['low_findings']}</div><div class="label">Low</div></div>
  </div>

  <div class="section">
    <div class="section-header">Evidence Items</div>
    <div class="section-body">
      <table>
        <tr><th>Type</th><th>Path</th><th>Size</th></tr>
        {evidence_rows if evidence_rows else '<tr><td colspan="3" style="text-align:center;color:#6c757d;">No evidence items recorded.</td></tr>'}
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">Findings ({len(findings)})</div>
    <div class="section-body">
      {findings_rows if findings_rows else '<p style="color:#6c757d;">No findings recorded.</p>'}
    </div>
  </div>

  <div class="section">
    <div class="section-header">Hashes</div>
    <div class="section-body">
      <table>
        <tr><th>Algorithm</th><th>Value</th><th>File</th></tr>
        {hash_rows if hash_rows else '<tr><td colspan="3" style="text-align:center;color:#6c757d;">No hashes recorded.</td></tr>'}
      </table>
    </div>
  </div>

  <div style="text-align:center;color:#6c757d;font-size:0.85em;padding:20px;">
    Generated by Forensis v1.0.0 &middot; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
  </div>
</div>
</body>
</html>"""
