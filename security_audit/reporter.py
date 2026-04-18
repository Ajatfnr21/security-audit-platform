"""
Report generation in multiple formats.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from dataclasses import asdict

from .scanner import ScanResult, Severity


class ReportGenerator:
    """Generate security reports in various formats."""
    
    def __init__(self, results: List[ScanResult]):
        self.results = results
    
    def to_json(self) -> str:
        """Generate JSON report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": self._get_summary(),
            "scans": []
        }
        
        for result in self.results:
            scan_data = {
                "target": {
                    "url": result.target.get_full_url() if result.target.url else None,
                    "domain": result.target.domain,
                    "port": result.target.port
                },
                "scan_type": result.scan_type.value,
                "timestamp": result.timestamp.isoformat(),
                "duration_ms": result.duration_ms,
                "passed": result.passed,
                "error": result.error,
                "findings": result.findings,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "description": v.description,
                        "severity": v.severity.value,
                        "cve_id": v.cve_id,
                        "cvss_score": v.cvss_score,
                        "remediation": v.remediation
                    }
                    for v in result.vulnerabilities
                ]
            }
            report["scans"].append(scan_data)
        
        return json.dumps(report, indent=2)
    
    def to_html(self) -> str:
        """Generate HTML report."""
        summary = self._get_summary()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #1a1a2e; color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ margin: 0; color: #666; font-size: 14px; }}
        .summary-card .value {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .scan-section {{ background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .scan-header {{ background: #f8f9fa; padding: 15px 20px; border-bottom: 1px solid #dee2e6; }}
        .vuln-list {{ padding: 20px; }}
        .vulnerability {{ border-left: 4px solid #dee2e6; padding: 15px; margin-bottom: 15px; background: #f8f9fa; }}
        .vulnerability.critical {{ border-left-color: #dc3545; }}
        .vulnerability.high {{ border-left-color: #fd7e14; }}
        .vulnerability.medium {{ border-left-color: #ffc107; }}
        .vulnerability.low {{ border-left-color: #28a745; }}
        .vuln-title {{ font-weight: bold; margin-bottom: 5px; }}
        .vuln-meta {{ font-size: 12px; color: #666; margin-top: 10px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Audit Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="value critical">{summary['critical']}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="value high">{summary['high']}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="value medium">{summary['medium']}</div>
        </div>
        <div class="summary-card">
            <h3>Low</h3>
            <div class="value low">{summary['low']}</div>
        </div>
    </div>
"""
        
        for result in self.results:
            status = "✓" if result.passed else "✗"
            html += f"""
    <div class="scan-section">
        <div class="scan-header">
            <strong>{status} {result.scan_type.value.upper()}</strong> - {result.target.get_full_url()}
            <span style="float: right; color: #666;">{result.duration_ms:.0f}ms</span>
        </div>
        <div class="vuln-list">
"""
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    html += f"""
            <div class="vulnerability {vuln.severity.value}">
                <span class="badge badge-{vuln.severity.value}">{vuln.severity.value.upper()}</span>
                <div class="vuln-title">{vuln.id}: {vuln.title}</div>
                <div>{vuln.description}</div>
                <div class="vuln-meta">
                    {f"CVE: {vuln.cve_id}<br>" if vuln.cve_id else ""}
                    {f"CVSS: {vuln.cvss_score}<br>" if vuln.cvss_score else ""}
                    <strong>Remediation:</strong> {vuln.remediation or "N/A"}
                </div>
            </div>
"""
            else:
                html += "<p style='color: #28a745;'>✓ No vulnerabilities found</p>"
            
            html += """
        </div>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def to_markdown(self) -> str:
        """Generate Markdown report."""
        summary = self._get_summary()
        
        md = f"""# 🔒 Security Audit Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['critical']} |
| 🟠 High | {summary['high']} |
| 🟡 Medium | {summary['medium']} |
| 🟢 Low | {summary['low']} |

## Findings

"""
        for result in self.results:
            status = "✓ PASS" if result.passed else "✗ FAIL"
            md += f"""### {result.scan_type.value.upper()} - {result.target.get_full_url()}

**Status:** {status}  
**Duration:** {result.duration_ms:.0f}ms

"""
            if result.vulnerabilities:
                md += "#### Vulnerabilities\n\n"
                for vuln in result.vulnerabilities:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln.severity.value, "⚪")
                    md += f"""{emoji} **{vuln.id}** - {vuln.title}
- **Severity:** {vuln.severity.value.upper()}
- **Description:** {vuln.description}
- **Remediation:** {vuln.remediation or "N/A"}

"""
            else:
                md += "✓ No vulnerabilities found\n\n"
        
        return md
    
    def save(self, output_dir: str, formats: List[str] = None):
        """Save reports to files."""
        formats = formats or ["json", "html"]
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_files = []
        
        if "json" in formats:
            json_path = output_path / f"security_report_{timestamp}.json"
            json_path.write_text(self.to_json())
            saved_files.append(str(json_path))
        
        if "html" in formats:
            html_path = output_path / f"security_report_{timestamp}.html"
            html_path.write_text(self.to_html())
            saved_files.append(str(html_path))
        
        if "md" in formats:
            md_path = output_path / f"security_report_{timestamp}.md"
            md_path.write_text(self.to_markdown())
            saved_files.append(str(md_path))
        
        return saved_files
    
    def _get_summary(self) -> Dict[str, int]:
        """Get vulnerability summary counts."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in self.results:
            for vuln in result.vulnerabilities:
                counts[vuln.severity.value] += 1
        return counts
