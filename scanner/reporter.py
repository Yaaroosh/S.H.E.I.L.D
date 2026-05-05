"""
Vulnerability Reporter
Generates reports from categorized vulnerability findings
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlsplit, urlunsplit


class VulnerabilityReporter:
    """Generates text and JSON reports from vulnerability findings"""
    
    def __init__(self, target_url: str, output_dir: str = "scan-results"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _normalize_url(self, url: str) -> str:
        if not url:
            return "Unknown"

        try:
            parsed = urlsplit(url)
            path = parsed.path or "/"
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")
            return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        except Exception:
            return url.rstrip("/") or url

    def _format_request_detail(self, finding: Dict) -> str:
        method = str(finding.get("method", "")).strip().upper()
        url = str(finding.get("url", "")).strip()
        param = str(finding.get("param", "")).strip()
        attack = str(finding.get("attack", "")).strip()

        parts = []
        if method:
            parts.append(method)
        if url:
            parts.append(url)

        detail = " ".join(parts) if parts else url or "Unknown"
        extras = []
        if param:
            extras.append(f"param={param}")
        if attack:
            extras.append(f"attack={attack}")
        if extras:
            detail = f"{detail} ({', '.join(extras)})"

        return detail

    def _aggregate_findings(self, vulns: List[Dict]) -> List[Dict]:
        aggregated = {}

        for finding in vulns:
            key = (
                finding.get("tool", "Unknown"),
                finding.get("name", "Unknown"),
                finding.get("severity", "UNKNOWN"),
                finding.get("vulnerability_type", "Unknown"),
                finding.get("description", ""),
            )

            if key not in aggregated:
                aggregated[key] = finding.copy()
                aggregated[key]["url_list"] = []
                aggregated[key]["request_details"] = []
                aggregated[key]["evidence_list"] = []

            normalized_url = self._normalize_url(str(finding.get("url", "")))
            if normalized_url not in aggregated[key]["url_list"]:
                aggregated[key]["url_list"].append(normalized_url)

            request_detail = self._format_request_detail(finding)
            if request_detail not in aggregated[key]["request_details"]:
                aggregated[key]["request_details"].append(request_detail)

            evidence = str(finding.get("evidence", "")).strip()
            if evidence and evidence not in aggregated[key]["evidence_list"]:
                aggregated[key]["evidence_list"].append(evidence)

        return list(aggregated.values())
    
    def generate_text_report(self, findings: Dict[str, List[Dict]]) -> Path:
        """Generate a formatted text report with aggregated endpoints"""
        report_file = self.output_dir / f"vulnerability_report_{self.timestamp}.txt"
        
        with open(report_file, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY VULNERABILITY REPORT\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            total_findings = 0
            severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            # Write findings by category
            for category, vulns in findings.items():
                if vulns:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"CATEGORY: {category}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    aggregated = self._aggregate_findings(vulns)
                    ffuf_findings = [v for v in aggregated if v.get("tool") == "ffuf"]
                    other_findings = [v for v in aggregated if v.get("tool") != "ffuf"]

                    # Output ffuf findings as clean table (no per-item headings)
                    if ffuf_findings:
                        f.write("Discovered Paths:\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{'Path':<50} | {'Severity':<10} | Status\n")
                        f.write("-" * 80 + "\n")
                        for finding in ffuf_findings:
                            total_findings += 1
                            severity = finding.get("severity", "UNKNOWN")
                            if severity in severity_summary:
                                severity_summary[severity] += 1
                            url = finding.get("url", "").replace(self.target_url, "").lstrip("/") or "/"
                            description = finding.get("description", "")
                            status_code = ""
                            if "status" in description:
                                status_code = description.split("status ")[-1].split(",")[0]
                            f.write(f"{url:<50} | {severity:<10} | {status_code}\n")
                        f.write("\n")

                    # Output other findings in detail format
                    for i, finding in enumerate(other_findings, 1):
                        total_findings += 1
                        severity = finding.get("severity", "UNKNOWN")
                        if severity in severity_summary:
                            severity_summary[severity] += 1
                        
                        f.write(f"\n[{i}] {finding.get('vulnerability_type', 'Unknown')}\n")
                        f.write(f"    Tool: {finding.get('tool', 'Unknown')}\n")
                        f.write(f"    Name: {finding.get('name', 'N/A')}\n")
                        f.write(f"    Severity: {severity}\n")
                        if finding.get('url_list'):
                            f.write(f"    Affected URLs ({len(finding['url_list'])}): {', '.join(finding['url_list'][:5])}")
                            if len(finding['url_list']) > 5:
                                f.write(f" ... and {len(finding['url_list']) - 5} more")
                            f.write("\n")
                        else:
                            f.write(f"    URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"    Description: {finding.get('description', 'N/A')}\n")
                        if finding.get('request_details'):
                            f.write(f"    Request details ({len(finding['request_details'])} instances): {', '.join(finding['request_details'][:5])}")
                            if len(finding['request_details']) > 5:
                                f.write(f" ... and {len(finding['request_details']) - 5} more")
                            f.write("\n")
                        elif finding.get('evidence_list'):
                            f.write(f"    Evidence ({len(finding['evidence_list'])} instances): {', '.join(finding['evidence_list'][:5])}")
                            if len(finding['evidence_list']) > 5:
                                f.write(f" ... and {len(finding['evidence_list']) - 5} more")
                            f.write("\n")
                        f.write("\n")
            
            # Summary
            f.write(f"\n{'=' * 80}\n")
            f.write("SUMMARY\n")
            f.write(f"{'=' * 80}\n")
            f.write(f"Total Unique Findings: {total_findings}\n")
            f.write(f"Critical: {severity_summary['CRITICAL']}\n")
            f.write(f"High: {severity_summary['HIGH']}\n")
            f.write(f"Medium: {severity_summary['MEDIUM']}\n")
            f.write(f"Low: {severity_summary['LOW']}\n")
        
        return report_file
    
    def generate_summary(self, findings: Dict[str, List[Dict]]) -> str:
        """Generate a quick summary string"""
        total = sum(len(self._aggregate_findings(vulns)) for vulns in findings.values())
        
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vulns in findings.values():
            for vuln in self._aggregate_findings(vulns):
                severity = vuln.get("severity", "UNKNOWN")
                if severity in severity_count:
                    severity_count[severity] += 1
        
        return f"Total: {total} | Critical: {severity_count['CRITICAL']} | High: {severity_count['HIGH']} | Medium: {severity_count['MEDIUM']}"
