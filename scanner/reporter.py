"""
Vulnerability Reporter
Generates reports from categorized vulnerability findings
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List


class VulnerabilityReporter:
    """Generates text and JSON reports from vulnerability findings"""
    
    def __init__(self, target_url: str, output_dir: str = "scan-results"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_text_report(self, findings: Dict[str, List[Dict]]) -> Path:
        """Generate a formatted text report"""
        report_file = self.output_dir / f"vulnerability_report_{self.timestamp}.txt"
        
        with open(report_file, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY VULNERABILITY REPORT\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            total_findings = 0
            severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            
            # Write findings by category
            for category, vulns in findings.items():
                if vulns:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"CATEGORY: {category}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    for i, finding in enumerate(vulns, 1):
                        total_findings += 1
                        severity = finding.get("severity", "UNKNOWN")
                        if severity in severity_summary:
                            severity_summary[severity] += 1
                        
                        f.write(f"\n[{i}] {finding.get('vulnerability_type', 'Unknown')}\n")
                        f.write(f"    Tool: {finding.get('tool', 'Unknown')}\n")
                        f.write(f"    Name: {finding.get('name', 'N/A')}\n")
                        f.write(f"    Severity: {severity}\n")
                        f.write(f"    URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"    Description: {finding.get('description', 'N/A')}\n")
                        if finding.get('evidence'):
                            f.write(f"    Evidence: {finding.get('evidence', 'N/A')}\n")
                        f.write("\n")
            
            # Summary
            f.write(f"\n{'=' * 80}\n")
            f.write("SUMMARY\n")
            f.write(f"{'=' * 80}\n")
            f.write(f"Total Findings: {total_findings}\n")
            f.write(f"Critical: {severity_summary['CRITICAL']}\n")
            f.write(f"High: {severity_summary['HIGH']}\n")
            f.write(f"Medium: {severity_summary['MEDIUM']}\n")
            f.write(f"Low: {severity_summary['LOW']}\n")
            f.write(f"Info: {severity_summary['INFO']}\n")
        
        return report_file
    
    def generate_summary(self, findings: Dict[str, List[Dict]]) -> str:
        """Generate a quick summary string"""
        total = sum(len(vulns) for vulns in findings.values())
        
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vulns in findings.values():
            for vuln in vulns:
                severity = vuln.get("severity", "UNKNOWN")
                if severity in severity_count:
                    severity_count[severity] += 1
        
        return f"Total: {total} | Critical: {severity_count['CRITICAL']} | High: {severity_count['HIGH']} | Medium: {severity_count['MEDIUM']}"
