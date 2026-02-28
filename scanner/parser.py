"""
Vulnerability Parser
Parses ZAP results, categorizes findings by vulnerability type
"""

from typing import Dict, List


class VulnerabilityParser:
    """Parses and categorizes vulnerability findings"""
    
    def __init__(self):
        """Initialize with OWASP vulnerability categories"""
        self.categories = {
            "Injection Attacks": {
                "SQL Injection": ["zap", "semgrep"],
                "NoSQL Injection": ["zap", "semgrep"],
                "Command Injection": ["zap", "semgrep"],
                "LDAP Injection": ["zap", "semgrep"],
                "XML External Entity (XXE)": ["zap", "semgrep"],
            },
            "Authentication & Session": {
                "Broken Authentication": ["zap", "semgrep"],
                "Session Fixation": ["zap", "semgrep"],
            },
            "Access Control": {
                "Broken Access Control": ["zap", "semgrep"],
                "Path Traversal": ["zap", "semgrep"],
                "Insecure Direct Object References (IDOR)": ["zap", "semgrep"],
            },
            "Sensitive Data": {
                "Exposed Credentials": ["zap", "semgrep"],
                "Sensitive Data in URLs/Headers": ["zap", "semgrep"],
                "Information Disclosure": ["zap", "semgrep"],
                "Unencrypted Data Transmission": ["zap", "semgrep"],
            },
            "Cross-Site Attacks": {
                "Cross-Site Scripting (XSS)": ["zap", "semgrep"],
                "Cross-Site Request Forgery (CSRF)": ["zap", "semgrep"],
            },
            "Security Misconfiguration": {
                "Security Headers Missing": ["zap", "semgrep"],
                "Outdated Libraries": ["zap", "semgrep"],
                "Known Vulnerabilities in Dependencies": ["zap", "semgrep"],
            },
        }
        # Initialize findings structure
        self.findings: Dict[str, List[Dict]] = {}
        for category in self.categories.keys():
            self.findings[category] = []

    def parse_zap(self, zap_data: Dict):
        """Parse ZAP JSON results and categorize"""
        if not zap_data or "site" not in zap_data:
            return
        
        for site in zap_data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskcode", "3")
                severity_map = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}
                
                finding = {
                    "tool": "ZAP",
                    "name": alert.get("name", "Unknown"),
                    "description": alert.get("desc", ""),
                    "severity": severity_map.get(str(risk), "UNKNOWN"),
                    "url": alert.get("url", ""),
                    "evidence": alert.get("evidence", ""),
                }
                
                self._categorize_finding(finding, "zap")
    
    def parse_semgrep(self, semgrep_data: Dict):
        """Parse Semgrep JSON results and categorize"""
        if not semgrep_data or "results" not in semgrep_data:
            return
        severity_map = {
            "ERROR": "CRITICAL",
            "WARNING": "HIGH",
            "INFO": "MEDIUM",
            "LOW": "LOW",
        }
        for result in semgrep_data.get("results", []):
            finding = {
                "tool": "Semgrep",
                "name": result.get("check_id", "Unknown"),
                "description": result.get("extra", {}).get("message", ""),
                "severity": severity_map.get(result.get("extra", {}).get("severity", "INFO").upper(), "MEDIUM"),
                "url": result.get("path", ""),
                "evidence": result.get("extra", {}).get("lines", ""),
            }
            self._categorize_finding(finding, "semgrep")
    
    def _categorize_finding(self, finding: Dict, tool: str):
        """Categorize a single finding into appropriate category"""
        categorized = False
        
        for category, vulns in self.categories.items():
            for vuln_name, tools in vulns.items():
                if tool in tools and self._match_vulnerability(finding["name"], vuln_name):
                    self.findings[category].append({**finding, "vulnerability_type": vuln_name})
                    categorized = True
                    break
            if categorized:
                break
        
        if not categorized:
            # Fallback category
            self.findings["Security Misconfiguration"].append({**finding, "vulnerability_type": "Other"})
    
    def _match_vulnerability(self, finding_name: str, vuln_type: str) -> bool:
        """Check if finding matches vulnerability type"""
        finding_lower = finding_name.lower()
        vuln_lower = vuln_type.lower()
        return vuln_lower in finding_lower or finding_lower in vuln_lower
    
    def get_findings(self) -> Dict[str, List[Dict]]:
        """Return all categorized findings"""
        return self.findings
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        total = sum(len(vulns) for vulns in self.findings.values())
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vulns in self.findings.values():
            for vuln in vulns:
                severity = vuln.get("severity", "UNKNOWN")
                if severity in severity_count:
                    severity_count[severity] += 1
        
        return {
            "total_findings": total,
            "by_severity": severity_count,
            "by_category": {cat: len(vulns) for cat, vulns in self.findings.items() if vulns},
        }
