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
                "SQL Injection": ["zap", "codeql"],
                "NoSQL Injection": ["zap", "codeql"],
                "Command Injection": ["zap", "codeql"],
                "LDAP Injection": ["zap", "codeql"],
                "XML External Entity (XXE)": ["zap", "codeql"],
            },
            "Authentication & Session": {
                "Broken Authentication": ["zap", "codeql"],
                "Session Fixation": ["zap", "codeql"],
            },
            "Access Control": {
                "Broken Access Control": ["zap", "codeql"],
                "Path Traversal": ["zap", "codeql"],
                "Insecure Direct Object References (IDOR)": ["zap", "codeql"],
            },
            "Sensitive Data": {
                "Exposed Credentials": ["zap", "codeql"],
                "Sensitive Data in URLs/Headers": ["zap", "codeql"],
                "Information Disclosure": ["zap", "codeql"],
                "Unencrypted Data Transmission": ["zap", "codeql"],
            },
            "Cross-Site Attacks": {
                "Cross-Site Scripting (XSS)": ["zap", "codeql"],
                "Cross-Site Request Forgery (CSRF)": ["zap", "codeql"],
            },
            "Security Misconfiguration": {
                "Security Headers Missing": ["zap", "codeql"],
                "Outdated Libraries": ["zap", "codeql"],
                "Known Vulnerabilities in Dependencies": ["zap", "codeql"],
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
    
    def parse_codeql(self, codeql_data: Dict):
        """Parse CodeQL SARIF results and categorize"""
        if not codeql_data or "runs" not in codeql_data:
            return

        for run in codeql_data.get("runs", []):
            rules = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules[rule.get("id")] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "Unknown")
                rule = rules.get(rule_id, {})

                level = (result.get("level") or "warning").lower()
                properties = rule.get("properties", {})
                security_severity = str(properties.get("security-severity", "")).strip()

                if level == "error":
                    severity = "CRITICAL"
                elif security_severity:
                    try:
                        sec_val = float(security_severity)
                        if sec_val >= 9.0:
                            severity = "CRITICAL"
                        elif sec_val >= 7.0:
                            severity = "HIGH"
                        elif sec_val >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    except ValueError:
                        severity = "HIGH" if level == "warning" else "MEDIUM"
                else:
                    severity = "HIGH" if level == "warning" else "MEDIUM"

                message = result.get("message", {}).get("text", "")
                artifact_uri = ""
                locations = result.get("locations", [])
                if locations:
                    artifact_uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")

                finding = {
                    "tool": "CodeQL",
                    "name": rule.get("name", rule_id),
                    "description": message,
                    "severity": severity,
                    "url": artifact_uri,
                    "evidence": rule_id,
                }
                self._categorize_finding(finding, "codeql")
    
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
            inferred = self._infer_vulnerability_type(finding)
            if inferred:
                category, vulnerability_type = inferred
                self.findings[category].append({**finding, "vulnerability_type": vulnerability_type})
            else:
                # Fallback category
                fallback_type = finding.get("name", "Uncategorized Finding")
                self.findings["Security Misconfiguration"].append({**finding, "vulnerability_type": fallback_type})
    
    def _match_vulnerability(self, finding_name: str, vuln_type: str) -> bool:
        """Check if finding matches vulnerability type"""
        finding_lower = finding_name.lower()
        vuln_lower = vuln_type.lower()
        return vuln_lower in finding_lower or finding_lower in vuln_lower

    def _infer_vulnerability_type(self, finding: Dict):
        """Infer category/type for tool-native finding names when direct matching fails."""
        name = finding.get("name", "").lower()

        if "cloud metadata" in name or "header not set" in name or "cross-domain" in name:
            return ("Security Misconfiguration", "Security Headers Missing")
        if "timestamp disclosure" in name or "information disclosure" in name:
            return ("Sensitive Data", "Information Disclosure")
        if "xss" in name or "cross-site scripting" in name:
            return ("Cross-Site Attacks", "Cross-Site Scripting (XSS)")
        if "csrf" in name or "cross-site request forgery" in name:
            return ("Cross-Site Attacks", "Cross-Site Request Forgery (CSRF)")

        return None
    
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
