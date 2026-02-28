"""
Vulnerability Engine
Orchestrates ZAP and Semgrep security scans
"""

import subprocess
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import requests


class VulnerabilityEngine:
    """Runs ZAP and Semgrep scans against a target"""
    
    def __init__(self, target_url: str, output_dir: str = "scan-results", timeout: float = 10.0, verify_tls: bool = True):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # settings used by scans
        self.timeout = timeout
        self.verify_tls = verify_tls

    def check_reachability(self) -> Dict:
        """Perform a simple HTTP GET to verify the target is reachable.
        Returns a dict with an "ok" key and either status information or an error.
        """
        try:
            r = requests.get(
                self.target_url,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=True,
            )
            return {"ok": True, "status_code": r.status_code, "final_url": r.url}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def run_zap_scan(self) -> Dict:
        """Execute OWASP ZAP scan and return JSON results"""
        print(f"[*] Starting OWASP ZAP scan on {self.target_url}...")
        
        zap_report = (Path.cwd() / self.output_dir / f"zap_report_{self.timestamp}.json").resolve()
        
        try:
            # Find ZAP executable from tools directory (check relative to CWD)
            zap_paths = [
                Path.cwd() / "tools" / "zap" / "ZAP_2.15.0" / "zap.bat",
                Path.cwd() / "tools" / "zap" / "zap.bat",
                Path("tools/zap/ZAP_2.15.0/zap.bat").resolve(),
                Path("tools/zap/zap.bat").resolve(),
                Path(r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"),
                Path(r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat"),
            ]
            
            zap_cmd = None
            zap_dir = None
            for zap_path in zap_paths:
                if zap_path.exists():
                    zap_cmd = str(zap_path)
                    zap_dir = zap_path.parent
                    print(f"[*] Found ZAP at: {zap_cmd}")
                    break
            
            if not zap_cmd:
                print("[!] ZAP not found. Checked:")
                for p in zap_paths:
                    print(f"    {p}")
                return {}
            
            cmd = [zap_cmd, "-cmd", "-quickurl", self.target_url, "-quickout", str(zap_report)]
            
            # Run ZAP from its own directory so it can find JAR
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=str(zap_dir))
            
            if result.returncode != 0:
                print(f"[!] ZAP warning: {result.stderr}")
            
            if zap_report.exists():
                with open(zap_report) as f:
                    return json.load(f)
            else:
                print("[!] ZAP report not generated")
                return {}
                
        except subprocess.TimeoutExpired:
            print("[!] ZAP scan timed out (5 minutes)")
            return {}
        except Exception as e:
            print(f"[!] ZAP scan failed: {e}")
            return {}
    
    def run_semgrep_scan(self, source_path: str = None) -> Dict:
        """Execute Semgrep scan and return JSON results"""
        print(f"[*] Starting Semgrep scan...")
        
        # Determine source path
        if source_path is None:
            # Try to find Juice Shop source if target is localhost:3000
            if "localhost:3000" in self.target_url:
                juice_shop_path = Path.cwd() / "tools" / "juice-shop"
                if juice_shop_path.exists():
                    source_path = str(juice_shop_path)
                    print(f"[*] Scanning Juice Shop source at: {source_path}")
                else:
                    print("[!] Note: Semgrep requires source code. Juice Shop source not found.")
                    return {"results": []}
            else:
                print("[!] Note: Semgrep requires source code path. Use --source-path to specify.")
                return {"results": []}
        
        try:
            # Try to find semgrep executable
            # First, try the Python user scripts directory
            user_scripts_dir = Path.home() / "AppData" / "Local" / "Packages" / "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0" / "LocalCache" / "local-packages" / "Python311" / "Scripts"
            pysemgrep_path = user_scripts_dir / "pysemgrep.exe"
            
            if pysemgrep_path.exists():
                semgrep_cmd = str(pysemgrep_path)
            else:
                # Fall back to trying semgrep in PATH
                semgrep_cmd = "semgrep"
            
            cmd = [
                semgrep_cmd,
                "--config", "p/ci",  # Use CI ruleset
                "--json",
                source_path
            ]
            
            # Set UTF-8 encoding for subprocess to handle Unicode in source code
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
            
            print(f"[*] Running Semgrep analysis...")
            result = subprocess.run(cmd, capture_output=True, text=False, timeout=300, cwd=source_path, env=env)
            
            # Save stderr to a file for debugging
            if result.stderr:
                error_file = self.output_dir / f"semgrep_error_{self.timestamp}.txt"
                try:
                    with open(error_file, 'wb') as f:
                        f.write(result.stderr)
                    print(f"[*] Semgrep stderr saved to: {error_file}")
                except Exception:
                    pass
            
            # Decode output with proper encoding
            try:
                stdout = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ""
                stderr_text = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ""
            except Exception:
                stdout = ""
                stderr_text = ""
            
            # Semgrep returns 0 (no findings) or 1 (findings found) on success
            if result.returncode not in (0, 1):
                print(f"[!] Semgrep encountered an error (exit code: {result.returncode})")
                if stderr_text and len(stderr_text.strip()) < 500:
                    # Try to print a short error message
                    error_lines = stderr_text.strip().split('\n')
                    if error_lines:
                        print(f"[!] Error: {error_lines[-1][:200]}")
                return {"results": []}
            
            # Parse JSON from stdout
            if stdout:
                try:
                    data = json.loads(stdout)
                    findings_count = len(data.get("results", []))
                    if findings_count > 0:
                        print(f"[*] Semgrep found {findings_count} potential issues")
                    else:
                        print("[*] Semgrep scan complete - no issues found")
                    return data
                except json.JSONDecodeError:
                    print("[!] Semgrep output is not valid JSON")
                    return {"results": []}
            else:
                print("[*] Semgrep scan complete - no issues found")
                return {"results": []}
        except subprocess.TimeoutExpired:
            print("[!] Semgrep scan timed out (5 minutes)")
            return {"results": []}
        except Exception as e:
            print(f"[!] Semgrep scan failed: {e}")
            return {"results": []}
    
    def run(self, run_zap: bool = True, run_semgrep: bool = True, source_path: str = None) -> Dict:
        """Run ZAP and Semgrep scans and return raw results"""
        print(f"\n{'=' * 80}")
        print(f"Starting security scan of {self.target_url}")
        print(f"{'=' * 80}\n")
        
        results = {}
        
        # ensure the target responds before running heavy scans
        if run_zap:
            reach = self.check_reachability()
            if not reach.get("ok"):
                print(f"[!] Target not reachable: {reach.get('error')}")
                return {}
        
        if run_zap:
            results["zap"] = self.run_zap_scan()
        
        if run_semgrep:
            results["semgrep"] = self.run_semgrep_scan(source_path)
        
        return results
