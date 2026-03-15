"""
Vulnerability Engine
Orchestrates ZAP and CodeQL security scans
"""

import subprocess
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import requests


logger = logging.getLogger(__name__)

JS_SECURITY_SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"


class VulnerabilityEngine:
    """Runs ZAP and CodeQL scans against a target"""
    
    def __init__(
        self,
        target_url: str,
        output_dir: str = "scan-results",
        timeout: float = 10.0,
        verify_tls: bool = True,
        zap_auth_cookie: str = None,
        zap_auth_header: str = None,
    ):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # settings used by scans
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.zap_auth_cookie = zap_auth_cookie
        self.zap_auth_header = zap_auth_header

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
        logger.info("Starting ZAP scan for %s", self.target_url)

        temp_report_path = None
        
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
                    logger.debug("ZAP executable resolved to %s", zap_cmd)
                    break
            
            if not zap_cmd:
                print("[!] ZAP not found. Checked:")
                for p in zap_paths:
                    print(f"    {p}")
                    logger.debug("ZAP path checked: %s", p)
                return {}

            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_report:
                temp_report_path = Path(temp_report.name)
            
            cmd = [zap_cmd, "-cmd", "-quickurl", self.target_url, "-quickout", str(temp_report_path)]

            zap_config_args = []
            if self.zap_auth_cookie:
                cookie_value = self.zap_auth_cookie.replace(" ", "")
                zap_config_args.extend([
                    "-config", "replacer.full_list(0).description=auth-cookie",
                    "-config", "replacer.full_list(0).enabled=true",
                    "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
                    "-config", "replacer.full_list(0).matchstr=Cookie",
                    "-config", "replacer.full_list(0).regex=false",
                    "-config", f"replacer.full_list(0).replacement={cookie_value}",
                ])
                logger.info("ZAP auth cookie configured")

            if self.zap_auth_header:
                parts = self.zap_auth_header.split(":", 1)
                if len(parts) == 2:
                    header_name = parts[0].strip()
                    header_value = parts[1].strip()
                    index = 1 if self.zap_auth_cookie else 0
                    zap_config_args.extend([
                        "-config", f"replacer.full_list({index}).description=auth-header",
                        "-config", f"replacer.full_list({index}).enabled=true",
                        "-config", f"replacer.full_list({index}).matchtype=REQ_HEADER",
                        "-config", f"replacer.full_list({index}).matchstr={header_name}",
                        "-config", f"replacer.full_list({index}).regex=false",
                        "-config", f"replacer.full_list({index}).replacement={header_value}",
                    ])
                    logger.info("ZAP auth header configured for %s", header_name)
                else:
                    logger.warning("Invalid zap_auth_header format. Expected 'Header-Name: value'")

            cmd.extend(zap_config_args)
            
            # Run ZAP from its own directory so it can find JAR
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=str(zap_dir))
            
            if result.returncode != 0:
                print(f"[!] ZAP warning: {result.stderr}")
                logger.warning("ZAP returned non-zero exit code %s: %s", result.returncode, result.stderr)
            
            if temp_report_path and temp_report_path.exists():
                with open(temp_report_path, encoding="utf-8") as f:
                    return json.load(f)
            else:
                print("[!] ZAP report not generated")
                logger.warning("ZAP report was not generated")
                return {}
                
        except subprocess.TimeoutExpired:
            print("[!] ZAP scan timed out (5 minutes)")
            logger.error("ZAP scan timed out")
            return {}
        except Exception as e:
            print(f"[!] ZAP scan failed: {e}")
            logger.exception("ZAP scan failed")
            return {}
        finally:
            if temp_report_path and temp_report_path.exists():
                try:
                    temp_report_path.unlink()
                except OSError:
                    logger.debug("Failed to remove temporary ZAP report: %s", temp_report_path)
    
    def run_codeql_scan(self, source_path: str = None) -> Dict:
        """Execute CodeQL scan and return SARIF results"""
        print(f"[*] Starting CodeQL scan...")
        logger.info("Starting CodeQL scan")

        if source_path is None:
            print("[!] CodeQL requires source code path. Provide --source-path <path>.")
            logger.warning("CodeQL source path missing; skipping CodeQL scan")
            return {"runs": []}

        source_root = Path(source_path).expanduser().resolve()
        if not source_root.exists() or not source_root.is_dir():
            print(f"[!] Invalid --source-path: {source_root}")
            logger.warning("Invalid CodeQL source path: %s", source_root)
            return {"runs": []}

        source_path = str(source_root)
        print(f"[*] Scanning source at: {source_path}")
        logger.debug("CodeQL source path: %s", source_path)
        
        temp_dir = None
        try:
            codeql_candidates = [
                Path.cwd() / "tools" / "codeql" / "codeql" / "codeql.exe",
                Path.cwd() / "tools" / "codeql" / "codeql.exe",
                Path("tools/codeql/codeql/codeql.exe").resolve(),
                Path("tools/codeql/codeql.exe").resolve(),
            ]

            codeql_cmd = None
            for candidate in codeql_candidates:
                if candidate.exists():
                    codeql_cmd = str(candidate)
                    break

            if not codeql_cmd:
                codeql_cmd = "codeql"

            temp_dir = Path(tempfile.mkdtemp(prefix="codeql_scan_"))
            db_dir = temp_dir / "db"
            sarif_output = temp_dir / "results.sarif"

            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'

            create_cmd = [
                codeql_cmd,
                "database",
                "create",
                str(db_dir),
                "--language=javascript-typescript",
                "--source-root",
                source_path,
                "--overwrite",
            ]

            print("[*] Building CodeQL database...")
            create_result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=900, env=env)
            if create_result.returncode != 0:
                logger.error("CodeQL database creation failed: %s", create_result.stderr[-500:])
                print("[!] CodeQL database creation failed")
                return {"runs": []}

            analyze_cmd = [
                codeql_cmd,
                "database",
                "analyze",
                str(db_dir),
                JS_SECURITY_SUITE,
                "--download",
                "--format=sarif-latest",
                "--output",
                str(sarif_output),
            ]

            print("[*] Running CodeQL analysis...")
            analyze_result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=900, env=env)
            if analyze_result.returncode != 0:
                logger.error("CodeQL analysis failed: %s", analyze_result.stderr[-500:])
                print("[!] CodeQL analysis failed")
                return {"runs": []}

            if sarif_output.exists():
                with open(sarif_output, "r", encoding="utf-8") as file:
                    sarif_data = json.load(file)
                findings_count = sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))
                if findings_count > 0:
                    print(f"[*] CodeQL found {findings_count} potential issues")
                    logger.info("CodeQL found %s issues", findings_count)
                else:
                    print("[*] CodeQL scan complete - no issues found")
                    logger.info("CodeQL completed with zero findings")
                return sarif_data

            print("[*] CodeQL scan complete - no SARIF output generated")
            logger.info("CodeQL completed with no SARIF output")
            return {"runs": []}
        except FileNotFoundError:
            print("[!] CodeQL CLI not found. Run scripts/before_setup.bat to install CodeQL.")
            logger.error("CodeQL executable not found")
            return {"runs": []}
        except subprocess.TimeoutExpired:
            print("[!] CodeQL scan timed out")
            logger.error("CodeQL scan timed out")
            return {"runs": []}
        except Exception as e:
            print(f"[!] CodeQL scan failed: {e}")
            logger.exception("CodeQL scan failed")
            return {"runs": []}
        finally:
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    logger.debug("Failed to cleanup CodeQL temp dir: %s", temp_dir)
    
    def run(self, run_zap: bool = True, run_codeql: bool = True, source_path: str = None) -> Dict:
        """Run ZAP and CodeQL scans and return raw results"""
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
        
        if run_codeql:
            results["codeql"] = self.run_codeql_scan(source_path)
        
        return results
