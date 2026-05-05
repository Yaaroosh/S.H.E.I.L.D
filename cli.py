
import argparse
import json
import logging
import os
from urllib.parse import urlparse
import certifi #for TLS verification
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner import VulnerabilityEngine, VulnerabilityParser, VulnerabilityReporter
from scanner.logging_config import setup_logging


logger = logging.getLogger(__name__)



# -------------------------
# Configuration
# -------------------------

def load_config(
    personal_path: str = "./config/config.json",
    
) -> dict:
    """
    Load configuration with priority:

    A personal config file (default `./config/config.json`).
    This file is included in the repository and provides sane defaults.
   
    The CLI will automatically look for either location when invoked from the
    project root.  You can also override the path via --config if needed.
    """

    if os.path.exists(personal_path):
        path = personal_path
    
    else:
        raise FileNotFoundError(
            "No config file found. Expected './config/config.json'.  Run the CLI from the project root "
            "or supply --config explicitly."
        )

    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    if not isinstance(cfg, dict):
        raise ValueError(f"{path} must contain a JSON object.")

    return cfg



# -------------------------
# URL helpers
# -------------------------

def normalize_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url) #detect all parts of url (domain, params, query...)
    if not parsed.scheme:
        url = "https://" + url
    return url


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https:// (or omit scheme to default to https)")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname (example.com)")



def run_full_security_scan(
    target_url: str,
    timeout: float,
    verify_tls: bool,
    run_zap: bool = True,
    run_codeql: bool = True,
    run_dirscan: bool = False,
    source_path: str = None,
    dirscan_wordlist: str = None,
    dirscan_recursive: bool = True,
    dirscan_depth: int = 2,
    dirscan_threads: int = 80,
) -> dict:
    """
    Run integrated security scan with categorization
    """
    try:
        logger.info(
            "Running full scan | target=%s | run_zap=%s | run_codeql=%s | run_dirscan=%s | dirscan_recursive=%s | dirscan_depth=%s",
            target_url,
            run_zap,
            run_codeql,
            run_dirscan,
            dirscan_recursive,
            dirscan_depth,
        )
        
        #create engine instance for scan
        engine = VulnerabilityEngine(
            target_url,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        
        # Run scan (engine will also perform reachability check)
        scan_data = engine.run(
            run_zap=run_zap,
            run_codeql=run_codeql,
            run_dirscan=run_dirscan,
            source_path=source_path,
            dirscan_wordlist=dirscan_wordlist,
            dirscan_recursive=dirscan_recursive,
            dirscan_depth=dirscan_depth,
            dirscan_threads=dirscan_threads,
        )
        parser = VulnerabilityParser() #create parser instance
        
        #parse results
        if run_zap:
            parser.parse_zap(scan_data.get("zap", {}))
        if run_codeql:
            parser.parse_codeql(scan_data.get("codeql", {}))
        if run_dirscan:
            parser.parse_dirscan(scan_data.get("dirscan", {}))
        
        findings = parser.get_findings()
        summary = parser.get_summary()
        # Generate report
        reporter = VulnerabilityReporter(target_url)
        report_file = reporter.generate_text_report(findings)
        print(f"\n✓ Scan completed")
        print(f"  Report: {report_file}")
        print(f"  Summary: {reporter.generate_summary(findings)}")
        logger.info("Scan complete. Report generated at %s", report_file)
        return {
            "test": "full_scan",
            "ok": True,
            "target": target_url,
            "report": str(report_file),
            "summary": summary,
            "message": f"Scan completed. Report: {report_file}"
        }
    except ImportError as e:
        logger.exception("Import error during full scan")
        return {
            "test": "full_scan",
            "ok": False,
            "error": f"Missing module: {e}. Make sure all vulnerability_*.py files are in the project root."
        }
    except Exception as e:
        logger.exception("Unhandled error during full scan")
        return {
            "test": "full_scan",
            "ok": False,
            "error": f"{type(e).__name__}: {e}"
        }


# -------------------------
# CLI
# -------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="S.H.E.I.L.D Web App Scanner")
    parser.add_argument("url", nargs="?", default="http://localhost:3000", help="Target URL (default: http://localhost:3000)")

    # Global options
    parser.add_argument("--timeout", type=float, default=None, help="Override timeout from config (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    parser.add_argument(
        "--config",
        default="./config/config.json",
        help="Path to config file (default: ./config/config.scanner.json)"
    )

    # Test flags (ADD MORE HERE)
    parser.add_argument("--full-scan", action="store_true", dest="full_scan", help="Run full security scan (ZAP, CodeQL, and dirscan)")
    parser.add_argument("--zap-only", action="store_true", dest="zap_only", help="Run only ZAP DAST scan")
    parser.add_argument("--codeql-only", action="store_true", dest="codeql_only", help="Run only CodeQL SAST scan")
    parser.add_argument("--dirscan-only", action="store_true", dest="dirscan_only", help="Run only directory brute-force scan")
    parser.add_argument("--source-path", type=str, default=None, help="Path to source code for CodeQL analysis (required for --codeql-only or --full-scan)")
    parser.add_argument("--dirscan-wordlist", type=str, default=None, help="Path to a custom wordlist for directory scan")
    parser.add_argument("--dirscan-no-recursion", action="store_true", dest="dirscan_no_recursion", help="Disable recursive directory discovery for dirscan")
    parser.add_argument("--dirscan-depth", type=int, default=2, help="Maximum recursion depth for dirscan (default: 2)")
    parser.add_argument("--dirscan-threads", type=int, default=80, help="Concurrent dirscan threads (default: 80)")

    # Convenience flags (ADD MORE HERE)
    # parser.add_argument("--all", action="store_true", help="Run all tests")

    return parser


def main() -> int:
    setup_logging("logs") #log folder
    parser = build_parser() #for args
    args = parser.parse_args()

    # Load config and resolve settings
    cfg = load_config(args.config)

    target_url = normalize_url(args.url) #parse url and add https if no scheme provided
    validate_url(target_url) #ensure url is valid and has http/https scheme

    timeout = float(args.timeout) if args.timeout is not None else float(cfg["timeout"])
    verify_tls = certifi.where() if cfg["verify_tls"] else False
    user_agent = str(cfg["user_agent"])

    # Shared HTTP session for FUTURE use
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    logger.debug("HTTP session initialized with user-agent: %s", user_agent)

    # Decide which tests to run
    if not (args.full_scan or args.zap_only or args.codeql_only or args.dirscan_only):
        print("No tests selected. Use --full-scan, --zap-only, --codeql-only, or --dirscan-only")
        logger.warning("CLI invoked without test selection")
        return 2

    # Determine which tools to run
    run_zap = args.full_scan or args.zap_only
    run_codeql = args.full_scan or args.codeql_only
    run_dirscan = args.full_scan or args.dirscan_only
    dirscan_recursive = not args.dirscan_no_recursion
    dirscan_depth = max(0, int(args.dirscan_depth))
    dirscan_threads = max(1, int(args.dirscan_threads))
    

    results = []

    # run the full security scan
    try:
        results.append(run_full_security_scan(
            target_url, 
            timeout, 
            verify_tls, 
            run_zap=run_zap, 
            run_codeql=run_codeql,
            run_dirscan=run_dirscan,
            source_path=args.source_path,
            dirscan_wordlist=args.dirscan_wordlist,
            dirscan_recursive=dirscan_recursive,
            dirscan_depth=dirscan_depth,
            dirscan_threads=dirscan_threads,
        ))
    except Exception as e:
        results.append({"test": "full_scan", "ok": False, "error": f"{type(e).__name__}: {e}"})

    # Output
    output = {"target": target_url, "results": results}
    print(json.dumps(output, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
