
import argparse
import json
import os
from urllib.parse import urlparse
import certifi #for TLS verification
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner import VulnerabilityEngine, VulnerabilityParser, VulnerabilityReporter



# -------------------------
# Configuration
# -------------------------

def load_config(
    personal_path: str = "./config/config.json",
    example_path: str = "./config/config.scanner.json"
) -> dict:
    """
    Load configuration with priority:

    1. A personal config file (default `./config/config.json`).
       This is meant for user-specific overrides and is not committed to
       source control.
    2. The bundled example config (`./config/config.scanner.json`).
       This file is included in the repository and provides sane defaults.

    The CLI will automatically look for either location when invoked from the
    project root.  You can also override the path via --config if needed.
    """

    if os.path.exists(personal_path):
        path = personal_path
    elif os.path.exists(example_path):
        path = example_path
    else:
        raise FileNotFoundError(
            "No config file found. Expected either './config/config.json' or "
            "'./config/config.scanner.json'.  Run the CLI from the project root "
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
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https:// (or omit scheme to default to https)")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname (example.com)")



def run_full_security_scan(target_url: str, timeout: float, verify_tls: bool, run_zap: bool = True, run_semgrep: bool = True, source_path: str = None) -> dict:
    """
    Run integrated security scan with categorization
    """
    try:
        # Run scan (engine will also perform reachability check)
        engine = VulnerabilityEngine(target_url, timeout=timeout, verify_tls=verify_tls)
        scan_data = engine.run(run_zap=run_zap, run_semgrep=run_semgrep, source_path=source_path)
        parser = VulnerabilityParser()
        
        if run_zap:
            parser.parse_zap(scan_data.get("zap", {}))
        if run_semgrep:
            parser.parse_semgrep(scan_data.get("semgrep", {}))
        
        findings = parser.get_findings()
        summary = parser.get_summary()
        # Generate report
        reporter = VulnerabilityReporter(target_url)
        report_file = reporter.generate_text_report(findings)
        print(f"\n✓ Scan completed")
        print(f"  Report: {report_file}")
        print(f"  Summary: {reporter.generate_summary(findings)}")
        return {
            "test": "full_scan",
            "ok": True,
            "target": target_url,
            "report": str(report_file),
            "summary": summary,
            "message": f"Scan completed. Report: {report_file}"
        }
    except ImportError as e:
        return {
            "test": "full_scan",
            "ok": False,
            "error": f"Missing module: {e}. Make sure all vulnerability_*.py files are in the project root."
        }
    except Exception as e:
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
    parser.add_argument("url", nargs="?", default="http://localhost:3000", help="Target URL (default: http://localhost:3000 - OWASP Juice Shop)")

    # Global options
    parser.add_argument("--timeout", type=float, default=None, help="Override timeout from config (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    parser.add_argument(
        "--config",
        default="./config/config.scanner.json",
        help="Path to config file (default: ./config/config.scanner.json)"
    )

    # Test flags (ADD MORE HERE)
    parser.add_argument("--full-scan", action="store_true", dest="full_scan", help="Run full security scan (both ZAP and Semgrep)")
    parser.add_argument("--zap-only", action="store_true", dest="zap_only", help="Run only ZAP DAST scan")
    parser.add_argument("--semgrep-only", action="store_true", dest="semgrep_only", help="Run only Semgrep SAST scan")
    parser.add_argument("--source-path", type=str, default=None, help="Path to source code for Semgrep analysis (auto-detects Juice Shop if not provided)")

    # Convenience flags (ADD MORE HERE)
    # parser.add_argument("--all", action="store_true", help="Run all tests")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Load config and resolve settings
    cfg = load_config(args.config)

    target_url = normalize_url(args.url)
    validate_url(target_url)

    timeout = float(args.timeout) if args.timeout is not None else float(cfg["timeout"])
    verify_tls = certifi.where() if cfg["verify_tls"] else False
    user_agent = str(cfg["user_agent"])

    # Shared HTTP session
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    # Decide which tests to run
    if not (args.full_scan or args.zap_only or args.semgrep_only):
        print("No tests selected. Use --full-scan, --zap-only, or --semgrep-only")
        return 2

    # Determine which tools to run
    run_zap = args.full_scan or args.zap_only
    run_semgrep = args.full_scan or args.semgrep_only

    results = []

    # run the full security scan
    try:
        results.append(run_full_security_scan(
            target_url, 
            timeout, 
            verify_tls, 
            run_zap=run_zap, 
            run_semgrep=run_semgrep,
            source_path=args.source_path
        ))
    except Exception as e:
        results.append({"test": "full_scan", "ok": False, "error": f"{type(e).__name__}: {e}"})

    # Output
    output = {"target": target_url, "results": results}
    print(json.dumps(output, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
