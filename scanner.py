
import argparse
import json
import os
from urllib.parse import urlparse
import certifi #for TLS verification
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# -------------------------
# Configuration
# -------------------------

def load_config(
    personal_path: str = "./config/config.json",
    example_path: str = "./config/config.scanner.json"
) -> dict:
    """
    Load configuration with priority:
    1. config.json (personal, not committed)
    2. config.example.json (committed default template)
    """

    if os.path.exists(personal_path):
        path = personal_path
    elif os.path.exists(example_path):
        path = example_path
    else:
        raise FileNotFoundError(
            "No config file found. Expected config.json or config.example.json"
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


# -------------------------
# Tests (placeholders for now)
# Later: move each into its own file/module.
# -------------------------

def test_ping(session: requests.Session, url: str, timeout: float, verify_tls: bool) -> dict:
    """Basic reachability check."""
    r = session.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True)
    return {
        "test": "ping",
        "ok": True,
        "status_code": r.status_code,
        "final_url": r.url,
    }


def test_headers(session: requests.Session, url: str, timeout: float, verify_tls: bool) -> dict:
    """Basic header visibility check (placeholder)."""
    r = session.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True)
    headers = dict(r.headers)

    interesting_keys = [
        "Server",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    interesting = {k: headers.get(k) for k in interesting_keys if k in headers}

    return {
        "test": "headers",
        "ok": True,
        "status_code": r.status_code,
        "interesting": interesting,
    }


# -------------------------
# CLI
# -------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple Web App Scanner (starter template)")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")

    # Global options
    parser.add_argument("--timeout", type=float, default=None, help="Override timeout from config (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    parser.add_argument("--config", default="config.json", help="Path to config file (default: config.json)")

    # Test flags (ADD MORE HERE)
    parser.add_argument("--ping", action="store_true", help="Run a basic reachability test")
    parser.add_argument("--headers", action="store_true", help="Run a basic headers check")

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
    selected_tests = []
    if args.ping:
        selected_tests.append("ping")
    if args.headers:
        selected_tests.append("headers")

    if not selected_tests:
        print("No tests selected. Try: --ping or --headers")
        return 2

    results = []

    # Run tests (simple manual dispatch for now)
    if "ping" in selected_tests:
        try:
            results.append(test_ping(session, target_url, timeout, verify_tls))
        except Exception as e:
            results.append({"test": "ping", "ok": False, "error": f"{type(e).__name__}: {e}"})

    if "headers" in selected_tests:
        try:
            results.append(test_headers(session, target_url, timeout, verify_tls))
        except Exception as e:
            results.append({"test": "headers", "ok": False, "error": f"{type(e).__name__}: {e}"})

    # Output
    output = {"target": target_url, "results": results}
    print(json.dumps(output, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
