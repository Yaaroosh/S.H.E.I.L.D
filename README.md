# S.H.E.I.L.D
Web Applications Vulnerability Scanner Tool

python -m venv .venv
source .venv/bin/activate  
# .venv\Scripts\activate    # windows
pip install -r requirements.txt
# If PowerShell blocks the script, run once (as admin):
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned 

# Installation of Dependencies
./scripts/before_setup.bat (runs setup.ps1 automatically)

The setup script installs the scanner dependencies and bundled tooling (CodeQL,
ZAP, and ffuf). Use the CLI from the project root after setup is complete.

Directory brute-force scanning is also available as a separate mode. It uses
the bundled ffuf binary installed under tools/ffuf, with a built-in
official ffuf-recommended SecLists common wordlist by default
(`tools/ffuf/wordlists/common.txt`).
# Brief Description
`cli.py` (invoked via `python cli.py` from the project root) - CLI web app vulnerability scanner

Current features:
- Accepts a target URL (defaults to `http://localhost:3000`)
- Loads configuration from `./config/config.json` if present, falling back to
  the committed `./config/config.scanner.json`.  When executed outside the
  project root the automatic lookup may fail, so either `cd` back to the
  workspace base or supply `--config <path>` explicitly.
- Shared requests.Session with User-Agent
- Runs full OWASP ZAP security scan using `--full-scan` (DAST, CodeQL, and dirscan)
- Runs CodeQL static analysis scan (SAST) on the target source code
- Runs directory brute-force discovery with `--dirscan-only`
- **New**: Run tools separately with `--zap-only` or `--codeql-only` flags
- **New**: Override the dirscan wordlist with `--dirscan-wordlist <path>`
- **New**: Tune dirscan depth/performance with `--dirscan-depth`, `--dirscan-threads`, and `--dirscan-rate`
- **New**: Include extension fuzzing with `--dirscan-extensions` and toggle recursion with `--dirscan-no-recursion`
- **New**: Specify custom source path for CodeQL with `--source-path <path>`
- CodeQL database is built in a temporary OS directory during each run and cleaned up afterward; `--source-path` is used only as the analysis source root
- Categorizes findings by OWASP vulnerability type (from ZAP, CodeQL, and dirscan)
- Generates a timestamped text report and prints JSON summary to stdout
- Reports include results from both ZAP (DAST) and CodeQL (SAST) for broader coverage

Usage examples:
```bash
# Full scan (ZAP, CodeQL, and dirscan)
python cli.py --full-scan

# ZAP DAST only
python cli.py --zap-only

# ZAP with authenticated session cookie
python cli.py --zap-only --auth-cookie "session=abc123"

# CodeQL SAST only (requires source path)
python cli.py --codeql-only

# CodeQL with custom source path
python cli.py --codeql-only --source-path ./my-app/src

# Directory scan only
python cli.py --dirscan-only

# Directory scan with a custom wordlist
python cli.py --dirscan-only --dirscan-wordlist ./wordlists/common.txt

# Deeper directory scan with recursion and extension fuzzing
python cli.py --dirscan-only --dirscan-depth 4 --dirscan-threads 120 --dirscan-extensions "php,html,js,bak,txt,old,zip"

# Safer deep scan on slower targets (rate limited)
python cli.py --dirscan-only --dirscan-depth 3 --dirscan-rate 50 --dirscan-extensions "php,html"
```

Next steps (when you're ready):
- Move each test into separate module files
- Add a test registry and --list-tests / --all
- Add report output (file writing)

