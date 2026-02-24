# S.H.E.I.L.D
Web Applications Vulnerability Scanner Tool

python -m venv .venv
source .venv/bin/activate  
# .venv\Scripts\activate    # windows
pip install -r requirements.txt

# Brief Description
scanner.py - CLI web app vulnerability scanner

Current features:
- Accepts a target URL
- Loads optional config.json (defaults to config.scanner.json if missing)
- Shared requests.Session with User-Agent
- Runs selected tests via flags (--ping, --headers)
- Prints JSON results to stdout

Next steps:
- Move each test into separate module files
- Add a test registry and --list-tests / --all
- Add report output (file writing)

