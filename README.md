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

> **Note:** Juice Shop requires Node.js 18+ to build; Node 20 is recommended for compatibility.
> The setup script now warns when a newer Node version (22+) is detected but will
> still attempt the build unless Docker is being used.  The install will often
> succeed with TypeScript warnings/errors (see terminal output), but a failed build
> means you should either switch to Node 20/18 or fall back to the Docker image.

# if all is successful run juice shop:
cd tools/juice-shop
npm start

Alternatively, if building locally is problematic (e.g. you have Node 22) you can use the
pre‑built Docker image instead:

```powershell
# pull and run container on port 3000
docker pull bkimminich/juice-shop:17.1.0
docker run -p 3000:3000 bkimminich/juice-shop:17.1.0
```

The setup script will even detect Docker and offer this fallback automatically.
# Brief Description
`cli.py` (invoked via `python cli.py` from the project root) - CLI web app vulnerability scanner

Current features:
- Accepts a target URL (defaults to `http://localhost:3000`)
- Loads configuration from `./config/config.json` if present, falling back to
  the committed `./config/config.scanner.json`.  When executed outside the
  project root the automatic lookup may fail, so either `cd` back to the
  workspace base or supply `--config <path>` explicitly.
- Shared requests.Session with User-Agent
- Runs full OWASP ZAP security scan using `--full-scan` (DAST)
- Runs CodeQL static analysis scan (SAST) on the target source code
- **New**: Run tools separately with `--zap-only` or `--codeql-only` flags
- **New**: Specify custom source path for CodeQL with `--source-path <path>`
- Categorizes findings by OWASP vulnerability type (from both ZAP and CodeQL)
- Generates a timestamped text report and prints JSON summary to stdout
- Reports include results from both ZAP (DAST) and CodeQL (SAST) for broader coverage

Usage examples:
```bash
# Full scan (both ZAP and CodeQL)
python cli.py --full-scan

# ZAP DAST only
python cli.py --zap-only

# ZAP with authenticated session cookie
python cli.py --zap-only --auth-cookie "session=abc123"

# ZAP with bearer token header
python cli.py --zap-only --auth-header "Authorization: Bearer <token>"

# CodeQL SAST only (requires source path)
python cli.py --codeql-only

# CodeQL with custom source path
python cli.py --codeql-only --source-path ./my-app/src
```

Next steps (when you're ready):
- Move each test into separate module files
- Add a test registry and --list-tests / --all
- Add report output (file writing)

