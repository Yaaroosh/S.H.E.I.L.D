import subprocess, json
from pathlib import Path

target = "http://localhost:3000"
report = Path("scan-results") / "nuclei_debug.json"
paths = [
    Path("tools/nuclei/nuclei.exe"),
    Path("tools/nuclei/nuclei"),
    "nuclei",
]
cmd = None
for p in paths:
    if isinstance(p, str):
        cmd = p
        break
    elif p.exists():
        cmd = str(p)
        break
print("chosen cmd", cmd)
cmd_list = [cmd, "-u", target, "-json", "-o", str(report), "-severity", "critical,high,medium,low"]
print("cmd list", cmd_list)
try:
    res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300)
    print("rc", res.returncode)
    print("stdout", res.stdout)
    print("stderr", res.stderr)
except Exception as e:
    print("exception", e)
