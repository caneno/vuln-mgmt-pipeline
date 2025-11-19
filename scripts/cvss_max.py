#/usr/bin/env python3
import json, sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_PATH = BASE_DIR / "docker" / "vulnerable-nginx" / "reports" / "trivy.json"

if not REPORT_PATH.is_file():
    print(f"Error: Trivy report not found at {REPORT_PATH}", file=sys.stderr)
    sys.exit(1)

data = json.loads(REPORT_PATH.read_text())
max_cvss = 0.0

for results in data.get("Results", []):
    for v in results.get("Vulnerabilities", []):
        score = 0.0
        if v.get("CVSS") and "nvd" in v["CVSS"]:
            score = float(v["CVSS"]["nvd"].get("V3Score", 0.0))
        else:
            score = float(v.get("CVSSScore", 0.0))
        if score > max_cvss:
            max_cvss = score
            
print(f"{max_cvss:.1f}")    # the .1f  (rounda to one decimal)
