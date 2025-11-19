#/usr/bin/env python3
import json, sys
from pathlib import Path

data = json.loads(Path("/root/code/vuln-mgmt-pipeline/docker/vulnerable-nginx/reports/trivy.json").read_text())
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
