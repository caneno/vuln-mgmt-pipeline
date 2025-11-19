#!/usr/bin/env python3
import subprocess, sys
from pathlib import Path

CVSS_SCRIPT = Path(__file__).resolve().parent / "cvss_max.py"

output = subprocess.check_output(
    [sys.executable, str(CVSS_SCRIPT)],
    text=True,
).strip()

max_cvss = float(output)

def estimate_epss(cvss):
    if cvss >= 9.0: return .07
    if cvss >= 7.0: return 0.35
    if cvss >= 4.0: return 0.1
    return 0.01

epss = estimate_epss(max_cvss)
risk = 0.6*(max_cvss/10.0) + 0.3*epss + 0.05*0 + 0.05*0

print(f"Max CVSS={max_cvss}, EPSS≈{epss}, Risk={risk:.2f}")

if (max_cvss >= 9.0 and epss >= 0.5) or (risk >= 0.70):
    print("❌ Policy violation. Block.")
    sys.exit(1)
print("✅ Policy satisfied.")
       
