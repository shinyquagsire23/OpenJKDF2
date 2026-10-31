"""Run the synthetic tool suites from the consolidated repository."""
from pathlib import Path
import subprocess, sys

ROOT=Path(__file__).resolve().parent
for name in ['key-domain-guard', 'png-alignment', 'mpc-selection', 'texture-mode']:
    result=subprocess.run([sys.executable,'-B','-m','unittest','-v'],cwd=ROOT/name)
    if result.returncode:
        raise SystemExit(result.returncode)
