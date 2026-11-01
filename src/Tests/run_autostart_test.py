#!/usr/bin/env python3
"""Execute production startup/parser functions with controlled engine dependencies."""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "Main/Main.c").read_text()
# These complete function boundaries deliberately fail closed if signatures change.
startup = source.split("int Main_StartupDedicated(int bFullyDedicated)", 1)[1].split("\n#endif // QOL_IMPROVEMENTS", 1)[0]
parser = source.split("void Main_ParseCmdLine(char *cmdline)", 1)[1].split("\nint Main_FPrintf", 1)[0]
with tempfile.TemporaryDirectory(prefix="autostart-test-") as tmp:
    unit = Path(tmp) / "production.inc"
    unit.write_text("int Main_StartupDedicated(int bFullyDedicated)" + startup + "\nvoid Main_ParseCmdLine(char *cmdline)" + parser)
    exe = Path(tmp) / "test"
    subprocess.run([os.environ.get("CC", "gcc"), "-std=c11", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-parentheses", "-I", str(ROOT), "-I", tmp, str(ROOT / "Tests/autostart_test.c"), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
