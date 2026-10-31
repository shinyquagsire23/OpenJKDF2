#!/usr/bin/env python3
"""Compile capture contract/UI-stub tests; no SDL, game, or desktop API is linked."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="")
        result.check_returncode()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    compiler = os.environ.get("CC", "gcc")
    flags = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-Wall", "-Wextra", "-Werror"]
    logs = []
    with tempfile.TemporaryDirectory(prefix="openjk-capture-test-") as tmp:
        stage = Path(tmp)
        (stage / "resource").mkdir()
        (stage / "resource/jk_.cd").write_bytes(b"test")
        (stage / ".openjkdf2-capture-session").write_text("synthetic\n")
        request = stage / "request.txt"
        request.write_text("sed-engine-capture-v1\n64 64 0 3 1000\n0 0 0 0 0 0 75\n" + str(stage / "unused.ppm") + "\n")
        for name in ("capture_request_test", "capture_ui_test", "capture_launch_test"):
            exe = stage / name
            run([compiler, *flags, "-I", str(ROOT), str(ROOT / "Tests" / (name + ".c")), "-lm", "-o", str(exe)])
            command = [str(exe)]
            if name == "capture_request_test":
                command.append(str(stage / "pixels.ppm"))
            if name == "capture_launch_test":
                command.append(str(request))
            result = run(command, cwd=stage)
            logs.append({"test": name, "stdout": result.stdout, "stderr": result.stderr})
        pixels = stage / "pixels.ppm"
        (args.output / "pixels.ppm").write_bytes(pixels.read_bytes())
        (args.output / "pixels.ppm.json").write_bytes((stage / "pixels.ppm.json").read_bytes())
    sources = ["Main/stdCapture.c", "Main/stdCapture.h", "Main/stdAutostartCharacter.h", "Platform/SDL2/stdCaptureUi.h", "Tests/capture_request_test.c", "Tests/capture_ui_test.c", "Tests/capture_launch_test.c", "Tests/run_capture_test.py"]
    receipt = {
        "schemaVersion": 1, "gameLaunched": False, "windowSystemLinked": False,
        "sanitizers": ["address", "undefined"], "testGroupsPassed": 3,
        "ordinaryModeControlPassed": True, "compiler": run([compiler, "--version"]).stdout.splitlines()[0],
        "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
        "logs": logs,
    }
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
