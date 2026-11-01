#!/usr/bin/env python3
"""Build real production translation units; no source-text extraction/mutation."""
import argparse
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile


def run_checked(command, timeout):
    """Bound the whole POSIX build process group, including compiler children."""
    process = subprocess.Popen(command, start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--ubsan", action="store_true")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("the focused host target requires Linux; use the normal engine build on other platforms")
    with tempfile.TemporaryDirectory(prefix="openjk-vectorcross-") as build:
        run_checked(["cmake", "-S", str(args.source_root / "src/Tests/cmake/vectorcross"), "-B", build,
                        "-DCMAKE_C_COMPILER=" + args.cc,
                        "-DPython3_EXECUTABLE=" + sys.executable,
                        "-DENABLE_UBSAN=" + ("ON" if args.ubsan else "OFF")], timeout=60)
        run_checked(["cmake", "--build", build, "--parallel", "1"], timeout=120)
        run_checked(["ctest", "--test-dir", build, "--output-on-failure", "-V"], timeout=45)


if __name__ == "__main__":
    main()
