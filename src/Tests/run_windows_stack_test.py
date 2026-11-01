#!/usr/bin/env python3
"""Link with the production MinGW toolchain and inspect its Windows stack policy.

On Linux, use a fresh --build-dir outside the checkout. On Windows, use
--check-exe <built probe> --run-native to also observe main/default
worker stack reservations without intentionally causing an overflow.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def read_stack_header(path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE executable")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    optional = pe + 24
    if machine != 0x8664 or struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("expected an AMD64 PE32+ executable")
    reserve, commit = struct.unpack_from("<QQ", data, optional + 72)
    return {"reserve": reserve, "commit": commit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--build-dir", type=Path,
                        help="Fresh external build directory (must not contain CMakeCache.txt)")
    source.add_argument("--check-exe", type=Path,
                        help="Inspect any existing AMD64 PE32+ executable without running it")
    parser.add_argument("--run-native", action="store_true",
                        help="Run the built stack probe on Windows (only use with the probe executable)")
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    if args.build_dir:
        build = args.build_dir.resolve()
        if (build / "CMakeCache.txt").exists():
            parser.error("--build-dir must be fresh: existing CMakeCache.txt can retain "
                         "old toolchain linker flags; choose a new build directory")
        root = tests.parent.parent
        subprocess.run(["cmake", "-S", str(tests / "cmake/windows-stack"),
                        "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
                        "-DCMAKE_TOOLCHAIN_FILE=" + str(root / "cmake_modules/toolchain_mingw.cmake")],
                       check=True, timeout=120)
        subprocess.run(["cmake", "--build", str(build), "--parallel", "2"],
                       check=True, timeout=120)
        executable = build / "windows_stack_probe.exe"
    else:
        executable = args.check_exe.resolve()
    header = read_stack_header(executable)
    result = {"executable": str(executable), "header": header}
    # The Win32 documented default is 1 MiB. Reject a linker policy that
    # silently gives application and default library threads less than that.
    valid = header["reserve"] >= 1048576 and 0 < header["commit"] <= header["reserve"]
    if args.run_native:
        if os.name != "nt":
            parser.error("--run-native requires native Windows")
        run = subprocess.run([str(executable)], capture_output=True, text=True,
                             timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        result["native"] = {"exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
        valid = valid and run.returncode == 0
    result["passed"] = valid
    print(json.dumps(result, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
