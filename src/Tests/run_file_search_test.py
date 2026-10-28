#!/usr/bin/env python3
"""Test corrected POSIX directory searches using owned temporary directories.

Extracts current production functions and structs, with native libc filesystem
calls. Desktop case correction and Dreamcast asset routing use their actual
production helpers. The retro configurations are host tests, not console runs.
Only corrected code is compiled; no former malformed-input path is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SOURCE_NAMES = (
    "src/General/stdFileUtil.c", "src/General/stdFileUtil.h",
    "src/external/fcaseopen/fcaseopen.c", "src/Platform/Dreamcast/dcStorage.c",
    "src/Tests/file_search_test.c", "src/Tests/run_file_search_test.py",
)


def extract_block(source, pattern, label):
    """Extract one complete production block, ignoring quoted/comment braces."""
    matches = list(re.finditer(pattern, source, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one {label} block, found {len(matches)}")
    start = matches[0].start()
    index = source.find("{", matches[0].end())
    if index == -1:
        raise RuntimeError(f"Missing opening brace for {label}")
    depth = 0
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index:index + 2]
        if state == "line-comment":
            if char == "\n": state = "code"
        elif state == "block-comment":
            if following == "*/":
                state = "code"
                index += 1
        elif state in ('"', "'"):
            if char == "\\":
                index += 1
            elif char == state:
                state = "code"
        elif following == "//":
            state = "line-comment"
            index += 1
        elif following == "/*":
            state = "block-comment"
            index += 1
        elif char in ('"', "'"):
            state = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if not depth:
                return source[start:index + 1]
        index += 1
    raise RuntimeError(f"Missing closing brace for {label}")


def find_compiler(requested):
    """Use a native compiler without importing another regression suite."""
    for candidate in ([requested] if requested else ("cc", "gcc", "clang")):
        compiler = shutil.which(candidate)
        if compiler:
            return compiler
    raise RuntimeError("Native C compiler not found: " + (requested or "cc, gcc, clang"))


def prepare(work, inputs):
    source = {name: value.decode().replace("\r\n", "\n") for name, value in inputs.items()}
    utility = source[SOURCE_NAMES[0]]
    posix = utility.rsplit("#if defined(PLATFORM_POSIX) && !defined(WIN32)", 1)[1]
    types = []
    for name in ("stdFileSearch", "stdFileSearchResult"):
        types.append(extract_block(source[SOURCE_NAMES[1]], r"^typedef struct " + name + r"\b", name) + " " + name + ";")
    functions = ["#ifdef FS_POSIX", extract_block(source[SOURCE_NAMES[2]], r"^int casepath\(", "case correction"), "#endif"]
    functions += ["#ifdef TARGET_DREAMCAST", "static int dcStorage_bInit;", "static char dcStorage_assetRoot[128];"]
    for name, prefix in (("dcStorage_IsWritable", "static int"), ("dcStorage_ResolveAssetPath", "int")):
        functions.append(extract_block(source[SOURCE_NAMES[3]], "^" + prefix + " " + name + r"\(", name))
    functions.append("#endif")
    for name in ("stdFileUtil_PrepareSearchPath", "stdFileUtil_PrepareSearchDirectory"):
        functions.append(extract_block(utility, "^static int " + name + r"\(", name))
    functions.append(extract_block(utility, r"^stdFileSearch\* stdFileUtil_NewFind\(", "new search"))
    functions.append('static const char* search_ext = "";')
    for name, prefix in (("parse_ext", "static int"), ("stdFileUtil_FindNext", "int"),
                         ("stdFileUtil_DisposeFind", "void"), ("stdFileUtil_FindReset", "void"),
                         ("stdFileUtil_FindQuick", "int"), ("stdFileUtil_CountMatches", "int")):
        functions.append(extract_block(posix, "^" + prefix + " " + name + r"\(", name))
    (work / "actual_search_types.inc").write_text("\n".join(types) + "\n")
    (work / "actual_search_functions.inc").write_text("\n".join(functions) + "\n")
    (work / "file_search_test.c").write_bytes(inputs[SOURCE_NAMES[4]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC"))
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    compiler = find_compiler(args.cc)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    inputs = {name: (ROOT / name).read_bytes() for name in SOURCE_NAMES}
    receipt = {
        "compiler": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
        "sanitizers": ["address", "undefined"] if args.sanitize else [],
        "scope": "Corrected extracted search functions/types; real temporary files/scandir; actual casepath and Dreamcast routing helper; no console/game runtime.",
        "source_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
        "configurations": [],
    }
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-D_DEFAULT_SOURCE", "-D_POSIX_C_SOURCE=200809L", "-DPLATFORM_POSIX"]
    environment = os.environ.copy()
    if args.sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
        environment["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    try:
        with tempfile.TemporaryDirectory(prefix="openjkdf2-file-search-") as directory:
            work = Path(directory)
            prepare(work, inputs)
            for name, defines in (("desktop", ["-DFS_POSIX"]), ("retro", ["-DTARGET_RETRO_HOMEBREW"]),
                                  ("dreamcast-routing", ["-DTARGET_RETRO_HOMEBREW", "-DTARGET_DREAMCAST"])):
                fixture = work / (name + "-files")
                fixture.mkdir()
                executable = work / name
                command = [compiler, *flags, *defines, str(work / "file_search_test.c"), "-o", str(executable)]
                started = time.monotonic()
                compiled = subprocess.run(command, cwd=work, env=environment, text=True, capture_output=True, timeout=90)
                record = {"name": name, "command": command, "compile_exit_code": compiled.returncode}
                receipt["configurations"].append(record)
                log = "$ " + " ".join(command) + "\n" + compiled.stdout + compiled.stderr
                if compiled.returncode:
                    if args.output: (args.output / (name + ".log")).write_text(log)
                    raise RuntimeError(name + " compile failed:\n" + compiled.stdout + compiled.stderr)
                result = subprocess.run([str(executable), str(fixture)], cwd=work, env=environment, text=True, capture_output=True, timeout=30)
                log += result.stdout + result.stderr
                record.update(exit_code=result.returncode, seconds=round(time.monotonic() - started, 3))
                if args.output: (args.output / (name + ".log")).write_text(log)
                if result.returncode:
                    raise RuntimeError(name + " failed:\n" + result.stdout + result.stderr)
                record.update(json.loads(result.stdout))
                print(name + ": " + result.stdout.strip())
        receipt["source_unchanged"] = all((ROOT / name).read_bytes() == data for name, data in inputs.items())
        if not receipt["source_unchanged"]:
            raise RuntimeError("Source changed during validation")
        receipt["passed"] = True
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        receipt["passed"] = False
        receipt["error"] = str(error)
        raise
    finally:
        if args.output: (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
