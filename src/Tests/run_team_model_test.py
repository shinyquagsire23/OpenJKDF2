#!/usr/bin/env python3
"""Test extracted production JK/MotS team-model packet handlers without assets.

Usage: python3 src/Tests/run_team_model_test.py --cc gcc --ubsan
Independent expectations cover the upstream five-row mapping and ensure
lookup misses skip model changes without rejecting otherwise valid team updates.
Generated fragments and executables live only in a temporary directory.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_test_utils import extract_block, unique_match, find_compiler


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = ("src/Dss/jkDSS.c", "src/Dss/sithMulti.h", "src/types_enums.h")


def write(directory, name, value):
    (directory / name).write_text(value + "\n", encoding="utf-8", newline="\n")


def extract_production(directory):
    source_bytes = {name: (REPO_ROOT / name).read_bytes() for name in SOURCE_PATHS}
    source = {name: data.decode("utf-8").replace("\r\n", "\n")
              for name, data in source_bytes.items()}
    dss = source["src/Dss/jkDSS.c"]
    arrays = []
    for name in ("jkDSS_aKyTeamModels", "jkDSS_aMotsKyTeamModels"):
        arrays.append(extract_block(dss, rf"^const char\s*\*\s*{name}\s*\[", name) + ";")
    write(directory, "team_model_arrays.inc", "\n\n".join(arrays))
    helper = extract_block(dss, r"^static const char\s*\*\s*jkDSS_GetMotsTeamModel\s*\(",
                           "checked MotS team-model lookup")
    write(directory, "team_model_lookup.inc", helper)
    functions = []
    for name in ("jkDSS_ProcessSetSaberInfoMots", "jkDSS_ProcessSetSaberInfo", "jkDSS_ProcessSetTeam"):
        functions.append(extract_block(dss, rf"^int\s+{name}\s*\(", name))
    write(directory, "team_model_handlers.inc", "\n\n".join(functions))

    network = source["src/Dss/sithMulti.h"]
    start = unique_match(r"^#define NETMSG_START intptr_t[^\n]*", network, "wire macro start")
    end = unique_match(r"^#define NETMSG_IN_END[^\n]*", network, "wire macro end")
    if end.end() <= start.start():
        raise RuntimeError("Network macro ordering changed")
    write(directory, "team_model_wire.h", network[start.start():end.end()])
    enums = source["src/types_enums.h"]
    constants = []
    for name in ("DSS_SABERINFO1", "DSS_SABERINFO2", "DSS_SETTEAM",
                 "MULTIMODEFLAG_TEAMS", "MULTIMODEFLAG_20", "MULTIMODEFLAG_100"):
        match = unique_match(rf"^[ \t]*{name}\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)", enums, name)
        constants.append("enum { " + match.group().strip() + " };")
    write(directory, "team_model_constants.h", "\n".join(constants))
    shutil.copyfile(Path(__file__).with_name("team_model_test.c"), directory / "team_model_test.c")
    return source_bytes


def execute(command, directory, environment):
    return subprocess.run(command, cwd=directory, env=environment, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=120, check=False)


def require_success(result, label):
    if result.returncode:
        raise RuntimeError(f"{label} exited {result.returncode}\n{result.stdout}{result.stderr}")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def run(compiler, ubsan):
    with tempfile.TemporaryDirectory(prefix="openmots-team-model-") as temporary:
        directory = Path(temporary)
        source_bytes = extract_production(directory)
        environment = os.environ.copy()
        flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
        if ubsan:
            flags += ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        version = execute([compiler, "--version"], directory, environment)
        require_success(version, "Compiler version")
        print(version.stdout.splitlines()[0])
        print("UndefinedBehaviorSanitizer:", "enabled" if ubsan else "disabled")
        binary = directory / "team-model-current"
        if os.name == "nt":
            binary = binary.with_suffix(".exe")
        command = [compiler, *flags, "team_model_test.c", "-o", str(binary)]
        require_success(execute(command, directory, environment), "Compile team-model harness")
        result = execute([str(binary)], directory, environment)
        require_success(result, "Production team-model regression")
        print(result.stdout, end="")
        for name, data in source_bytes.items():
            if (REPO_ROOT / name).read_bytes() != data:
                raise RuntimeError("Production input changed during test: " + name)
            print(f"SHA256 {hashlib.sha256(data).hexdigest()} {name}")
        print("PASS production inputs unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC"))
    parser.add_argument("--ubsan", action="store_true")
    args = parser.parse_args()
    try:
        run(find_compiler(args.cc), args.ubsan)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print("FAIL:", error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
