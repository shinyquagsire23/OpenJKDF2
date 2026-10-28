#!/usr/bin/env python3
"""Run extracted production backpack regressions with native GCC or Clang.

Usage: python3 src/Tests/run_backpack_test.py --cc gcc --ubsan
No engine build or retail assets are needed. Generated source and binaries live
in a temporary directory. Both the non-QOL 12-entry and QOL 16-entry production
layouts run the same capacity-derived checks on corrected production code.
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
SOURCE_PATHS = (
    "src/Gameplay/sithInventory.c",
    "src/Dss/sithDSSThing.c",
    "src/types.h",
    "src/types_enums.h",
    "src/engine_config.h",
)


def write(directory, name, value):
    with (directory / name).open("w", encoding="utf-8", newline="\n") as output:
        output.write(value + "\n")


def named_typedef(source, name):
    body = extract_block(source, rf"^typedef struct {name}\b", name)
    start = source.index(body)
    end = source.index(";", start + len(body)) + 1
    return source[start:end]


def extract_production(directory):
    source_bytes = {name: (REPO_ROOT / name).read_bytes() for name in SOURCE_PATHS}
    source = {name: data.decode("utf-8").replace("\r\n", "\n")
              for name, data in source_bytes.items()}
    inventory = source["src/Gameplay/sithInventory.c"]
    bodies = []
    for return_type, name in (
        ("int", "sithInventory_GetNumBackpackItems"),
        ("SithThing\\s*\\*", "sithInventory_CreateBackpack"),
        ("void", "sithInventory_PickupBackpack"),
        ("int", "sithInventory_GetBackpackItemID"),
        ("flex_t", "sithInventory_GetBackpackItemValue"),
    ):
        bodies.append(extract_block(inventory, rf"^{return_type}\s*{name}\s*\(", name))
    functions = "\n\n".join(bodies)
    write(directory, "backpack_inventory.inc", functions)
    dss = source["src/Dss/sithDSSThing.c"]
    for return_type, name, fragment in (
        ("void", "sithDSSThing_UpdateState", "backpack_dss_pack.inc"),
        ("int", "sithDSSThing_ProcessStateUpdate", "backpack_dss_unpack.inc"),
    ):
        function = extract_block(dss, rf"^{return_type}\s+{name}\s*\(", name)
        start = unique_match(r"^[ \t]*case SITH_THING_ITEM:", function, name + " item case")
        end = unique_match(r"^[ \t]*default:", function, name + " default case")
        if end.start() <= start.start():
            raise RuntimeError("DSS item case boundaries changed")
        write(directory, fragment, function[start.start():end.start()])

    types = source["src/types.h"]
    write(directory, "backpack_structs.h",
          named_typedef(types, "SithBackpackItem") + "\n\n"
          + named_typedef(types, "SithItemInfo"))
    enums = source["src/types_enums.h"]
    constants = []
    for name in ("SITH_ITEM_BACKPACK", "SITH_THING_ITEM",
                 "SITHINVENTORY_TYPE_REGISTERED", "SITHINVENTORY_TYPE_BACKPACKITEM",
                 "SITHBIN_ENERGY", "SITHBIN_MOTS_NONE", "SITHBIN_MOTS_CARBO_GUN"):
        match = unique_match(rf"^[ \t]*{name}\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)", enums, name)
        constants.append("enum { " + match.group().strip() + " };")
    match = unique_match(r"^#define SITHBIN_NUMBINS\s+\([0-9]+\)",
                         source["src/engine_config.h"], "inventory capacity")
    constants.append(match.group())
    write(directory, "backpack_constants.h", "\n".join(constants))
    shutil.copyfile(Path(__file__).with_name("backpack_test.c"), directory / "backpack_test.c")
    return source_bytes


def execute(command, directory, environment):
    result = subprocess.run(command, cwd=directory, env=environment,
                            capture_output=True, text=True, errors="replace",
                            timeout=120, check=False)
    return result


def require_success(result, label):
    if result.returncode:
        raise RuntimeError(f"{label} exited {result.returncode}\n{result.stdout}{result.stderr}")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def run(compiler, ubsan):
    with tempfile.TemporaryDirectory(prefix="openmots-backpack-") as temporary:
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
        for layout, defines, expected_capacity in (
            ("non-qol", ["-UQOL_IMPROVEMENTS"], 12),
            ("qol", ["-DQOL_IMPROVEMENTS"], 16),
        ):
            print(f"Backpack layout: {layout}, expected capacity {expected_capacity}")
            binary = directory / f"backpack-{layout}"
            if os.name == "nt":
                binary = binary.with_suffix(".exe")
            compiled = execute([compiler, *flags, *defines, "backpack_test.c", "-o", str(binary)],
                               directory, environment)
            require_success(compiled, f"Compile {layout} backpack harness")
            result = execute([str(binary)], directory, environment)
            require_success(result, f"Production {layout} backpack regression")
            if not re.search(rf"\bcapacity {expected_capacity}\s*$", result.stdout):
                raise RuntimeError(f"{layout} production backpack capacity differs from {expected_capacity}\n"
                                   + result.stdout + result.stderr)
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
