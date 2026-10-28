#!/usr/bin/env python3
"""Test upstream's actual static MAT I/O helpers with synthetic packed rows.

Run: python3 src/Tests/run_material_test.py --cc gcc --ubsan
The functions are extracted unchanged from rdMaterial.c and compiled against
an in-memory HostServices fileRead stub; no duplicate I/O helper is introduced.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_test_utils import extract_block, write_fragment, find_compiler, execute, require_success

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = ("src/Engine/rdMaterial.c", "src/types.h")


def run(compiler, ubsan):
    inputs = {name: (REPO_ROOT / name).read_bytes() for name in SOURCE_PATHS}
    source = {name: value.decode("utf-8").replace("\r\n", "\n")
              for name, value in inputs.items()}
    functions = [extract_block(source[SOURCE_PATHS[0]], rf"^static int {name}\(", name)
                 for name in ("rdMaterial_ReadExact", "rdMaterial_ReadPackedRows",
                              "rdMaterial_ValidTextureLayout")]
    header = extract_block(source[SOURCE_PATHS[1]], r"^typedef struct rdTextureHeader\s*\{",
                           "rdTextureHeader") + " rdTextureHeader;"
    with tempfile.TemporaryDirectory(prefix="openjkdf2-material-") as temporary:
        directory = Path(temporary)
        write_fragment(directory, "material_helpers.inc", "\n\n".join(functions))
        write_fragment(directory, "texture_header.inc", header)
        shutil.copyfile(Path(__file__).with_name("material_test.c"), directory / "material_test.c")
        environment = os.environ.copy()
        flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
        if ubsan:
            flags += ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        version = execute([compiler, "--version"], directory, environment, 30)
        require_success(version, "Compiler version query")
        print(version.stdout.splitlines()[0])
        print("UndefinedBehaviorSanitizer:", "enabled" if ubsan else "disabled")
        binary = directory / ("material-test.exe" if os.name == "nt" else "material-test")
        command = [compiler, *flags, "material_test.c", "-o", str(binary)]
        require_success(execute(command, directory, environment, 120), "Compile material harness")
        result = execute([str(binary)], directory, environment, 30)
        require_success(result, "Production MAT helper regression")
        print(result.stdout, end="")
        for name, data in inputs.items():
            if (REPO_ROOT / name).read_bytes() != data:
                raise RuntimeError("Production input changed during test: " + name)
            print(f"SHA256 {hashlib.sha256(data).hexdigest()} {name}")
        print("PASS production inputs unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC"))
    parser.add_argument("--ubsan", action="store_true", help="require UndefinedBehaviorSanitizer")
    args = parser.parse_args()
    try:
        run(find_compiler(args.cc), args.ubsan)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
