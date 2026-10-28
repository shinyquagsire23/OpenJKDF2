#!/usr/bin/env python3
"""Exercise production bitmap conversion with explicit in-memory display stubs.

Run: python3 src/Tests/run_bitmap_test.py --cc gcc --ubsan
No game assets or renderer are required. Only corrected production code runs;
the null guard is never removed. All generated files are temporary.
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
SOURCE_PATHS = ("src/General/stdBitmap.c", "src/General/stdBitmap.h", "src/types.h")


def run(compiler, ubsan):
    inputs = {name: (REPO_ROOT / name).read_bytes() for name in SOURCE_PATHS}
    source = {name: value.decode("utf-8").replace("\r\n", "\n")
              for name, value in inputs.items()}
    function = extract_block(source[SOURCE_PATHS[0]],
                             r"^void stdBitmap_ConvertColorFormat\(", "bitmap conversion")
    types = []
    for path, name in ((SOURCE_PATHS[2], "rdTexFormat"), (SOURCE_PATHS[1], "stdBitmap")):
        types.append(extract_block(source[path], r"^typedef struct " + name + r"\s*\{", name)
                     + " " + name + ";")
    type_source = ("#include <stdint.h>\n" + types[0]
                   + "\ntypedef struct tVBuffer tVBuffer;\n" + types[1])
    with tempfile.TemporaryDirectory(prefix="openjkdf2-bitmap-") as temporary:
        directory = Path(temporary)
        write_fragment(directory, "source_types.inc", type_source)
        write_fragment(directory, "actual_function.inc", function)
        shutil.copyfile(Path(__file__).with_name("bitmap_test.c"), directory / "bitmap_test.c")
        environment = os.environ.copy()
        flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
        if ubsan:
            flags += ["-fsanitize=undefined", "-fno-sanitize-recover=all"]
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        version = execute([compiler, "--version"], directory, environment, 30)
        require_success(version, "Compiler version query")
        print(version.stdout.splitlines()[0])
        print("UndefinedBehaviorSanitizer:", "enabled" if ubsan else "disabled")
        for name, extra in (("default", []), ("sdl2-layout", ["-DSDL2_RENDER"])):
            binary = directory / (name + (".exe" if os.name == "nt" else ""))
            command = [compiler, *flags, *extra, "bitmap_test.c", "-o", str(binary)]
            require_success(execute(command, directory, environment, 120), f"Compile bitmap {name}")
            result = execute([str(binary)], directory, environment, 30)
            require_success(result, f"Production bitmap regression {name}")
            print(f"{name}: {result.stdout}", end="")
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
