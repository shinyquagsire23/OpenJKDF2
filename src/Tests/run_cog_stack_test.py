#!/usr/bin/env python3
"""Run bounded production COG stack checks without assets or an engine build.

Usage: python3 src/Tests/run_cog_stack_test.py --cc gcc --sanitize
Fixed/dynamic and compressed/uncompressed layouts use eight test slots. The
dynamic TWL allocation path is also checked with owned host-memory stubs.
Uses only the Python standard library and a native GCC/Clang compiler.
No old unsafe implementation is compiled or executed.
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

ROOT = Path(__file__).resolve().parents[2]
PATHS = ("src/Cog/sithCogExec.c", "src/types.h", "src/types_enums.h",
         "src/stdPlatform.c", "src/stdPlatform.h")


def unique_match(pattern, text, description):
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one {description}; found {len(matches)}. "
            "Review the extractor against the current production source."
        )
    return matches[0]


def extract_block(text, marker, description):
    """Include the complete brace-delimited body, ignoring comments/literals."""
    match = unique_match(marker, text, description)
    opening = text.index("{", match.start())
    tokens = re.finditer(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
        text[opening:],
        re.DOTALL,
    )
    depth = 0
    for token in tokens:
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return text[match.start():opening + token.end()]
    raise RuntimeError(f"Unbalanced production body: {description}")


def find_compiler(requested):
    candidates = [requested] if requested else ["gcc", "clang", "cc"]
    for name in candidates:
        compiler = shutil.which(name)
        if compiler:
            return compiler
    raise RuntimeError(
        "Native GCC/Clang compiler not found. Set --cc to its executable path "
        "or add gcc/clang to PATH; do not select a cross compiler."
    )

def prepare(directory):
    originals = {name: (ROOT / name).read_bytes() for name in PATHS}
    sources = {name: value.decode("utf-8").replace("\r\n", "\n")
               for name, value in originals.items()}
    types = sources["src/types.h"]
    symbols = unique_match(
        r"^#ifdef COG_COMPRESS_VAR_SIZE\n(?s:.*?)^#endif(?=\n\ntypedef struct sithCog\n)",
        types, "symbol representations").group()
    fields = unique_match(
        r"^#ifdef COG_DYNAMIC_STACKS\n    SithCogSymbolValue\* stack;\n(?s:.*?)^#endif\n    uint32_t stackPos;",
        types, "stack storage fields").group()
    declarations = ["typedef struct sithCog sithCog;"]
    for declaration in ("typedef int32_t cog_int_t;", "typedef float flex32_t;",
                        "typedef flex32_t cog_flex_t;", "typedef void (*cogSymbolFunc_t)(sithCog *);"):
        declarations.append(unique_match(re.escape(declaration), types, declaration).group())
    value = unique_match(r"^[ \t]*SITHCOG_VALUE_INT\s*=\s*\d+",
                         sources["src/types_enums.h"], "integer symbol type").group()
    declarations += ["enum { " + value.strip() + " };", symbols,
                     "struct sithCog {\n" + fields + "\n};"]
    (directory / "stack_types.inc").write_text("\n".join(declarations) + "\n")
    code = sources[PATHS[0]]
    operations = []
    for name, kind in (("sithCogExec_PushStack", "void"), ("sithCogExec_PopStack", "int32_t"),
                       ("sithCogExec_ResetStack", "void")):
        operations.append(extract_block(code, rf"^{kind}\s+{name}\s*\(", name))
    operations += ["#ifdef COG_DYNAMIC_STACKS", extract_block(
        code, r"^void\s+sithCogExec_GrowStack\s*\(", "stack growth"), "#endif"]
    (directory / "stack_operations.inc").write_text("\n\n".join(operations) + "\n")
    word = extract_block(sources["src/stdPlatform.h"],
                         r"^static inline void stdPlatform_WriteByte16\(", "word byte store")
    copy = extract_block(sources["src/stdPlatform.c"],
                         r"^void stdPlatform_Memcpy32\(", "word copy")
    (directory / "word_copy.inc").write_text(
        word + "\n#define stdPlatform_Memcpy32 testWordCopy\n" + copy +
        "\n#undef stdPlatform_Memcpy32\n")
    shutil.copyfile(Path(__file__).with_name("cog_stack_test.c"), directory / "cog_stack_test.c")
    return originals


def run(compiler, sanitize):
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing"]
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    env = os.environ.copy()
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    print(subprocess.check_output([compiler, "--version"], text=True).splitlines()[0], flush=True)
    with tempfile.TemporaryDirectory(prefix="openjk-cog-stack-") as temporary:
        directory = Path(temporary)
        originals = prepare(directory)
        for dynamic, compressed, twl in ((False, False, False), (False, True, False),
                                         (True, False, False), (True, True, False),
                                         (True, False, True), (True, True, True)):
            label = f"{'dynamic' if dynamic else 'fixed'}-{'compressed' if compressed else 'full'}"
            if twl:
                label += "-twl-allocation"
            defines = []
            for enabled, name in ((dynamic, "COG_DYNAMIC_STACKS"),
                                  (compressed, "COG_COMPRESS_VAR_SIZE"), (twl, "TARGET_TWL")):
                if enabled:
                    defines.append("-D" + name)
            binary = directory / (label + (".exe" if os.name == "nt" else ""))
            subprocess.run([compiler, *flags, *defines, "cog_stack_test.c", "-o", str(binary)],
                           cwd=directory, env=env, check=True, timeout=60)
            result = subprocess.run([str(binary)], cwd=directory, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if result.returncode:
                raise RuntimeError(f"{label} failed ({result.returncode})\n{result.stdout}{result.stderr}")
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
            print(label + ": " + result.stdout.strip(), flush=True)
        for name, content in originals.items():
            if (ROOT / name).read_bytes() != content:
                raise RuntimeError(f"Production input changed during the test: {name}")
            print(f"SHA256 {hashlib.sha256(content).hexdigest()} {name}")
        print("PASS all six layouts; production inputs unchanged; no old-path execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC"))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    run(find_compiler(args.cc), args.sanitize)
