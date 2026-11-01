"""Shared source extraction and native-test helpers; no game assets required."""

import os
import re
import shutil
import subprocess
import sys

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


def write_fragment(directory, name, text):
    with (directory / name).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text + "\n")


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


def execute(command, directory, environment, timeout):
    return subprocess.run(
        command, cwd=directory, env=environment, capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False,
    )


def require_success(result, description):
    if result.returncode != 0:
        raise RuntimeError(
            f"{description} exited {result.returncode}\n"
            f"{result.stdout}{result.stderr}"
        )
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
