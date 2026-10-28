#!/usr/bin/env python3
"""Source-based MinGW x64 verification; never publishes or executes game binaries.

Adapted from CodaLilitari/OpenJKDF2-MotS-Fixes windows-x64-retail-fidelity.yml
at 6fa54630a123485d8c7b602c47992613a1f397b5 (andreipemberton/Coda Lilitari).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

SYSTEM_DLLS = set("""advapi32 avrt bcrypt comctl32 comdlg32 crypt32 dbgcore dbghelp
    dnsapi dwmapi gdi32 imagehlp imm32 iphlpapi kernel32 ksuser msvcrt ntdll ole32
    oleacc oleaut32 opengl32 powrprof psapi rpcrt4 setupapi shell32 shlwapi user32
    uxtheme version winmm wintrust ws2_32""".split())
# Current SDL3/SDL3_mixer source paths, including the statically enabled codecs.
LICENSES = """
LICENSE.md
3rdparty/json/LICENSE.MIT
src/external/libsmacker/COPYING
src/external/libsmusher/LICENSE
src/external/fcaseopen/LICENSE.txt
src/external/nativefiledialog-extended/LICENSE
flex/COPYING
byacc/README
byacc/NO_WARRANTY
lib/SDL/LICENSE.txt
lib/SDL/src/hidapi/LICENSE.txt
lib/SDL/src/hidapi/LICENSE-bsd.txt
lib/SDL/src/video/yuv2rgb/LICENSE
lib/SDL_mixer/LICENSE.txt
lib/SDL_mixer/src/dr_libs/LICENSE
lib/SDL_mixer/external/ogg/COPYING
lib/SDL_mixer/external/vorbis/COPYING
lib/SDL_mixer/external/opus/COPYING
lib/SDL_mixer/external/opus/LICENSE_PLEASE_READ.txt
lib/SDL_mixer/external/opusfile/COPYING
lib/freeglut/COPYING
lib/glew/LICENSE.txt
lib/libpng/LICENSE
lib/zlib/LICENSE
lib/physfs/LICENSE.txt
lib/openal/COPYING
lib/openal/BSD-3Clause
lib/GameNetworkingSockets/LICENSE
lib/GameNetworkingSockets/src/external/picojson/LICENSE
lib/GameNetworkingSockets/src/external/abseil/LICENSE
lib/GameNetworkingSockets/src/external/webrtc/LICENSE
lib/protobuf/LICENSE
""".split()
RUNTIME_ARCHIVES = ("libstdc++.a", "libssp.a", "libwinpthread.a", "libmingwex.a",
                    "libmingw32.a", "libgcc.a", "libgcc_eh.a")


def run(command, cwd=None):
    return subprocess.run(command, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify_hashes(root, manifest):
    for name, expected in manifest.items():
        if sha256(root / name) != expected:
            raise RuntimeError(f"Hash mismatch: {name}")


def system_dll(name):
    name = name.lower()
    return (name.endswith(".dll") and
            (name[:-4] in SYSTEM_DLLS or name.startswith(("api-ms-win-", "ext-ms-win-"))))


def pe_header(path):
    data = path.read_bytes()
    if len(data) < 64:
        raise RuntimeError(f"Truncated DOS header: {path}")
    offset = int.from_bytes(data[60:64], "little")
    if offset < 64 or len(data) < offset + 26:
        raise RuntimeError(f"Truncated PE header: {path}")
    machine = int.from_bytes(data[offset + 4:offset + 6], "little")
    magic = int.from_bytes(data[offset + 24:offset + 26], "little")
    if (data[:2] != b"MZ" or data[offset:offset + 4] != b"PE\0\0" or
            machine != 0x8664 or magic != 0x20b):
        raise RuntimeError(f"Expected AMD64/PE32+ binary: {path}")
    return {"machine": "0x8664", "optional_magic": "0x020b"}


def stage_pe(seeds, search_dirs, stage, records):
    """Stage explicit entry points and their transitive non-system imports."""
    if not seeds:
        raise RuntimeError("No PE entry points")
    candidates = {}
    for directory in search_dirs:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix.lower() == ".dll":
                candidates.setdefault(path.name.lower(), []).append(path)
    queue = list(seeds)
    done = {}
    origins = {}
    while queue:
        source = queue.pop(0)
        key = source.name.lower()
        if key in done:
            if sha256(source) != done[key]["sha256"]:
                raise RuntimeError(f"Conflicting PE filename: {source.name}")
            continue
        header = pe_header(source)
        info = run(["x86_64-w64-mingw32-objdump", "-f", str(source)])
        description = run(["file", "-b", str(source)])
        if ("file format pei-x86-64" not in info or "architecture: i386:x86-64" not in info
                or not re.search(r"PE32\+.*x86-64", description)):
            raise RuntimeError(f"Architecture inspectors disagree: {source}")
        imports_text = run(["x86_64-w64-mingw32-objdump", "-p", str(source)])
        imports = re.findall(r"^\s*DLL Name:\s*(\S+)\s*$", imports_text, re.MULTILINE)
        if not imports:
            raise RuntimeError(f"No import records from objdump: {source}")
        dest = stage / source.name
        shutil.copy2(source, dest)
        done[key] = {**header, "sha256": sha256(dest), "imports": imports,
                     "file": description.strip(), "objdump_header": info}
        origins[source.name] = str(source)
        for name in imports:
            if system_dll(name) or name.lower() in done:
                continue
            found = candidates.get(name.lower(), [])
            if not found:
                runtime = Path(run(["x86_64-w64-mingw32-gcc", "-print-file-name=" + name]).strip())
                if runtime.is_file():
                    found = [runtime]
            if not found:
                raise RuntimeError(f"Missing non-system dependency: {name} (imported by {source.name})")
            if len({sha256(path) for path in found}) != 1:
                raise RuntimeError(f"Ambiguous non-system dependency: {name}")
            queue.append(found[0])
    result = {path.name: done[path.name.lower()] for path in sorted(stage.iterdir())}
    write_json(records / "PE.json", result)
    write_json(records / "BINARY_ORIGINS.json", origins)
    manifest = {name: value["sha256"] for name, value in result.items()}
    verify_hashes(stage, manifest)
    write_json(records / "BINARY_SHA256.json", manifest)
    # These are verification inputs only: the caller uploads records, never stage.
    return result


def copy_licenses(source, records, licenses=LICENSES):
    manifest = {}
    for name in licenses:
        path = source / name
        if not path.is_file():
            raise FileNotFoundError(f"Required license is missing: {path}")
        if not path.stat().st_size:
            raise RuntimeError(f"Empty license: {path}")
        dest = records / "licenses" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        manifest[name] = sha256(path)
    verify_hashes(records / "licenses", manifest)
    return manifest


def source_receipt(source, pristine):
    def git(*args):
        return run(["git", "-C", str(source), *args])
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    if pristine and status:
        raise RuntimeError(f"Source is not pristine: {source}\n{status}")
    modules = []
    for entry in git("ls-tree", "-r", "-z", "HEAD").split("\0"):
        if not entry:
            continue
        meta, name = entry.split("\t", 1)
        mode, _, expected = meta.split()
        if mode != "160000":
            continue
        path = source / name
        # Require an actual submodule checkout, not the parent's repository.
        if not (path / ".git").exists():
            raise RuntimeError(f"Uninitialized submodule: {path}")
        sub = source_receipt(path, pristine)
        if sub["commit"] != expected:
            raise RuntimeError(f"Submodule commit mismatch: {path}")
        modules.append({"path": name, "expected_commit": expected, **sub})
    return {"commit": git("rev-parse", "HEAD").strip(), "status": status,
            "remote": git("config", "--get", "remote.origin.url").strip()
            if git("remote").strip() else None,
            "diff": git("diff", "HEAD", "--", "."), "submodules": modules}


def runtime_licenses(records, binaries, build):
    """Verify archive/DLL ownership and retain actual distro package notices."""
    paths = [Path(run(["x86_64-w64-mingw32-gcc", "-print-file-name=" + name]).strip())
             for name in RUNTIME_ARCHIVES]
    paths.extend(Path(path) for path in binaries.values() if not Path(path).is_relative_to(build))
    packages = {}
    for path in paths:
        path = path.resolve(strict=True)
        owner = run(["dpkg-query", "-S", str(path)]).split(": ", 1)[0].strip()
        version = run(["dpkg-query", "-W", "-f=${Package} ${Version}\n", owner]).strip()
        notice = Path("/usr/share/doc") / owner.split(":", 1)[0] / "copyright"
        if not notice.is_file() or not notice.stat().st_size:
            raise RuntimeError(f"Missing compiler runtime copyright: {notice}")
        dest = records / "licenses" / "MinGW" / (owner.replace(":", "_") + "-copyright.txt")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(notice, dest)
        packages[str(path)] = {"package": version, "sha256": sha256(path),
                               "copyright_sha256": sha256(dest)}
    write_json(records / "MINGW_RUNTIME_PACKAGES.json", packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["before", "after", "verify"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--stage", type=Path)
    args = parser.parse_args()
    source, records = args.source.resolve(), args.records.resolve()
    records.mkdir(parents=True, exist_ok=True)
    if args.mode in {"before", "after"}:
        receipt = source_receipt(source, pristine=args.mode == "before")
        write_json(records / ("SOURCE_" + args.mode.upper() + ".json"), receipt)
        if args.mode == "after":
            before = json.loads((records / "SOURCE_BEFORE.json").read_text())
            if receipt["commit"] != before["commit"]:
                raise RuntimeError("Source commit changed during build")
            # Dependency patches are retained in each recursive receipt. The root
            # checkout must have no other tracked changes or untracked inputs.
            clean_root = run(["git", "-C", str(source), "status", "--porcelain=v1",
                              "--ignore-submodules=dirty", "--untracked-files=all"])
            if clean_root:
                raise RuntimeError(f"Unexpected root source mutation:\n{clean_root}")
        return
    if args.build is None or args.stage is None:
        parser.error("verify requires --build and --stage")
    before = json.loads((records / "SOURCE_BEFORE.json").read_text())
    after = json.loads((records / "SOURCE_AFTER.json").read_text())
    current = run(["git", "-C", str(source), "rev-parse", "HEAD"]).strip()
    if before["commit"] != after["commit"] or before["commit"] != current:
        raise RuntimeError("Verification inputs do not match source receipts")
    build, stage = args.build.resolve(), args.stage.resolve()
    stage.mkdir(parents=True, exist_ok=False)
    seeds = [build / "openjkdf2-64.exe", build / "OpenAL32.dll",
             build / "libGameNetworkingSockets.dll"]
    # FreeGLUT is a required full-build dependency; select installed output.
    freeglut = sorted((build / "freeglut").rglob("*freeglut.dll"))
    if not freeglut:
        raise FileNotFoundError("Required FreeGLUT DLL is missing")
    seeds.append(freeglut[0])
    stage_pe(seeds, [build], stage, records)
    write_json(records / "LICENSE_SOURCES.json", copy_licenses(source, records))
    origins = json.loads((records / "BINARY_ORIGINS.json").read_text())
    runtime_licenses(records, origins, build)
    generator = build / "cogapp_venv/bin/python3"
    # This is the environment created and used by precompile_globals.cmake.
    versions = run([str(generator), "-c", "import importlib.metadata as m; import sys; "
                    "print(sys.executable); print(sys.version); print('cogapp=' + m.version('cogapp'))"])
    frozen = run([str(generator), "-m", "pip", "freeze", "--all"])
    (records / "GENERATOR.txt").write_text(versions + "\n" + frozen)
    tools = [run(command) for command in (["cmake", "--version"],
             ["x86_64-w64-mingw32-gcc", "--version"], ["x86_64-w64-mingw32-g++", "--version"],
             ["x86_64-w64-mingw32-ld", "--version"], ["x86_64-w64-mingw32-objdump", "--version"],
             ["file", "--version"], ["python3", "--version"])]
    (records / "BUILD_TOOLCHAIN.txt").write_text("\n".join(tools))
    shutil.copy2(build / "CMakeCache.txt", records / "CMakeCache.txt")
    (records / "SOURCE_URL.txt").write_text(
        f"Source remote: {before['remote']}\nCommit: {before['commit']}\n"
        "Upstream project: https://github.com/shinyquagsire23/OpenJKDF2\n"
        "Checkout the recorded commit, then git submodule update --init --recursive.\n"
        "SOURCE_AFTER.json retains dependency patches applied by the existing build.\n"
        "Records cover a source build; no Windows runtime or retail-data acceptance is implied.\n")
    manifest = {str(p.relative_to(records)): sha256(p)
                for p in sorted(records.rglob("*")) if p.is_file() and p.name != "SHA256SUMS.json"}
    verify_hashes(records, manifest)
    write_json(records / "SHA256SUMS.json", manifest)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
