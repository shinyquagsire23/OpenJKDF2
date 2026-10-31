#!/usr/bin/env python3
"""Run the asset-free Linux host gate, or collect its allowlisted CI evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
GROUPS = (
    ("pixel-unpack-gl", "Surfaceless EGL pixel-unpack readback", []),
)
SOURCE_RECORDS = (
    "host-orchestration.stdout.txt", "host-orchestration.stderr.txt",
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def provenance():
    def git(*args):
        result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                                text=True, check=True, timeout=30)
        return result.stdout.strip()

    result = {"commit": git("rev-parse", "HEAD"),
              "worktree_status": git("status", "--porcelain=v1"),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    for name in ("GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                 "GITHUB_REPOSITORY", "GITHUB_SERVER_URL"):
        if name in os.environ:
            result[name.lower()] = os.environ[name]
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        result["pull_request_head_sha"] = event.get("pull_request", {}).get("head", {}).get("sha")
    return result


def command_plan(work, cxx):
    flags = ["-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-Isrc"]
    binary = str(work / "pixel-unpack-gl")
    commands = {
        "pixel-unpack-gl": [
            [cxx, *flags, "src/Tests/jkgm_pixel_unpack_gl_test.cpp", "-lEGL", "-lGL", "-o", binary],
            [binary],
        ],
    }
    return [{"id": name, "name": label, "sanitizers": sanitizers,
             "commands": commands[name]} for name, label, sanitizers in GROUPS]


def check_tools(cxx):
    versions = {"python": sys.version.splitlines()[0]}
    for name, executable in (("cxx", cxx), ("git", "git")):
        result = subprocess.run([executable, "--version"], capture_output=True,
                                text=True, check=True, timeout=30)
        versions[name] = result.stdout.splitlines()[0]
    return versions

def execute_command(command, cwd, environment, stdout, stderr, timeout):
    started = time.monotonic()
    result = {"argv": command, "status": "error", "exit_code": None}
    with stdout.open("a", encoding="utf-8") as out, stderr.open("a", encoding="utf-8") as err:
        out.write("$ " + shlex.join(command) + "\n")
        out.flush()
        try:
            child = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            try:
                result["exit_code"] = child.wait(timeout=timeout)
                result["status"] = "passed" if child.returncode == 0 else "failed"
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                # Terminate only the new command's process group, including any
                # compiler/test children belonging to that command.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
                result["exit_code"] = child.returncode
                result["status"] = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted"
                err.write(result["status"] + "\n")
        except OSError as error:
            result["error"] = str(error)
            err.write(str(error) + "\n")
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result


def execute_groups(groups, output, environment, cwd, setup, source, timeout=900):
    """Fail fast, keeping a checkpoint and explicit not-run rows for every group."""
    output.mkdir(parents=True, exist_ok=False)
    (output / "logs").mkdir()
    started = time.monotonic()
    receipt = {"schema_version": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
               "source": source, "scope": "asset-free native Linux host regressions",
               "game_launched": False, "status": "running", "timeout_seconds": timeout,
               "groups": [{"id": group["id"], "name": group["name"],
                           "sanitizers": group["sanitizers"], "status": "not_run", "commands": []}
                          for group in groups]}

    def checkpoint():
        receipt["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json(output / "summary.json", receipt)

    checkpoint()
    try:
        receipt["tools"] = setup()
    except (OSError, ImportError, subprocess.SubprocessError) as error:
        receipt.update(status="setup_failed", error=str(error))
        checkpoint()
        return receipt
    for group, row in zip(groups, receipt["groups"]):
        row["status"] = "running"
        row["stdout"] = f"logs/{group['id']}.stdout.txt"
        row["stderr"] = f"logs/{group['id']}.stderr.txt"
        checkpoint()
        print(f"RUN {group['name']}", flush=True)
        child_environment = environment.copy()
        if group["id"] == "pixel-unpack-gl":
            child_environment["LIBGL_ALWAYS_SOFTWARE"] = "1"
        for command in group["commands"]:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                row["status"] = "timeout"
                break
            result = execute_command(command, cwd, child_environment, output / row["stdout"],
                                     output / row["stderr"], min(300, remaining))
            row["commands"].append(result)
            checkpoint()
            if result["status"] != "passed":
                row["status"] = result["status"]
                break
        else:
            row["status"] = "passed"
        print(f"{row['status'].upper()} {group['name']}", flush=True)
        checkpoint()
        if row["status"] != "passed":
            receipt["status"] = row["status"]
            break
    else:
        receipt["status"] = "passed"
    checkpoint()
    return receipt


def copy_text(source, root, destination):
    """Copy only named regular UTF-8 text/JSON; reject links and binary contents."""
    if source.is_symlink():
        raise ValueError(f"Evidence is a symlink: {source}")
    if not source.exists():
        return None
    for parent in source.relative_to(root).parents:
        if (root / parent).is_symlink():
            raise ValueError(f"Evidence has a symlink parent: {source}")
    if not source.is_file() or source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"Evidence is not a regular text file of at most 16 MiB: {source}")
    data = source.read_bytes()
    text = data.decode("utf-8")
    if "\0" in text or data.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x89PNG")):
        raise ValueError(f"Binary contents in evidence: {source}")
    if source.suffix == ".json":
        json.loads(text)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def collect_evidence(host_results, output, source_records=None, job_status="local"):
    output.mkdir(parents=True, exist_ok=False)
    candidates = [(host_results, "summary.json", "host/summary.json")]
    for name, _, _ in GROUPS:
        for stream in ("stdout", "stderr"):
            relative = f"logs/{name}.{stream}.txt"
            candidates.append((host_results, relative, f"host/{relative}"))
    if source_records is not None:
        candidates.extend((source_records, name, f"source/{name}") for name in SOURCE_RECORDS)
    manifest = {"schema_version": 1, "job_status_before_collection": job_status,
                "source": provenance(), "files": {}, "missing": [],
                "policy": "Explicit text/JSON allowlist; no binaries, images, assets, or evaluation archives."}
    for root, relative, name in candidates:
        record = copy_text(root / relative, root, output / name)
        if record is None:
            manifest["missing"].append(name)
        else:
            manifest["files"][name] = record
    summary_path = output / "host/summary.json"
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    manifest["host_status"] = summary.get("status", "not_run")
    rows = summary.get("groups", [{"name": label, "status": "not_run"} for _, label, _ in GROUPS])
    lines = ["## OpenJKDF2 host regression evidence", "", f"Host status: **{manifest['host_status']}**",
             f"Job status before collection: **{job_status}**", "",
             "| Group | Status |", "| --- | --- |"]
    lines += [f"| {row['name']} | {row['status']} |" for row in rows]
    lines += ["", "The artifact contains allowlisted text/JSON only. Missing files are recorded in manifest.json.",
              "These checks do not launch the game or establish retail gameplay parity.", ""]
    (output / "summary.txt").write_text("\n".join(lines), encoding="utf-8")
    write_json(output / "manifest.json", manifest)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run all registered groups; output directory must be new")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--cxx", default="g++", help="native C++ compiler, not a cross compiler")
    collect = sub.add_parser("collect", help="stage only approved text/JSON for artifact upload")
    collect.add_argument("--host-results", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--source-records", type=Path)
    collect.add_argument("--job-status", choices=("local", "success", "failure", "cancelled"), default="local")
    args = parser.parse_args()
    if args.command == "collect":
        text = collect_evidence(args.host_results, args.output, args.source_records, args.job_status)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
                stream.write(text)
        print(text)
        return 0
    if os.name != "posix":
        parser.error("The complete gate requires a native Linux host with surfaceless EGL.")
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = os.environ.copy()
    environment.update(CXX=args.cxx, PYTHONDONTWRITEBYTECODE="1")
    for name in ("DISPLAY", "WAYLAND_DISPLAY"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="openjk-host-gate-") as temporary:
        work = Path(temporary)
        receipt = execute_groups(command_plan(work, args.cxx), args.output, environment,
                                 ROOT, lambda: check_tools(args.cxx), provenance())
    print(f"Receipt: {args.output / 'summary.json'}")
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
