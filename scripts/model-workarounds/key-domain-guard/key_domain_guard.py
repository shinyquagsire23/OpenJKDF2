"""Plan additive Sith-engine hierarchy slots from an explicit KEY corpus.

This is an index-footprint and exporter-metadata guard, not a full KEY/3DO parser
or an engine compatibility certificate. It never edits a model or game profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

NODE_LIMIT = 64
MESH_LIMITS = {"vertex_count": 512, "uv_count": 768, "face_count": 512}
MAX_INPUT_BYTES = 16 * 1024 * 1024


def integer(value, label, minimum=0, maximum=NODE_LIMIT):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label}: expected an integer in {minimum}..{maximum}")
    return value


def read_input(path):
    if not path.is_file():
        raise ValueError(f"{path.name}: input must be a regular file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{path.name}: input exceeds {MAX_INPUT_BYTES} bytes")
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES or b"\x00" in data:
        raise ValueError(f"{path.name}: oversized or binary input")
    return data


def meaningful_lines(data):
    return [(i, line.split("#", 1)[0].strip())
            for i, line in enumerate(data.decode("latin1").splitlines(), 1)
            if line.split("#", 1)[0].strip()]


def analyze_key_bytes(files):
    """Map provenance labels to bytes; retain hashes and indices, not poses.

    NODE blocks are conservatively treated as occupied even if ENTRIES is zero.
    A declaration reserves its whole allocation, including unpopulated slots.
    """
    if not files:
        raise ValueError("An explicit nonempty intended KEY corpus is required")
    rows = []
    for name, data in sorted(files.items()):
        if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES or b"\x00" in data:
            raise ValueError(f"{name}: expected bounded text bytes")
        declarations = {"JOINTS": [], "NODES": [], "NODE": []}
        for number, line in meaningful_lines(data):
            keyword = re.match(r"^(JOINTS|NODES|NODE)\b", line, re.I)
            if not keyword:
                continue
            token = keyword[1].upper()
            match = re.fullmatch(r"(JOINTS|NODES|NODE)\s+([0-9]+)", line, re.I)
            if not match:
                raise ValueError(f"{name}:{number}: malformed {token} index declaration")
            declarations[token].append(int(match[2]))
        if len(declarations["JOINTS"]) != 1:
            raise ValueError(f"{name}: expected one JOINTS declaration")
        count = integer(declarations["JOINTS"][0], f"{name}: JOINTS", 1)
        populated = declarations["NODE"]
        if not populated:
            raise ValueError(f"{name}: expected at least one NODE block")
        if len(set(populated)) != len(populated):
            raise ValueError(f"{name}: repeated NODE index")
        if any(index >= count for index in populated):
            raise ValueError(f"{name}: populated NODE exceeds declared allocation")
        node_counts = declarations["NODES"]
        if len(node_counts) > 1 or (node_counts and node_counts[0] != len(populated)):
            raise ValueError(f"{name}: NODES declaration does not match NODE blocks")
        rows.append({
            "name": str(name), "sha256": hashlib.sha256(data).hexdigest(),
            "declared_joint_count": count,
            "populated_node_indices": sorted(populated),
            "highest_possible_addressed_index": max(count - 1, max(populated)),
        })
    return {
        "scope": "Only supplied KEY index footprints; caller must supply every reachable KEY.",
        "keys": rows,
        "required_slot_count": max(row["highest_possible_addressed_index"] + 1 for row in rows),
        "populated_slot_union": sorted({n for row in rows for n in row["populated_node_indices"]}),
    }


def plan_detail_nodes(base_node_count, footprint, detail_chunk_count, node_limit=NODE_LIMIT):
    integer(node_limit, "node_limit", 1)
    integer(base_node_count, "base_node_count", 1, node_limit)
    integer(detail_chunk_count, "detail_chunk_count", 0, node_limit)
    required = integer(footprint["required_slot_count"], "required_slot_count", 1, node_limit)
    first = max(base_node_count, required)
    total = first + detail_chunk_count
    if total > node_limit:
        raise ValueError(f"{total} nodes exceed {node_limit}; reduce detail node count")
    return {
        "base_node_count": base_node_count,
        "reserved_invisible_leaf_indices": list(range(base_node_count, first)),
        "first_detail_index": first,
        "detail_indices": list(range(first, total)),
        "total_node_count": total, "node_limit": node_limit,
        "rule": "Reserved slots have no mesh or children. Detail is neutral under its intended base parent.",
    }


def keys_from_pup(pup_path, key_directory):
    """Resolve all literal KEY references in a PUP, within one explicit directory.

    Includes every mode instead of guessing which inherited modes run.
    COG-selected or dynamically constructed filenames must be supplied separately.
    """
    directory = key_directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("--key-dir must be a directory")
    names = set()
    for number, line in meaningful_lines(read_input(pup_path)):
        if (re.fullmatch(r"mode\s*=\s*\d+(?:\s*,\s*basedon\s*=\s*\d+)?", line, re.I)
                or re.fullmatch(r"(?:joints|end)", line, re.I)
                or re.fullmatch(r"\d+\s*=\s*-?\d+", line)):
            continue
        fields = line.split()
        if len(fields) != 5 or not re.fullmatch(r"[A-Za-z0-9_$.-]+\.key", fields[1], re.I):
            raise ValueError(f"{pup_path.name}:{number}: unsupported or malformed PUP row")
        if fields[1].startswith("."):
            raise ValueError(f"{pup_path.name}:{number}: unsafe KEY filename")
        try:
            int(fields[2], 0)
            int(fields[3], 10)
            int(fields[4], 10)
        except ValueError as exc:
            raise ValueError(f"{pup_path.name}:{number}: malformed PUP flags/priorities") from exc
        names.add(fields[1].casefold())
    if not names:
        raise ValueError(f"{pup_path.name}: no literal KEY references found")
    matches = {name: [] for name in names}
    for candidate in directory.iterdir():
        if candidate.name.casefold() in matches:
            matches[candidate.name.casefold()].append(candidate)
    resolved = []
    for name in sorted(names):
        if len(matches[name]) != 1:
            raise ValueError(f"{pup_path.name}: missing or ambiguous KEY filename {name}")
        path = matches[name][0].resolve(strict=True)
        if not path.is_relative_to(directory) or not path.is_file():
            raise ValueError(f"{pup_path.name}: KEY reference escapes directory or is not a file")
        resolved.append(path)
    return resolved


def validate_hierarchy(document, base_node_count, footprint):
    """Validate a JSON export summary; counts do not certify real mesh contents."""
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("hierarchy: expected schema_version 1 object")
    nodes, meshes = document.get("nodes"), document.get("meshes")
    if not isinstance(nodes, list) or not isinstance(meshes, list):
        raise ValueError("hierarchy: nodes and meshes must be lists")
    integer(len(nodes), "hierarchy node count", 1)
    integer(base_node_count, "base_node_count", 1, len(nodes))
    first = max(base_node_count, integer(footprint["required_slot_count"], "required_slot_count", 1))
    if len(nodes) < first:
        raise ValueError("hierarchy: missing slots reserved for the intended animation domain")
    errors = []
    mesh_ids = set()
    for mesh in meshes:
        if not isinstance(mesh, dict) or not isinstance(mesh.get("id"), str) or not mesh["id"]:
            raise ValueError("mesh: expected a nonempty string id")
        if mesh["id"] in mesh_ids:
            raise ValueError(f"mesh: duplicate id {mesh['id']}")
        mesh_ids.add(mesh["id"])
        if mesh.get("primitive") != "triangles":
            errors.append(f"mesh {mesh['id']}: primitive must be triangles")
        for field, limit in MESH_LIMITS.items():
            value = mesh.get(field)
            if type(value) is not int or value < 0:
                raise ValueError(f"mesh {mesh['id']}: {field} must be a nonnegative integer")
            if value > limit:
                errors.append(f"mesh {mesh['id']}: {field} {value} exceeds {limit}")
        if mesh["face_count"] and (mesh["vertex_count"] < 3 or mesh["uv_count"] < 3):
            errors.append(f"mesh {mesh['id']}: triangle faces need at least 3 vertices and UVs")
    parents = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or type(node.get("index")) is not int or node["index"] != index:
            raise ValueError("nodes: expected ordered contiguous integer indices starting at 0")
        parent = node.get("parent")
        if parent is not None:
            integer(parent, f"node {index} parent", 0, len(nodes) - 1)
        if (index == 0) != (parent is None):
            errors.append(f"node {index}: only node 0 may have null parent")
        parents.append(parent)
        role = node.get("role")
        if role not in ("base", "reserved", "detail"):
            raise ValueError(f"node {index}: role must be base, reserved, or detail")
        mesh = node.get("mesh")
        if mesh is not None and (not isinstance(mesh, str) or mesh not in mesh_ids):
            raise ValueError(f"node {index}: unknown mesh id")
        expected_role = "base" if index < base_node_count else "reserved" if index < first else "detail"
        if role != expected_role:
            errors.append(f"node {index}: role {role} collides with required {expected_role} slot")
        if expected_role == "reserved" and mesh is not None:
            errors.append(f"node {index}: animation-reserved leaf must have no mesh")
        if expected_role == "detail":
            if node.get("neutral_transform") is not True:
                errors.append(f"node {index}: detail must declare a neutral local transform")
            if parent is None or parent >= base_node_count:
                errors.append(f"node {index}: detail parent must be an intended base animation node")
    for index, parent in enumerate(parents):
        if parent is not None and base_node_count <= parent < first:
            errors.append(f"node {parent}: animation-reserved slot must be a leaf (child {index})")
        seen = {index}
        cursor = parent
        while cursor is not None:
            if cursor in seen:
                errors.append(f"node {index}: hierarchy contains a cycle")
                break
            seen.add(cursor)
            cursor = parents[cursor]
    return {"valid": not errors, "node_count": len(nodes), "mesh_count": len(meshes),
            "first_safe_detail_index": first, "errors": errors,
            "scope": "Declared export metadata only; render and animate the actual model to verify it."}


def load_json(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"JSON: duplicate property {key}")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError(f"JSON: nonfinite constant {value}")
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_pairs,
                      parse_constant=invalid_constant)


def write_report(output, rendered, input_paths):
    """Write atomically and never replace an input, including an alias/hardlink."""
    destination = output.resolve()
    if any(destination == source.resolve()
           or (output.exists() and output.samefile(source)) for source in input_paths):
        raise ValueError("Output must not overwrite any input")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".key-domain-",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keys", type=Path, nargs="*", help="Exact KEY paths; no wildcard expansion by this program")
    parser.add_argument("--pup", type=Path, action="append", default=[])
    parser.add_argument("--key-dir", type=Path, help="Explicit flat KEY directory required with --pup")
    parser.add_argument("--base-nodes", type=int, required=True)
    parser.add_argument("--detail-chunks", type=int, default=0)
    parser.add_argument("--hierarchy", type=Path, help="Optional exporter metadata JSON to validate")
    parser.add_argument("--output", type=Path, help="Optional JSON report; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        if bool(args.pup) != bool(args.key_dir):
            raise ValueError("--pup and --key-dir must be supplied together")
        paths = [path.resolve(strict=True) for path in args.keys]
        if len(set(paths)) != len(paths):
            raise ValueError("Duplicate explicit KEY input")
        input_paths = list(paths)
        for pup in args.pup:
            input_paths.append(pup.resolve(strict=True))
            paths.extend(keys_from_pup(pup, args.key_dir))
        paths = sorted(set(paths))
        if any(path.suffix.casefold() != ".key" for path in paths):
            raise ValueError("All KEY inputs must have .key extension")
        footprint = analyze_key_bytes({f"key_{i:03d}:{path.name}": read_input(path)
                                       for i, path in enumerate(paths, 1)})
        result = {"footprint": footprint,
                  "plan": plan_detail_nodes(args.base_nodes, footprint, args.detail_chunks)}
        if args.hierarchy:
            input_paths.append(args.hierarchy.resolve(strict=True))
            result["hierarchy"] = validate_hierarchy(load_json(read_input(args.hierarchy)), args.base_nodes, footprint)
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            write_report(args.output, rendered, input_paths + paths)
        else:
            print(rendered, end="")
        return 0 if result.get("hierarchy", {}).get("valid", True) else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
