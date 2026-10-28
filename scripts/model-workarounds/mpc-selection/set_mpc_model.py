"""Preview or safely change only the model field in an explicitly named JK/MotS MPC.

The game must be closed before applying a change. No profile discovery or PLR
editing. This is a historical selection technique, not a new engine workaround.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

MODEL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,26}\.3do", re.ASCII)

def prepare(data: bytes, model: str) -> tuple[bytes, str]:
    if not MODEL.fullmatch(model) or len(model.encode('ascii')) > 31 or '..' in model:
        raise ValueError('Model must be an ASCII .3do basename of at most 31 bytes.')
    # The game writes ASCII-compatible profiles. Byte-level replacement retains
    # every force bin, personality, saber, soundclass and newline verbatim.
    versions = list(re.finditer(rb'(?im)^version\b[^\r\n]*\r?$', data))
    if len(versions) != 1 or not re.fullmatch(rb'version[ \t]+1[ \t]*\r?', versions[0][0], re.I):
        raise ValueError('Expected a JK/MotS version 1 MPC profile.')
    fields = list(re.finditer(rb'(?im)^(model:[ \t]*)([^\r\n]*)(\r?)$', data))
    if len(fields) != 1:
        raise ValueError('Expected exactly one model: line; no file was changed.')
    match = fields[0]
    old = match[2].decode('ascii', errors='strict').strip()
    result = data[:match.start(2)] + model.encode('ascii') + data[match.end(2):]
    return result, old

def checked_profile(path: Path) -> tuple[Path, os.stat_result]:
    """Refuse indirect paths; this is not a lock against concurrent writers."""
    path = path.absolute()
    if path.suffix.lower() != '.mpc':
        raise ValueError('Provide an existing regular .mpc file, not a PLR or link.')
    info = None
    for component in (path, *path.parents):
        current = component.lstat()
        if stat.S_ISLNK(current.st_mode) or (
            getattr(current, 'st_file_attributes', 0) & 0x400  # Windows reparse point
        ):
            raise ValueError('Profile paths must not contain links or reparse points.')
        if component == path:
            if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                raise ValueError('Provide a regular .mpc file with exactly one hard link.')
            info = current
        elif not stat.S_ISDIR(current.st_mode):
            raise ValueError('Every profile path ancestor must be a directory.')
    return path.resolve(strict=True), info

def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino

def update(path: Path, model: str, apply: bool = False) -> dict:
    path, original_info = checked_profile(path)
    before = path.read_bytes()
    after, old = prepare(before, model)
    result = dict(profile=str(path), old_model=old, new_model=model,
                  before_sha256=hashlib.sha256(before).hexdigest(),
                  after_sha256=hashlib.sha256(after).hexdigest(),
                  applied=False, changed=before != after)
    if apply and before != after:
        # Verify the exclusive backup before the first profile write. The game
        # must be closed: these checks detect changes, but do not acquire a lock.
        tag = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = path.with_name(path.name + f'.{tag}.{uuid.uuid4().hex[:8]}.bak')
        with backup.open('xb') as fp:
            fp.write(before)
            fp.flush()
            os.fsync(fp.fileno())
        if backup.read_bytes() != before:
            raise RuntimeError(f'Backup verification failed; profile was not written. Inspect {backup}.')
        _, current_info = checked_profile(path)
        if identity(current_info) != identity(original_info) or path.read_bytes() != before:
            raise RuntimeError(f'Profile changed while preparing; retained backup {backup}.')
        try:
            with path.open('r+b') as fp:
                opened_info = os.fstat(fp.fileno())
                if identity(opened_info) != identity(original_info) or opened_info.st_nlink != 1 or fp.read() != before:
                    raise RuntimeError('Profile changed; aborting write.')
                fp.seek(0)
                fp.write(after)
                fp.truncate()
                fp.flush()
                os.fsync(fp.fileno())
            if path.read_bytes() != after or backup.read_bytes() != before:
                raise RuntimeError('Post-write verification failed.')
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(f'{exc} Retained original backup: {backup}') from exc
        result.update(applied=True, backup=str(backup))
    return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('profile', type=Path, help='Exact existing .mpc path; close the game first')
    ap.add_argument('model', help='Installed model basename, e.g. custom.3do')
    ap.add_argument('--apply', action='store_true', help='Write after creating a verified backup; default is preview')
    args = ap.parse_args()
    try:
        print(json.dumps(update(args.profile, args.model, args.apply), indent=2))
    except (OSError, ValueError, RuntimeError) as exc:
        ap.error(str(exc))

if __name__ == '__main__':
    main()
