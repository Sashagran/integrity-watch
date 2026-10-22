"""Core logic: scanning, signed baselines and comparison.

Threat model
------------
An attacker who gains root can modify binaries and configs *and* the baseline
that describes them. integrity-watch therefore signs the baseline with an
HMAC key that should live outside the monitored host's writable storage
(read-only media, a secrets manager, or a separate admin account). A baseline
whose signature does not verify is reported as tampered and never trusted.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

FORMAT_VERSION = 1
SUPPORTED_ALGORITHMS = ("sha256", "sha512", "blake2b", "sha3_256")
CHUNK = 1024 * 1024


class BaselineError(Exception):
    """Baseline is missing, malformed or its signature is invalid."""


@dataclass(frozen=True)
class FileRecord:
    path: str
    type: str  # "file" | "symlink"
    digest: str
    size: int
    mode: str  # octal permission string, e.g. "0755"
    uid: int
    gid: int
    mtime: float
    target: str = ""  # symlink target

    @property
    def suid(self) -> bool:
        return bool(int(self.mode, 8) & (stat.S_ISUID | stat.S_ISGID))

    @property
    def world_writable(self) -> bool:
        return bool(int(self.mode, 8) & stat.S_IWOTH)


@dataclass
class Policy:
    paths: list[str]
    exclude: list[str] = field(default_factory=list)
    algorithm: str = "sha256"
    follow_symlinks: bool = False
    max_file_size: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"unsupported algorithm {self.algorithm!r}, choose from {SUPPORTED_ALGORITHMS}")

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        p = Path(path)
        if p.suffix == ".toml":
            import tomllib  # Python 3.11+

            data = tomllib.loads(p.read_text(encoding="utf-8"))
        else:
            data = json.loads(p.read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class Change:
    kind: str  # added | removed | modified | permissions | owner | symlink
    path: str
    severity: str
    details: str = ""


# ---------------------------------------------------------------- scanning


def _hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)


def iter_files(policy: Policy) -> Iterator[Path]:
    for root in policy.paths:
        root_path = Path(root)
        if root_path.is_file() or root_path.is_symlink():
            if not _excluded(str(root_path), policy.exclude):
                yield root_path
            continue
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=policy.follow_symlinks):
            dirnames[:] = sorted(d for d in dirnames if not _excluded(os.path.join(dirpath, d), policy.exclude))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if not _excluded(full, policy.exclude):
                    yield Path(full)


def scan(policy: Policy) -> tuple[dict[str, FileRecord], list[str]]:
    """Return records keyed by path, plus a list of non-fatal errors."""
    records: dict[str, FileRecord] = {}
    errors: list[str] = []
    for path in iter_files(policy):
        try:
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(path)
                rec = FileRecord(str(path), "symlink", hashlib.sha256(target.encode()).hexdigest(), 0,
                                 f"{stat.S_IMODE(st.st_mode):04o}", st.st_uid, st.st_gid, st.st_mtime, target)
            elif stat.S_ISREG(st.st_mode):
                if st.st_size > policy.max_file_size:
                    errors.append(f"{path}: skipped, larger than max_file_size")
                    continue
                rec = FileRecord(str(path), "file", _hash_file(path, policy.algorithm), st.st_size,
                                 f"{stat.S_IMODE(st.st_mode):04o}", st.st_uid, st.st_gid, st.st_mtime)
            else:
                continue  # sockets, fifos, devices
            records[rec.path] = rec
        except OSError as exc:
            errors.append(f"{path}: {exc.strerror or exc}")
    return records, errors


# ---------------------------------------------------------------- baseline


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(payload: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


def build_baseline(records: dict[str, FileRecord], policy: Policy, key: bytes) -> dict:
    payload = {
        "format": FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "algorithm": policy.algorithm,
        "policy": asdict(policy),
        "files": {p: asdict(r) for p, r in sorted(records.items())},
    }
    return {"payload": payload, "signature": {"alg": "HMAC-SHA256", "value": sign(payload, key)}}


def save_baseline(baseline: dict, path: str | Path) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(baseline, indent=1, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)  # atomic on POSIX


def load_baseline(path: str | Path, key: bytes) -> tuple[dict[str, FileRecord], dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        payload, signature = data["payload"], data["signature"]["value"]
    except FileNotFoundError:
        raise BaselineError(f"baseline not found: {path}") from None
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BaselineError(f"baseline is malformed: {exc}") from None

    if not hmac.compare_digest(sign(payload, key), signature):
        raise BaselineError("baseline signature is INVALID: the baseline was modified or the wrong key was used")
    if payload.get("format") != FORMAT_VERSION:
        raise BaselineError(f"unsupported baseline format {payload.get('format')}")
    records = {p: FileRecord(**r) for p, r in payload["files"].items()}
    return records, payload


# ---------------------------------------------------------------- comparison

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CRITICAL_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/", "/boot/", "/etc/pam.d/",
                  "/etc/ssh/", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/ld.so")


def _severity_for(path: str, base: str) -> str:
    norm = path if path.startswith("/") else "/" + path.lstrip("./")
    return "high" if any(d in norm for d in _CRITICAL_DIRS) else base


def compare(old: dict[str, FileRecord], new: dict[str, FileRecord]) -> list[Change]:
    changes: list[Change] = []
    for path in sorted(old.keys() - new.keys()):
        changes.append(Change("removed", path, _severity_for(path, "medium")))
    for path in sorted(new.keys() - old.keys()):
        rec = new[path]
        sev = "critical" if rec.suid else _severity_for(path, "low")
        details = "SUID/SGID bit set" if rec.suid else ""
        changes.append(Change("added", path, sev, details))

    for path in sorted(old.keys() & new.keys()):
        a, b = old[path], new[path]
        if a.type != b.type or (a.type == "symlink" and a.target != b.target):
            changes.append(Change("symlink" if "symlink" in (a.type, b.type) else "modified", path,
                                  _severity_for(path, "high"), f"{a.type}:{a.target} -> {b.type}:{b.target}"))
            continue
        if a.digest != b.digest:
            changes.append(Change("modified", path, _severity_for(path, "medium"),
                                  f"size {a.size} -> {b.size}, digest {a.digest[:12]}… -> {b.digest[:12]}…"))
        if a.mode != b.mode:
            sev = "critical" if b.suid and not a.suid else ("high" if b.world_writable and not a.world_writable else "medium")
            changes.append(Change("permissions", path, sev, f"{a.mode} -> {b.mode}"))
        if (a.uid, a.gid) != (b.uid, b.gid):
            changes.append(Change("owner", path, _severity_for(path, "medium"), f"{a.uid}:{a.gid} -> {b.uid}:{b.gid}"))

    changes.sort(key=lambda c: (-_SEVERITY_ORDER[c.severity], c.path))
    return changes


# ---------------------------------------------------------------- keys


def load_key(path: str | Path) -> bytes:
    p = Path(path)
    key = p.read_bytes().strip()
    if len(key) < 32:
        raise BaselineError("HMAC key is too short (need at least 32 bytes)")
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        raise BaselineError(f"key file {p} is accessible by group/others (mode {mode:04o}); run chmod 600")
    return key


def generate_key(path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"{p} already exists")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(os.urandom(32).hex())
