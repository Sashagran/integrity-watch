"""Command line interface for integrity-watch."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .core import BaselineError, Policy, build_baseline, compare, generate_key, load_baseline, load_key, save_baseline, scan

EXIT_OK, EXIT_CHANGES, EXIT_TAMPERED, EXIT_ERROR = 0, 1, 2, 3

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def _policy_from_args(args) -> Policy:
    if args.config:
        return Policy.from_file(args.config)
    if not args.paths:
        raise SystemExit("error: give paths to monitor or --config")
    return Policy(paths=args.paths, exclude=args.exclude or [], algorithm=args.algorithm)


def _syslog(changes, tampered: str | None = None) -> None:
    try:
        import syslog
    except ImportError:  # pragma: no cover - non-POSIX
        return
    syslog.openlog("integrity-watch", 0, syslog.LOG_AUTHPRIV)
    if tampered:
        syslog.syslog(syslog.LOG_CRIT, f"BASELINE TAMPERED: {tampered}")
    for c in changes:
        prio = syslog.LOG_CRIT if c.severity in ("critical", "high") else syslog.LOG_WARNING
        syslog.syslog(prio, f"{c.severity.upper()} {c.kind} {c.path} {c.details}".strip())


def cmd_keygen(args) -> int:
    generate_key(args.key)
    print(f"Generated 256-bit HMAC key in {args.key} (mode 0600). Store a copy off-host.")
    return EXIT_OK


def cmd_init(args) -> int:
    key = load_key(args.key)
    policy = _policy_from_args(args)
    records, errors = scan(policy)
    save_baseline(build_baseline(records, policy, key), args.baseline)
    for e in errors:
        print(f"warning: {e}", file=sys.stderr)
    print(f"Baseline created: {len(records)} files, algorithm {policy.algorithm}, signed with HMAC-SHA256 -> {args.baseline}")
    return EXIT_OK


def _render(changes, color: bool) -> str:
    if not changes:
        return "OK: no changes since baseline."
    counts = Counter(c.severity for c in changes)
    lines = [f"{len(changes)} change(s): " + ", ".join(f"{k} {counts[k]}" for k in ("critical", "high", "medium", "low") if counts[k])]
    for c in changes:
        tag = f"[{c.severity.upper():8}]"
        if color:
            tag = _COLORS[c.severity] + tag + _RESET
        lines.append(f"{tag} {c.kind:<11} {c.path}" + (f"  ({c.details})" if c.details else ""))
    return "\n".join(lines)


def cmd_check(args) -> int:
    key = load_key(args.key)
    try:
        old, payload = load_baseline(args.baseline, key)
    except BaselineError as exc:
        msg = str(exc)
        if args.format == "json":
            print(json.dumps({"status": "tampered", "error": msg}))
        else:
            alert = "ALERT:"
            if not args.no_color and sys.stderr.isatty():
                alert = _COLORS["critical"] + " ALERT " + _RESET
            print(f"{alert} {msg}", file=sys.stderr)
        if args.syslog:
            _syslog([], tampered=msg)
        return EXIT_TAMPERED

    policy = Policy(**payload["policy"])
    new, errors = scan(policy)
    changes = compare(old, new)

    if args.format == "json":
        print(json.dumps({
            "status": "changed" if changes else "ok",
            "baseline_created_at": payload["created_at"],
            "files_checked": len(new),
            "changes": [c.__dict__ for c in changes],
            "errors": errors,
        }, indent=2, ensure_ascii=False))
    else:
        print(f"Baseline from {payload['created_at']} ({len(old)} files), checked {len(new)} files")
        print(_render(changes, color=not args.no_color and sys.stdout.isatty()))
        for e in errors:
            print(f"warning: {e}", file=sys.stderr)
    if args.syslog and changes:
        _syslog(changes)
    return EXIT_CHANGES if changes else EXIT_OK


def cmd_update(args) -> int:
    """Accept the current state as the new baseline (after an approved change)."""
    key = load_key(args.key)
    old, payload = load_baseline(args.baseline, key)  # refuse to update a tampered baseline
    policy = Policy(**payload["policy"])
    new, _ = scan(policy)
    changes = compare(old, new)
    print(_render(changes, color=not args.no_color and sys.stdout.isatty()))
    if changes and not args.yes:
        if input("Accept these changes into the baseline? [y/N] ").strip().lower() != "y":
            print("Aborted.")
            return EXIT_CHANGES
    save_baseline(build_baseline(new, policy, key), args.baseline)
    print(f"Baseline updated: {len(new)} files.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="integrity-watch",
                                 description="File integrity monitoring with a tamper-evident (HMAC-signed) baseline.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p, need_policy=False):
        p.add_argument("--key", required=True, help="HMAC key file (keep it off the monitored host if possible)")
        p.add_argument("--baseline", default="baseline.json", help="baseline file (default: baseline.json)")
        p.add_argument("--no-color", action="store_true")
        if need_policy:
            p.add_argument("paths", nargs="*", help="files or directories to monitor")
            p.add_argument("--config", help="policy file (.json, or .toml on Python 3.11+)")
            p.add_argument("--exclude", action="append", help="glob pattern to exclude (repeatable)")
            p.add_argument("--algorithm", default="sha256", choices=["sha256", "sha512", "blake2b", "sha3_256"])

    p = sub.add_parser("keygen", help="generate a random 256-bit HMAC key")
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("init", help="scan and create a signed baseline")
    common(p, need_policy=True)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("check", help="verify the baseline signature and report changes")
    common(p)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--syslog", action="store_true", help="also send findings to syslog (authpriv) for SIEM collection")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("update", help="review changes and re-sign the baseline")
    common(p)
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_update)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (BaselineError, FileExistsError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_TAMPERED if isinstance(exc, BaselineError) else EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
