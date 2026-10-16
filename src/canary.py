#!/usr/bin/env python3
"""ci-canary-tokens — honeytokens for CI/CD pipelines.

A burglar alarm for your build pipelines. You generate canary credentials,
plant them as repo/org secrets (the exact place a GhostAction-style workflow
exfiltrator would steal them from), and commit the *registry* — which holds
only prefixes + hashes, never plaintext. A tripwire GitHub Action scans
workflow outputs/logs for any registered canary prefix; if a canary ever
shows up outside its secret vault, the build FAILS with an alert naming it.

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import secrets
import sys


VERSION = "1.0.0"

AWS_PREFIX = "AKIACANARY"      # identifiable canary marker inside a fake key
TOKEN_PREFIX = "ing_canary_"
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_value(kind: str) -> str:
    """Create one canary credential value (returned in plaintext ONCE)."""
    if kind == "aws":
        # Fake AWS-style access key ID: AKIA + CANARY marker + random tail.
        # Shape matches ^AKIA[0-9A-Z]{16}$ so naive exfiltrators grab it.
        return "AKIA" + "CANARY" + "".join(secrets.choice(_ALNUM) for _ in range(10))
    if kind == "token":
        return TOKEN_PREFIX + "".join(
            secrets.choice(_TOKEN_ALPHABET) for _ in range(32))
    raise ValueError(f"unknown kind: {kind!r}")


def prefix_of(kind: str) -> str:
    return {"aws": AWS_PREFIX, "token": TOKEN_PREFIX}[kind]


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_registry(path: str) -> dict:
    if not os.path.exists(path):
        return {"canaries": []}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_registry(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def register_canary(registry_path: str, name: str, kind: str) -> str:
    """Generate a canary, append prefix+hash to the registry, return plaintext."""
    value = generate_value(kind)
    data = load_registry(registry_path)
    data.setdefault("canaries", []).append({
        "name": name,
        "kind": kind,
        "prefix": prefix_of(kind),
        "sha256": sha256_hex(value),
        "created": utcnow(),
    })
    save_registry(registry_path, data)
    return value


def check_blob(registry_path: str, text: str, source: str = "<blob>") -> list[dict]:
    """Return list of fired canaries found in text: {name, prefix, source}."""
    fired = []
    for entry in load_registry(registry_path).get("canaries", []):
        if entry["prefix"] in text:
            fired.append({
                "name": entry["name"],
                "prefix": entry["prefix"],
                "kind": entry.get("kind", "?"),
                "source": source,
            })
    return fired


def cmd_generate(args: argparse.Namespace) -> int:
    value = register_canary(args.registry, args.name, args.kind)
    print("=" * 60)
    print("CANARY CREDENTIAL — shown ONCE. Plant it as a repo/org secret NOW,")
    print("then never store or commit this value anywhere.")
    print("=" * 60)
    print(value)
    print("=" * 60)
    print(f"Registered '{args.name}' ({args.kind}) in {args.registry}")
    print("Registry holds prefix + sha256 only — safe to commit.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    if args.blob:
        with open(args.blob, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        source = args.blob
    else:
        text = args.text or ""
        source = "<text>"
    fired = check_blob(args.registry, text, source)
    if fired:
        for f in fired:
            print(f"::error::CANARY TRIPWIRE FIRED — '{f['name']}' "
                  f"({f['kind']}) detected in {f['source']} "
                  f"(prefix '{f['prefix']}'). A planted secret leaked!")
        return 1
    print("Canary check clean — no registered canary prefixes found.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ci-canary-tokens: honeytokens for CI/CD pipelines.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = ap.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="Create a canary and register it")
    g.add_argument("--name", required=True, help="Canary name (e.g. ci-aws-canary-1)")
    g.add_argument("--kind", required=True, choices=["aws", "token"])
    g.add_argument("--registry", required=True, help="Path to canary registry JSON")
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser("check", help="Scan text for fired canaries")
    c.add_argument("--registry", required=True, help="Path to canary registry JSON")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument("--blob", help="File to scan (e.g. captured workflow log)")
    src.add_argument("--text", help="Raw text to scan")
    c.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
