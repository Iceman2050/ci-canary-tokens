#!/usr/bin/env python3
"""Tripwire runner for the ci-canary-tokens GitHub Action (action.yml).

Scans a provided text blob / log file for registered canary prefixes and
fails (exit 1) with an alert naming which canary fired and where.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from canary import check_blob  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="ci-canary-tokens tripwire")
    ap.add_argument("--registry", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--blob")
    g.add_argument("--text")
    args = ap.parse_args()

    if args.blob:
        with open(args.blob, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        source = args.blob
    else:
        text = args.text
        source = "<workflow-input>"

    fired = check_blob(args.registry, text, source)
    if fired:
        for f in fired:
            print(f"::error::CANARY TRIPWIRE FIRED — canary '{f['name']}' "
                  f"({f['kind']}) detected in {f['source']}. "
                  f"A planted CI secret was exfiltrated — investigate NOW.")
        print(f"::error::{len(fired)} canary(ies) fired. Failing the build.")
        return 1
    print("Canary tripwire: clean — no registered canary prefixes found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
