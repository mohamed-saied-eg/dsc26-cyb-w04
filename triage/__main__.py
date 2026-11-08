"""python -m triage --sarif S --bandit B --project NAME [...]"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from .core import (
    SEVERITIES,
    apply_suppressions,
    dedupe,
    diff_baseline,
    gate,
    load_bandit,
    load_semgrep_sarif,
    load_suppressions,
)


def _iso_date(s: str) -> date:
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date: {s}")


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _group_to_dict(g) -> dict:
    return {
        "key": g.key,
        "path": g.path,
        "line": g.line,
        "severity": g.severity,
        "tools": g.tools,
        "fingerprints": g.fingerprints,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today", type=_iso_date, default=None)
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES)
    args = ap.parse_args(argv)

    today = args.today or date.today()

    try:
        findings = load_semgrep_sarif(args.sarif, args.project)
        findings += load_bandit(args.bandit, args.project)

        equivalences = {}
        if args.equivalences:
            equivalences = _read_json(args.equivalences)
            if not isinstance(equivalences, dict):
                raise ValueError("equivalences must be a JSON object")

        baseline = set()
        if args.baseline:
            data = _read_json(args.baseline)
            if not isinstance(data, list):
                raise ValueError("baseline must be a JSON list")
            baseline = set(data)

        entries = []
        if args.suppressions:
            entries = _read_json(args.suppressions)
            if not isinstance(entries, list):
                raise ValueError("suppressions must be a JSON list")
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return 2

    groups = dedupe(findings, equivalences)
    valid, invalid = load_suppressions(entries)
    active, suppressed = apply_suppressions(groups, valid, today)
    new, existing, fixed = diff_baseline(active, baseline)
    passed = gate(new, args.fail_on)

    out = {
        "passed": passed,
        "new": [_group_to_dict(g) for g in new],
        "existing": [_group_to_dict(g) for g in existing],
        "suppressed": [_group_to_dict(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }
    print(json.dumps(out, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())