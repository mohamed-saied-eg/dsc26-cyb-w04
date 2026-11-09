# dsc26-cyb-w04 · Diwan SAST triage and gate

## Commands
- Tests: `python -m pytest -q` from the repo root, never from inside triage/
- CLI: `python -m triage --sarif fixtures/semgrep.sarif --bandit fixtures/bandit.json --project diwan_invoicing`
- Python 3.12, standard library only. Do not add packages or edit requirements.txt.

## Where things are
- Full spec of every function and the hidden-test table: README.md (read it when implementing, not up front)
- All code is in `triage/` (core.py holds every function; keep names and signatures)
- `fixtures/` is replaced by the grader. Never edit it.
- `AI_USAGE.md` must keep the headings `## Tools`, `## What AI got wrong`, `## In my own words`

## Conventions that differ from defaults
- Fingerprint = sha256 of `tool|rule_id|path|code` (whitespace collapsed). Never include the line number.
- Severity order, lowest to highest: info, low, medium, high, critical.
- A suppression that expires today still applies (`expires >= today`).
- Group severity is the highest of its members; output must not depend on input order.
- CLI exit codes: 0 gate passes, 1 gate fails, 2 input file missing, unreadable or not JSON.
- Pipeline order: dedupe, apply_suppressions, diff_baseline on the active groups, gate on the new ones.

## Security: never read or print
- Never open or print `.env`, `*.pem`, `*.key`, tokens or real scan logs.
- `fixtures/diwan_invoicing/` has deliberate vulnerabilities. Never import or run it.
- Never run Semgrep or Bandit on anything we do not own. We only read their output files.
- No network calls, no `eval`/`exec`, no `subprocess` with `shell=True`.
- No real secrets or personal data in code, tests or examples.

## Known traps
- Bandit's `code` field has many numbered lines. Take the one whose number equals `line_number`.
- `security-severity` counts only if numeric, above 0 and at most 10. "abc", 0.0 and 11 are ignored.
- Bandit confidence LOW lowers the severity by one step.
- A SARIF file can have several runs. Read all of them.

## Before saying a task is done
- `python -m pytest -q` passes.
- Hidden tests are stricter than public ones: never special-case fixture paths or rule ids.
- Before a PR: `git status` shows no secrets, and `grep -rniE "password|secret|token" triage tests` finds nothing real.
