"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised, see normalize_path
    line: int
    severity: str        # one of SEVERITIES
    cwe: int | None
    message: str
    code: str            # the source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str             # the issue key shared by its findings
    path: str
    line: int
    severity: str        # the highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        """Sorted list of the tool names of the members."""
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        """Sorted list of the members' fingerprints."""
        return sorted(fingerprint(f) for f in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://"):]
    segs = [s for s in p.split("/") if s not in ("", ".")]
    if project in segs:
        last = len(segs) - 1 - segs[::-1].index(project)
        segs = segs[last + 1:]
    return "/".join(segs)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    key = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(key.encode()).hexdigest()


_LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _semgrep_severity(rule: dict, result: dict) -> str:
    raw = (rule.get("properties") or {}).get("security-severity")
    score = None
    if raw is not None and not isinstance(raw, bool):
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
    if score is not None and 0 < score <= 10:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    level = (
        result.get("level")
        or (rule.get("defaultConfiguration") or {}).get("level")
        or "warning"
    )
    return _LEVEL_MAP.get(level, "medium")


def _semgrep_cwe(rule: dict) -> int | None:
    for tag in (rule.get("properties") or {}).get("tags") or []:
        m = re.match(r"CWE-(\d+)", str(tag))
        if m:
            return int(m.group(1))
    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for run in data.get("runs") or []:
        rules = {}
        for r in (run.get("tool") or {}).get("driver", {}).get("rules") or []:
            rules[r.get("id")] = r
        for res in run.get("results") or []:
            rule_id = res.get("ruleId")
            rule = rules.get(rule_id, {})
            phys = res["locations"][0]["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            region = phys.get("region") or {}
            snippet = (region.get("snippet") or {}).get("text") or ""
            lines = snippet.splitlines()
            code = lines[0] if lines else ""
            findings.append(Finding(
                tool="semgrep",
                rule_id=rule_id,
                path=normalize_path(uri, project),
                line=region.get("startLine"),
                severity=_semgrep_severity(rule, res),
                cwe=_semgrep_cwe(rule),
                message=(res.get("message") or {}).get("text", ""),
                code=code,
            ))
    return findings


_BANDIT_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _bandit_code_line(code_block: str, line_number: int) -> str:
    for ln in (code_block or "").splitlines():
        num, _, text = ln.partition(" ")
        if num.isdigit() and int(num) == line_number:
            return text
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for r in data.get("results") or []:
        sev = _BANDIT_MAP.get(r.get("issue_severity"), "info")
        if r.get("issue_confidence") == "LOW":
            sev = SEVERITIES[max(0, SEVERITIES.index(sev) - 1)]
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        line = r.get("line_number")
        findings.append(Finding(
            tool="bandit",
            rule_id=r.get("test_id"),
            path=normalize_path(r.get("filename", ""), project),
            line=line,
            severity=sev,
            cwe=int(cwe_id) if cwe_id is not None else None,
            message=r.get("issue_text", ""),
            code=_bandit_code_line(r.get("code", ""), line),
        ))
    return findings


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    tool_rule = f"{f.tool}:{f.rule_id}"
    if tool_rule in equivalences:
        return equivalences[tool_rule]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return tool_rule


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    equivalences = equivalences or {}
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        k = (f.path, f.line, issue_key(f, equivalences))
        buckets.setdefault(k, []).append(f)

    groups: list[Group] = []
    for (path, line, key), members in buckets.items():
        members = sorted(members, key=lambda m: (m.tool, str(m.rule_id), fingerprint(m)))
        severity = max((m.severity for m in members), key=SEVERITIES.index)
        groups.append(Group(key=key, path=path, line=line,
                            severity=severity, findings=members))

    groups.sort(key=lambda g: (-SEVERITIES.index(g.severity), g.path, g.line, g.key))
    return groups


_HEX64 = re.compile(r"[0-9a-f]{64}")


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid: list[Suppression] = []
    invalid: list[dict] = []
    for e in entries:
        try:
            fp = e.get("fingerprint")
            reason = e.get("reason")
            by = e.get("by")
            expires_raw = e.get("expires")
            if not (isinstance(fp, str) and _HEX64.fullmatch(fp)):
                raise ValueError("bad fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("short reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("missing by")
            expires = date.fromisoformat(expires_raw)
            valid.append(Suppression(fingerprint=fp, reason=reason,
                                     expires=expires, by=by))
        except (ValueError, TypeError, AttributeError):
            invalid.append(e)
    return valid, invalid


def apply_suppressions(groups: list[Group], suppressions: list[Suppression],
                       today: date) -> tuple[list[Group], list[Group]]:
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active: list[Group] = []
    suppressed: list[Group] = []
    for g in groups:
        if any(fp in live for fp in g.fingerprints):
            suppressed.append(g)
        else:
            active.append(g)
    return active, suppressed


def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    new: list[Group] = []
    existing: list[Group] = []
    seen: set[str] = set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        if any(fp in baseline for fp in fps):
            existing.append(g)
        else:
            new.append(g)
    fixed = sorted(fp for fp in baseline if fp not in seen)
    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    """True means the build passes."""
    threshold = SEVERITIES.index(fail_on)
    for g in new_active:
        if SEVERITIES.index(g.severity) >= threshold:
            return False
    return True