#!/usr/bin/env python3
"""Stdlib-only acceptance checks for the Neo documentation submission."""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

NAMES = (
    "neo-action-security-architecture.md",
    "neo-action-threat-model.md",
    "neo-action-confirmation-policy.md",
)
ARCH, THREATS, POLICY = NAMES
WORD_LIMITS = {ARCH: (1800, 3500), THREATS: (450, 1500), POLICY: (500, 1000)}
HEADINGS = (
    "Summary", "Goals / Non-goals", "Trust boundaries & components",
    "Interfaces (JSON schemas)", "Taint & data flow", "Action Gate rules (G1–G12)",
    "Worked scenario (decision trace)", "Residual risk", "Rollout & build plan (by role)",
    "Open questions", "References",
)
REQUIRED_REFERENCES = (
    "Gen and xAI Partner to Build Trusted AI Assistants for Millions of Consumers",
    "Browsing Agent Prompt Injection: The Architecture Fix",
    "The Comprehensive Guide to Prompt Injection Attacks in 2026",
    "Meet Norton Neo: The First Safe AI-Native Browser Now in Early Access",
)
OVERCLAIMS = ("solves", "guarantee", "100%", "bulletproof", "fully prevents")


def words(text: str) -> int:
    """Count prose words; fenced code is intentionally excluded from page-length checks."""
    return len(re.findall(r"\b[\w][\w'-]*\b", markdown_text(text)))


def markdown_text(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.S)


def headings(text: str) -> set[str]:
    return {m.group(1).strip().lower() for m in re.finditer(r"^#{1,6}\s+(.+?)\s*$", text, re.M)}


def section_lines(text: str, title: str) -> list[str]:
    match = re.search(rf"^#{{1,6}}\s+{re.escape(title)}\b.*$", text, re.M | re.I)
    if not match:
        return []
    following = text[match.end():]
    following = re.split(r"^#{1,6}\s+", following, maxsplit=1, flags=re.M)[0]
    return [line for line in following.splitlines() if re.match(r"^\s*(?:[-*+] |\d+[.)] )", line)]


def section_text(text: str, title: str) -> str:
    match = re.search(rf"^#{{1,6}}\s+{re.escape(title)}\s*$", text, re.M | re.I)
    if not match:
        return ""
    return re.split(r"^#{1,6}\s+", text[match.end():], maxsplit=1, flags=re.M)[0]


def schema_names(text: str) -> tuple[set[str], bool]:
    found: set[str] = set()
    valid = True
    for block in re.findall(r"```json\s*(.*?)```", text, re.I | re.S):
        try:
            value = json.loads(block)
        except json.JSONDecodeError:
            valid = False
            continue
        def visit(node: object) -> None:
            if isinstance(node, dict):
                found.update(str(key) for key in node)
                for child in node.values(): visit(child)
            elif isinstance(node, list):
                for child in node: visit(child)
        visit(value)
    return found, valid


def run(docs_dir: Path, zip_path: Path) -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []
    present = {path.name for path in docs_dir.iterdir()} if docs_dir.is_dir() else set()
    results.append(("submission files", present == set(NAMES), f"found: {', '.join(sorted(present)) or 'none'}"))
    docs = {name: (docs_dir / name).read_text(encoding="utf-8") if (docs_dir / name).is_file() else "" for name in NAMES}
    for name, (low, high) in WORD_LIMITS.items():
        count = words(docs[name])
        results.append((f"word count: {name}", low <= count <= high, f"{count} (need {low}-{high})"))
    arch = docs[ARCH]
    actual_headings = headings(arch)
    missing = [heading for heading in HEADINGS if heading.lower() not in actual_headings]
    results.append(("architecture headings", not missing, "missing: " + ", ".join(missing) if missing else "all 11 present"))
    rule_rows = {int(x) for x in re.findall(r"^\s*\|\s*\*{0,2}G(\d{1,2})\b", section_text(arch, HEADINGS[5]), re.I | re.M)}
    results.append(("G1-G12 rule table", rule_rows == set(range(1, 13)), f"rows: {sorted(rule_rows)}"))
    trace = section_text(arch, HEADINGS[6])
    trace_steps = {int(x) for x in re.findall(r"^\s*\|\s*(\d+)\s*\|", trace, re.M)}
    trace_lines = [line for line in trace.splitlines() if re.match(r"^\s*\|\s*\d+\s*\|", line)]
    denies = {int(rule) for line in trace_lines if re.search(r"\bDENY\b", line, re.I) for rule in re.findall(r"\bG(\d+)\b", line, re.I)}
    results.append(("decision trace", len(trace_steps) >= 8 and {2, 3, 4, 5} <= denies,
                    f"numbered rows={len(trace_steps)}, DENY rules={sorted(denies)}"))
    schemas, valid_json = schema_names(arch)
    required_schemas = {"IntentContract", "AffordanceEntry", "Action", "GateDecision"}
    results.append(("JSON schemas", valid_json and required_schemas <= schemas,
                    "invalid JSON block" if not valid_json else ("missing: " + ", ".join(sorted(required_schemas - schemas)) if required_schemas - schemas else "parsed")))
    threat = docs[THREATS]
    threat_rows = []
    for line in threat.splitlines():
        cells = [re.sub(r"[*`]", "", cell.strip()) for cell in line.strip().strip("|").split("|")]
        if cells and re.fullmatch(r"T\d+", cells[0], re.I):
            verdicts = [cell for cell in cells if cell.lower() in {"stopped", "reduced", "accepted"}]
            threat_rows.append((cells[0], verdicts[0] if verdicts else "", line))
    threat_ids = {ident.upper() for ident, _, _ in threat_rows}
    valid_rows = all(verdict and re.search(r"\bG\d+\b", row, re.I) for _, verdict, row in threat_rows)
    accepted = sum(verdict.lower() == "accepted" for _, verdict, _ in threat_rows)
    results.append(("threat table", len(threat_ids) >= 12 and valid_rows and accepted >= 2,
                    f"T rows={len(threat_ids)}, Accepted={accepted}, rules valid={valid_rows}"))
    all_text = "\n".join(docs.values())
    cited_g = {int(x) for x in re.findall(r"\bG(\d+)\b", all_text, re.I)}
    cited_t_policy = {x.upper() for x in re.findall(r"\b(T\d+)\b", docs[POLICY], re.I)}
    results.append(("cross references", cited_g <= rule_rows and cited_t_policy <= threat_ids,
                    f"unknown G={sorted(cited_g - rule_rows)}, unknown T={sorted(cited_t_policy - threat_ids)}"))
    counts = []
    valid_examples = True
    for section, minimum in (("Autonomous", 6), ("CONFIRM", 6), ("DENY", 3)):
        lines = section_lines(docs[POLICY], section)
        counts.append(f"{section}={len(lines)}")
        valid_examples &= len(lines) >= minimum and all(re.search(r"\bG\d+\b", line, re.I) and re.search(r"\bT\d+\b", line, re.I) for line in lines)
    results.append(("confirmation policy examples", valid_examples, ", ".join(counts) + "; every example needs G and T"))
    absent_refs = [title for title in REQUIRED_REFERENCES if title.lower() not in all_text.lower()]
    results.append(("supplied reference titles", not absent_refs, "missing: " + ", ".join(absent_refs) if absent_refs else "all four cited"))
    plain = markdown_text(all_text).lower()
    bad_overclaims = []
    for phrase in OVERCLAIMS:
        pattern = rf"\b{re.escape(phrase)}\b" if phrase != "100%" else re.escape(phrase)
        for match in re.finditer(pattern, plain, re.I):
            context = plain[max(0, match.start() - 40):match.start()]
            if not re.search(r"(?:does not|do not|never|cannot|can't|won't)\s+(?:\w+\s+){0,2}$", context):
                bad_overclaims.append(phrase)
                break
    results.append(("no overclaims", not bad_overclaims, "found: " + ", ".join(bad_overclaims) if bad_overclaims else "clear"))
    placeholders = re.findall(r"\b(?:TODO|TBD|lorem)\b", all_text, re.I)
    results.append(("no placeholders", not placeholders, "found: " + ", ".join(placeholders) if placeholders else "clear"))
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = archive.namelist()
            exact = len(members) == len(set(members)) and set(members) == set(NAMES) and all("/" not in member and "\\" not in member for member in members)
            bytes_match = exact and all(archive.read(name) == (docs_dir / name).read_bytes() for name in NAMES)
            results.append(("ZIP contents and bytes", exact and bytes_match,
                            f"members: {', '.join(members) or 'none'}; bytes match={bytes_match}"))
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        results.append(("ZIP contents and bytes", False, str(error)))
    return results


def main() -> int:
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs-dir", type=Path, default=base / "submission")
    parser.add_argument("--zip-path", type=Path, default=base / "neo-action-security-architecture.zip")
    args = parser.parse_args()
    results = run(args.docs_dir, args.zip_path)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
