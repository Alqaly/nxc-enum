"""Readable, evidence-linked summary of one NetExec enumeration run."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import json


def write_summary(out: Path, data: dict, decisions: list[dict]) -> dict:
    checks = [r for r in data.get("checks", []) if not r.get('historical')]
    historical_checks = sum(bool(r.get('historical')) for r in data.get('checks', []))
    current_hosts = {h:info for h,info in data.get('hosts', {}).items() if not info.get('historical')}
    analysis = data.get("analysis", {})
    grouped = defaultdict(list)
    for record in checks:
        grouped[(record["target"], record["protocol"])].append(record)
    module_groups = defaultdict(list)
    for decision in decisions:
        module_groups[(decision["target"], decision["protocol"])].append(decision)
    coverage = []
    for (host, protocol), records in sorted(grouped.items()):
        statuses = Counter(r["status"] for r in records)
        modules = module_groups[(host, protocol)]
        reasons = Counter(d["reason"] for d in modules if d["status"] != "attempted")
        coverage.append({"target": host, "protocol": protocol, "checks": dict(statuses),
                         "modules": dict(Counter(d["status"] for d in modules)),
                         "main_gaps": [{"reason": reason, "count": count} for reason, count in reasons.most_common(3)]})
    findings = [{k: f.get(k) for k in ("id", "priority", "target", "title", "confidence",
                 "status", "missing_prerequisites", "next_step", "evidence")}
                for f in analysis.get("findings", [])]
    result = {"schema_version": 1, "scope": "Observed evidence, not proof of exploitation or absence of exposure",
              "hosts_scanned": len(current_hosts), "historical_checks":historical_checks,
              "users_observed": len(data.get("users", [])),
              "candidate_paths": len(analysis.get("paths", [])), "loot_artifacts": len(analysis.get("loot", [])),
              "protocol_coverage": coverage, "findings": findings,
              "host_discovery": {h:{k:info.get(k) for k in ('discovery_coverage', 'protocol_endpoints', 'unsupported_services', 'capabilities', 'clock_observations')} for h,info in current_hosts.items()},
              "next_steps": analysis.get("next_steps", [])}
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    lines = ["# Scan summary", "", result["scope"], "",
             f"Hosts: {result['hosts_scanned']} · users observed: {result['users_observed']} · "
             f"candidate paths: {result['candidate_paths']} · loot artifacts: {result['loot_artifacts']}", "",
             "## Protocol coverage", "",
             "| Target | Protocol | Check results | Modules attempted / inventoried | Main limitation |",
             "|---|---|---|---|---|"]
    clean = lambda value: str(value).replace("|", r"\|").replace("\n", " ")
    for row in coverage:
        status = ", ".join(f"{k}: {v}" for k, v in sorted(row["checks"].items()))
        module_count = sum(row["modules"].values())
        attempted = sum(n for status,n in row['modules'].items() if status.startswith('attempted'))
        limitation = row["main_gaps"][0]["reason"] if row["main_gaps"] else "None recorded"
        lines.append("| " + " | ".join(map(clean, (row["target"], row["protocol"], status,
                     f"{attempted} / {module_count}", limitation))) + " |")
    lines += ["", f"Historical checks retained: {historical_checks}. These do not establish current access or current protocol coverage. Cached observations retain their original observation time; use `--refresh` for a new probe.", "", "## Discovery and access evidence", ""]
    for host, info in result['host_discovery'].items():
        lines.append(f"- {clean(host)}: {clean(info.get('discovery_coverage') or 'Port probing bypassed or simulated; reachability unverified')}")
        for service in info.get('unsupported_services') or []:
            lines.append(f"  - TCP/{service['port']} {clean(service.get('name', 'unknown'))}: external enumeration required.")
        for protocol, ports in (info.get('capabilities') or {}).items():
            for port, contexts in ports.items():
                for context in contexts:
                    lines.append(f"  - {clean(protocol)}:{clean(port)} {clean(context['effective_identity'])}: {clean(context['capability'])} ({clean(context['method'])}).")
    lines += ["", "Module counts describe the installed NetExec version. A completed command does not mean the module found an issue.", "",
              "## Findings to review", ""]
    if not findings:
        lines.append("No supported finding was extracted. Check authentication and coverage before drawing conclusions.")
    for finding in findings:
        evidence = finding.get("evidence") or []
        first = evidence[0] if evidence else {}
        source = first.get("source", "") if isinstance(first, dict) else ""
        lines += [f"### {clean(finding['priority'])} · {clean(finding['title'])}", "",
                  f"Target: {clean(finding['target'])} · confidence: {clean(finding['confidence'])}", "",
                  f"Still to verify: {clean('; '.join(finding.get('missing_prerequisites') or []) or 'Review the linked evidence and required context.')}", "",
                  f"Next: {clean(finding['next_step'])}", ""]
        if source:
            lines += [f"Evidence: `{clean(source)}`", ""]
    lines += ["## Next steps", ""]
    lines += [f"- {clean(x['priority'])}: {clean(x['action'])}" for x in result["next_steps"][:50]]
    if not result["next_steps"]:
        lines.append("- Review the protocol coverage table and raw logs for incomplete checks.")
    lines += ["", "Full command output: `report.html` · paths, findings and loot: `analysis.html` · "
              "every module decision: `module-applicability.json` · installed options: `module-options/`.", ""]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    return result
