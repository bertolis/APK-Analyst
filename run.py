#!/usr/bin/env python3
"""CLI entry for the Step 1 extraction pipeline.

    python3 run.py APKs/CommsApp.apk
"""
from __future__ import annotations

import argparse

from apk_analyst.pipeline import analyze


def _print_report(s: dict) -> None:
    m = s["manifest"]
    print(f"\n=== {s['apk']['name']}  ({s['apk']['size_bytes'] // 1024} KB) ===")
    print(f"package     : {m['package']}  v{m['version_name']}  (sdk {m['min_sdk']}->{m['target_sdk']})")
    print(f"frameworks  : {', '.join(s['frameworks'])}")
    print(f"flags       : debuggable={m['debuggable']}  allowBackup={m['allow_backup']}  cleartext={m['uses_cleartext_traffic']}")
    print(f"dangerous   : {[p.split('.')[-1] for p in m['dangerous_permissions']] or 'none'}")
    print(f"exported    : {len(m['exported_components'])} component(s)")
    for c in m["exported_components"]:
        perm = c["permission"] or "no-permission"
        print(f"              - {c['kind']} {c['name'].split('.')[-1]} [{perm}] {[a.split('.')[-1] for a in c['intent_filters']]}")
    print(f"natives     : {len(s['natives'])} .so")
    for n in s["natives"]:
        extra = f"  urls={len(n['urls'])}" if n["urls"] else ""
        print(f"              - {n['path']}  ({n['size'] // 1024} KB){extra}")
    d = s["decompile"]
    print(f"jadx        : {'ok' if d['jadx']['ok'] else 'FAIL'}  {d['jadx']['file_count']} .java  {d['jadx']['note']}")
    print(f"apktool     : {'ok' if d['apktool']['ok'] else 'FAIL'}  {d['apktool']['file_count']} .smali  {d['apktool']['note']}")
    print(f"\nfull summary -> {s['summary_json']}")


def _print_ai_report(report) -> None:
    print(f"\n=== AI security analysis ===")
    print(report.summary)
    print(f"\n{len(report.findings)} finding(s):")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for fi in sorted(report.findings, key=lambda x: order.get(x.severity.value, 9)):
        print(f"\n[{fi.severity.value.upper()}] {fi.title}  ({fi.confidence.value})")
        print(f"  {fi.owasp_mobile.value} | {fi.cwe}")
        print(f"  where : {fi.location}")
        print(f"  why   : {fi.exploit_path}")
        print(f"  fix   : {fi.recommendation}")
        if fi.standards:
            print(f"  cites : {', '.join(fi.standards)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="APK security analyst pipeline")
    ap.add_argument("apk", nargs="?", help="path to .apk")
    ap.add_argument("-w", "--workspace", default="workspace")
    ap.add_argument("--ai", action="store_true", help="run Step 2 single-call AI analysis")
    ap.add_argument("--agent", action="store_true", help="run Step 3 agentic AI analysis (tool-driven)")
    ap.add_argument("--build-kb", action="store_true",
                    help="build the Step 4 RAG knowledge index, then exit")
    args = ap.parse_args()

    if args.build_kb:
        from apk_analyst.knowledge.build import build_index
        build_index()
        return

    if not args.apk:
        ap.error("apk path is required (unless using --build-kb)")

    summary = analyze(args.apk, args.workspace)
    _print_report(summary)

    import json as _json
    from pathlib import Path as _Path
    from apk_analyst.ai.analyst import report_to_dict

    if args.ai:
        from apk_analyst.ai.analyst import analyze_with_ai
        report = analyze_with_ai(summary)
        _print_ai_report(report)
        out = _Path(summary["workspace"]) / "ai_report.json"
        out.write_text(_json.dumps(report_to_dict(report), indent=2))
        print(f"\nAI report -> {out}")

    if args.agent:
        from apk_analyst.ai.agent import analyze_agentic
        print("\n=== Step 3: agentic investigation ===")
        result = analyze_agentic(summary)
        print(f"\n(investigated in {result.iterations} iterations, {len(result.tool_calls)} tool calls)")
        _print_ai_report(result.report)
        out = _Path(summary["workspace"]) / "agent_report.json"
        payload = report_to_dict(result.report)
        payload["_meta"] = {"iterations": result.iterations, "tool_calls": result.tool_calls}
        out.write_text(_json.dumps(payload, indent=2))
        print(f"\nAgent report -> {out}")


if __name__ == "__main__":
    main()
