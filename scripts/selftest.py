#!/usr/bin/env python3
"""selftest.py - check a generated remediation package against the quality rubric.

Usage: python3 scripts/selftest.py <output_dir> [--org org.csv] [--raci routing/raci_matrix.yaml]
Exit code 0 when every check passes. Standard library only. License: MIT.
"""
import argparse, csv, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediation_pack import load_yaml, sev_from_score, ROOT  # noqa: E402

ATTACK_RE = re.compile(r"^T[01]\d{3}(\.\d{3})?$")
WSTG_RE = re.compile(r"^WSTG-v\d{2}-[A-Z]{4}-\d{2}$")
D3_RE = re.compile(r"^D3-[A-Z0-9]+$")
DD_SEV = {"Info", "Low", "Medium", "High", "Critical"}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("out"); ap.add_argument("--org")
    ap.add_argument("--raci", default=os.path.join(ROOT, "routing", "raci_matrix.yaml")); ap.add_argument("--max-title", type=int, default=80)
    a = ap.parse_args()
    raci = load_yaml(a.raci); depts = set(raci["departments"])
    org = {r["dept_code"] for r in csv.DictReader(open(a.org, encoding="utf-8"))} if a.org else None
    checks = []; fails = []; warns = set()
    def check(rule, ok, msg):
        checks.append(rule)
        if not ok: fails.append(f"[{rule}] {msg}")

    req = ["report.md", "findings.json", "findings.csv", "jira_import.csv", "servicenow_import.json", "defectdojo_generic.json"]
    for r in req: check("R9-files", os.path.exists(os.path.join(a.out, r)), f"missing {r}")
    data = json.load(open(os.path.join(a.out, "findings.json"), encoding="utf-8"))
    F = data["findings"]
    tickets = []
    for fn in sorted(os.listdir(os.path.join(a.out, "tickets"))):
        if fn.endswith(".json"): tickets += json.load(open(os.path.join(a.out, "tickets", fn), encoding="utf-8"))
        if fn.endswith(".csv"): list(csv.DictReader(open(os.path.join(a.out, "tickets", fn), encoding="utf-8")))
    by_finding = {}
    for t in tickets: by_finding.setdefault(t["finding_id"], []).append(t)

    for f in F:
        fid = f["id"]; rc = f["raci"]
        check("R1-owner", len(rc["R"]) >= 1 and all(d in depts for d in rc["R"]), f"{fid} has no valid Responsible")
        check("R1-owner", isinstance(rc["A"], str) and rc["A"] in depts, f"{fid} needs exactly one Accountable")
        check("R2-sla", f.get("sla_days") and re.match(r"^\d{4}-\d{2}-\d{2}$", f.get("due_date", "")), f"{fid} missing SLA/due date")
        check("R3-attack", f["attack"] and all(ATTACK_RE.match(t) for t in f["attack"]), f"{fid} bad ATT&CK IDs {f['attack']}")
        check("R3-d3fend", all(D3_RE.match(t) for t in f["d3fend"]), f"{fid} bad D3FEND IDs")
        if f["domain"] == "appsec":
            check("R4-wstg", f["wstg"] and all(WSTG_RE.match(w) for w in f["wstg"]), f"{fid} web finding without valid WSTG ID")
        check("R5-fix", len(f["fix"]) >= 2, f"{fid} fewer than 2 fix steps")
        check("R5-verify", len(f["verify"]) >= 1, f"{fid} no verification step")
        check("R6-impact", len(f.get("business_impact", "")) > 40, f"{fid} business impact missing")
        check("R6-cvss", str(f["cvss4_vector"]).startswith("CVSS:4.0/") and 0 <= float(f["cvss4_score"]) <= 10, f"{fid} invalid CVSS v4")
        check("R6-cvss", sev_from_score(f["cvss4_score"]) == f["severity"], f"{fid} severity does not match score")
        ts = by_finding.get(fid, [])
        check("R7-ticket", any(t["type"] == "fix" for t in ts), f"{fid} has no fix ticket")
        if f["priority"] in ("P1", "P2") and rc["detect"] not in ("none", None) and rc["detect"] not in rc["R"]:
            check("R7-detect", any(t["type"] == "detection" for t in ts), f"{fid} P1/P2 without interim detection ticket")
        if f["asset"]["zone"] == "OT":
            check("R10-ot", rc["R"] == ["OT-ENG"] and any("MOC" in n or "Management of Change" in n for n in f["routing_notes"]), f"{fid} OT finding not routed to OT-ENG with MOC note")
        if "personal" in (f["asset"]["data_classification"] or "").lower():
            check("R11-dpo", "GRC-DPO" in rc["C"] + rc["I"] + rc["R"], f"{fid} personal data but DPO not involved")
        check("R13-title", len(f["title"]) <= a.max_title and not re.search(r"\b\w\s\(", f["title"][-14:]), f"{fid} title too long or cut ({f['title']})")
        check("R14-why", f.get("why", "").startswith(f["priority"]), f"{fid} missing plain-language priority rationale")
        if f["kev"]:
            check("R15-kev-policy", f["priority"] in ("P1", "P2"), f"{fid} is in KEV but ranked {f['priority']}")
        if f["cves"] and data.get("kev_catalog_version"):
            check("R16-enrichment", f["epss"] is not None or f["kev"], f"{fid} has CVEs but no EPSS/KEV enrichment")
        elif f["cves"]:
            warns.add("R16-enrichment: KEV/EPSS not loaded for this run (offline without snapshots)")
    order = [(int(f["priority"][1]), -f["risk_score"]) for f in F]
    check("R17-order", order == sorted(order) or all(order[i][0] <= order[i + 1][0] for i in range(len(order) - 1)), "findings not sorted by priority")
    fmap = {f["id"]: f for f in F}
    for t in tickets:
        if t["finding_id"] in fmap:
            check("R18-due", t["due_date"] <= fmap[t["finding_id"]]["due_date"], f"{t['ticket_id']} due after its finding SLA")
        check("R8-ticket", t["department"] in depts and (org is None or t["department"] in org), f"{t['ticket_id']} unknown department")
        check("R8-ticket", len(t["steps"]) >= 1 and len(t["verify"]) >= 1 and t["due_date"], f"{t['ticket_id']} incomplete")
    for d in {t["department"] for t in tickets}:
        check("R8-ticket", os.path.exists(os.path.join(a.out, "tickets", d + ".md")), f"missing tickets/{d}.md")
    check("R8-mgmt", any(t["type"] == "governance" for t in tickets) or not any(f["priority"] in ("P1", "P2") for f in F), "no management approval ticket")

    jira = list(csv.reader(open(os.path.join(a.out, "jira_import.csv"), encoding="utf-8")))
    check("R9-jira", jira[0][:3] == ["Summary", "Issue Type", "Priority"] and len(jira) - 1 == len(tickets), "Jira CSV header/row count")
    sn = json.load(open(os.path.join(a.out, "servicenow_import.json"), encoding="utf-8"))["records"]
    check("R9-snow", len(sn) == len(tickets) and all(r["assignment_group"] and r["urgency"] in (1, 2, 3) for r in sn), "ServiceNow records")
    dd = json.load(open(os.path.join(a.out, "defectdojo_generic.json"), encoding="utf-8"))["findings"]
    check("R9-dojo", len(dd) == len(F) and all(x["severity"] in DD_SEV and x["title"] and x["description"] for x in dd), "DefectDojo generic findings")
    nav = os.path.join(a.out, "navigator")
    for fn in os.listdir(nav):
        layer = json.load(open(os.path.join(nav, fn)))
        check("R9-nav", layer["versions"]["layer"] and layer["domain"] in ("enterprise-attack", "ics-attack", "mobile-attack") and layer["techniques"], f"bad layer {fn}")
    for root, _, files in os.walk(a.out):
        for fn in files:
            if fn.endswith(".md"):
                txt = open(os.path.join(root, fn), encoding="utf-8").read()
                check("R12-placeholders", "{{" not in txt, f"unresolved placeholder in {fn}")

    total = len(checks); passed = total - len(fails)
    rules = sorted(set(checks)); bad = sorted({f.split("]")[0][1:] for f in fails})
    print(f"Rubric: {passed}/{total} checks passed across {len(rules)} rules; {len(F)} findings, {len(tickets)} tickets.")
    for r in rules: print(f"  {'FAIL' if r in bad else 'ok  '} {r}")
    for f in fails[:40]: print("   - " + f)
    for w in sorted(warns): print("  WARN " + w)
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
