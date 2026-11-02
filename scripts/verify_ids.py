#!/usr/bin/env python3
"""Check that every identifier in knowledge/catalog.json exists in the official data.

Reference data is NOT shipped in this repo (licensing and size). Fetch it once:
  ATT&CK enterprise + ICS STIX bundles : github.com/mitre-attack/attack-stix-data
  D3FEND                                : d3fend.mitre.org/api/technique/all.json
  WSTG checklist                        : github.com/OWASP/wstg (checklists/checklist.json)
Then build {id: name} maps (see --build) and run:
  python3 scripts/verify_ids.py --refdata /path/to/refdata
Exit code 1 if any identifier is unknown or deprecated.
"""
import argparse, json, os, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# WSTG v4.2 Input Validation section (INPV-01..19) is missing from some checklist exports, so it is allow-listed.
WSTG_ALLOW = {f"WSTG-INPV-{i:02d}" for i in range(1, 20)}

def build(refdata):
    """Turn raw downloads (enterprise.json, ics.json, d3fend.json, wstg_checklist.json) into *_ids.json maps."""
    for dom in ("enterprise", "ics"):
        b = json.load(open(refdata / f"{dom}.json", encoding="utf-8"))
        ids = {}
        for o in b["objects"]:
            if o.get("type") not in ("attack-pattern", "course-of-action") or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            for r in o.get("external_references", []):
                if r.get("source_name") in ("mitre-attack", "mitre-ics-attack") and r.get("external_id"):
                    ids[r["external_id"]] = o.get("name", "")
        json.dump(ids, open(refdata / f"{dom}_ids.json", "w"), indent=0)
    print("built", ", ".join(p.name for p in refdata.glob("*_ids.json")))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refdata", default=os.environ.get("REFDATA", str(ROOT.parent / "_refdata")))
    ap.add_argument("--catalog", default=str(ROOT / "knowledge" / "catalog.json"))
    ap.add_argument("--build", action="store_true")
    a = ap.parse_args(); ref = Path(a.refdata)
    if a.build: build(ref)
    load = lambda n: json.load(open(ref / f"{n}_ids.json", encoding="utf-8"))
    attack = {**load("enterprise"), **load("ics")}; d3f = load("d3fend"); wstg = set(load("wstg")) | WSTG_ALLOW
    cat = json.load(open(a.catalog, encoding="utf-8"))["categories"]
    bad, n = [], 0
    for key, c in cat.items():
        for t in c.get("attack", []) + c.get("attack_mitigations", []):
            n += 1
            if t not in attack: bad.append(f"{key}: ATT&CK {t} not found (or deprecated) in v20 data")
        for d in c.get("d3fend", []):
            n += 1
            if d not in d3f and d.replace("D3-", "D3A-") not in d3f: bad.append(f"{key}: D3FEND {d} not found")
        for w in c.get("wstg", []):
            n += 1; base = re.sub(r"^WSTG-v\d+-", "WSTG-", w)
            if base not in wstg: bad.append(f"{key}: WSTG {w} not found")
    print(f"verify_ids: {n - len(bad)}/{n} identifiers valid across {len(cat)} categories")
    for b in bad: print("  FAIL " + b)
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
