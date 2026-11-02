#!/usr/bin/env python3
"""
remediation_pack.py - turn raw security test output into a ready-to-apply,
department-routed remediation package.

Inputs : nmap XML, Nessus (.nessus), OWASP ZAP XML report, Burp Suite issues XML,
         generic findings CSV,
         asset inventory CSV, department/org CSV, RACI matrix YAML,
         optional KEV / EPSS snapshots (or --online to fetch them).
Outputs: report.md, findings.json/.csv, per-department tickets (.md/.csv/.json),
         jira_import.csv, servicenow_import.json, defectdojo_generic.json,
         ATT&CK Navigator layers, retest plan and (with --baseline) a retest delta.

Python 3.9+ standard library only. Optional: PyYAML (YAML parsing),
`cvss` package (recompute CVSS v4 scores from vectors).
License: MIT.
"""
import argparse, csv, datetime as dt, hashlib, json, os, re, sys, urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SCANNED = set()   # (tool, host key) pairs covered by this run, used for honest retest deltas
SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
PRIO_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
DECISION_TO_PRIO = {"ACT": "P1", "ATTEND": "P2", "TRACK*": "P3", "TRACK": "P4"}
JIRA_PRIO = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}
SNOW_UI = {"P1": (1, 1), "P2": (2, 1), "P3": (2, 2), "P4": (3, 3)}  # (urgency, impact)

# ------------------------------------------------------------------ i18n labels
L = {
 "en": dict(id="ID", title="Finding", prio="Priority", sev="Severity", cvss="CVSS v4", epss="EPSS", kev="KEV",
            asset="Asset", owner="Responsible", due="Due", attack="ATT&CK", dept="Department", tickets="Tickets",
            p1="P1", open_="Open", status="Status", yes="yes", no="no",
            exec1="{n} findings across {h} assets were consolidated from {s} sources. {p1} need action within 3 days (P1) and {p2} within the next SLA window (P2).",
            exec2="{k} findings involve vulnerabilities on the CISA KEV list (exploited in the wild). {ot} findings affect the OT / plant zone and are routed to OT Engineering under Management of Change.",
            exec3="Work is distributed to {d} departments as {t} tickets. The largest fix workload sits with {top}; the SOC also receives interim detection tickets for every open P1/P2.",
            fix="Fix steps", verify="Verification / retest", detect="Interim detection", impact="Business impact",
            refs="References", evidence="Evidence", raci="RACI", context="Context"),
 "es": dict(id="ID", title="Hallazgo", prio="Prioridad", sev="Severidad", cvss="CVSS v4", epss="EPSS", kev="KEV",
            asset="Activo", owner="Responsable", due="Vence", attack="ATT&CK", dept="Departamento", tickets="Tickets",
            p1="P1", open_="Abierto", status="Estado", yes="sí", no="no",
            exec1="Se consolidaron {n} hallazgos en {h} activos a partir de {s} fuentes. {p1} requieren acción en 3 días (P1) y {p2} en la siguiente ventana de SLA (P2).",
            exec2="{k} hallazgos implican vulnerabilidades del catálogo CISA KEV (explotadas activamente). {ot} hallazgos afectan a la zona OT / planta y se asignan a Ingeniería OT bajo Gestión del Cambio (MOC).",
            exec3="El trabajo se reparte entre {d} departamentos en {t} tickets. La mayor carga de corrección recae en {top}; el SOC recibe además tickets de detección provisional para cada P1/P2 abierto.",
            fix="Pasos de corrección", verify="Verificación / retest", detect="Detección provisional", impact="Impacto de negocio",
            refs="Referencias", evidence="Evidencia", raci="RACI", context="Contexto"),
 "pt-BR": dict(id="ID", title="Achado", prio="Prioridade", sev="Severidade", cvss="CVSS v4", epss="EPSS", kev="KEV",
            asset="Ativo", owner="Responsável", due="Prazo", attack="ATT&CK", dept="Departamento", tickets="Tickets",
            p1="P1", open_="Aberto", status="Status", yes="sim", no="não",
            exec1="{n} achados em {h} ativos foram consolidados a partir de {s} fontes. {p1} exigem ação em 3 dias (P1) e {p2} na próxima janela de SLA (P2).",
            exec2="{k} achados envolvem vulnerabilidades do catálogo CISA KEV (exploradas ativamente). {ot} achados afetam a zona OT / planta e foram roteados para Engenharia OT sob Gestão de Mudança (MOC).",
            exec3="O trabalho foi distribuído para {d} departamentos em {t} tickets. A maior carga de correção está com {top}; o SOC também recebe tickets de detecção provisória para cada P1/P2 aberto.",
            fix="Passos de correção", verify="Verificação / reteste", detect="Detecção provisória", impact="Impacto no negócio",
            refs="Referências", evidence="Evidência", raci="RACI", context="Contexto"),
}

# ------------------------------------------------------------------ tiny YAML
def _scalar(v):
    v = v.strip()
    if v == "" : return None
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [] if not inner else [_scalar(x) for x in inner.split(",")]
    if v in ("true", "True"): return True
    if v in ("false", "False"): return False
    if (v[0] == v[-1]) and v[0] in "'\"": return v[1:-1]
    try: return int(v)
    except ValueError: pass
    try: return float(v)
    except ValueError: return v

def load_yaml(path):
    """Minimal YAML subset: nested maps by indentation, inline lists, comments."""
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as fh: return yaml.safe_load(fh)
    except ImportError:
        pass
    root = {}; stack = [(-1, root)]
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split(" #")[0].rstrip() if not raw.lstrip().startswith("#") else ""
            if not line.strip(): continue
            indent = len(line) - len(line.lstrip(" "))
            key, _, val = line.strip().partition(":")
            while stack and indent <= stack[-1][0]: stack.pop()
            parent = stack[-1][1]
            if val.strip() == "":
                parent[key] = {}; stack.append((indent, parent[key]))
            else:
                parent[key] = _scalar(val)
    return root

# ------------------------------------------------------------------ helpers
def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [{k.strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(fh)]

def sev_from_score(s):
    if s is None: return "None"
    s = float(s)
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else "None"

def cvss4_score(vector, fallback):
    try:
        from cvss import CVSS4  # optional, LGPL-3.0, imported not vendored
        return float(CVSS4(vector).base_score)
    except Exception:
        return fallback

def fingerprint(cat, host, port, url):
    """Stable identity of a finding across runs: one finding per category per service/URL."""
    raw = "|".join([cat, (host or "").lower(), str(port or ""), (url or "").split("?")[0].lower()])
    return hashlib.sha1(raw.encode()).hexdigest()[:10]

def short_title(cat, product, cves):
    head = f"{cves[0]}" + (f" +{len(cves) - 1} more" if len(cves) > 1 else "")
    name = "SMBv1 / MS17-010" if cat == "legacy-smb" else product
    return f"{clip(name, 40)}: {head}"

def clip(text, n):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n - 1].rsplit(" ", 1)[0] + "…"

def fmt_epss(v):
    return "-" if v is None else f"{v:.2f}"

def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "si", "sim", "sí")

# ------------------------------------------------------------------ parsers
def parse_nmap(path, catalog, assets, source_zone):
    out = []
    tree = ET.parse(path)
    for h in tree.getroot().iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up": continue
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        hn = h.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else ""
        asset = lookup_asset(assets, ip, hostname)
        SCANNED.add(("nmap", host_key(asset, ip, hostname)))
        for p in h.iter("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open": continue
            port = int(p.get("portid")); proto = p.get("protocol")
            svc = p.find("service")
            svcname = svc.get("name", "") if svc is not None else ""
            product = " ".join(x for x in [svc.get("product", ""), svc.get("version", "")] if x).strip() if svc is not None else ""
            scripts = {s.get("id"): s.get("output", "") for s in p.findall("script")}
            base = dict(source="nmap", host=hostname or ip, ip=ip, port=port, proto=proto,
                        service=f"{svcname} {product}".strip(), asset=asset)
            # 1. CVEs reported by NSE scripts (vulners, smb-vuln-*)
            for sid, outp in scripts.items():
                cves = sorted(set(CVE_RE.findall(outp)))
                if not cves: continue
                if sid.startswith("smb-vuln") and "VULNERABLE" not in outp: continue
                cat = "legacy-smb" if sid.startswith("smb-vuln") else "vulnerable-software"
                out.append(dict(base, category=cat, cves=cves[:15],
                                title=short_title(cat, product or svcname, cves), auto_title=(cat, product or svcname),
                                evidence=f"nmap NSE {sid}: " + outp.strip().replace("\n", " | ")[:400],
                                exploit_available="*EXPLOIT*" in outp))
            # 2. Port based rules
            for rule in catalog["nmap_port_rules"]:
                if port not in rule["ports"]: continue
                if not rule_applies(rule.get("when"), asset, scripts, source_zone): continue
                cat = rule["category"]
                if cat == "legacy-smb" and any(f["category"] == "legacy-smb" and f["ip"] == ip for f in out): continue
                out.append(dict(base, category=cat, cves=[],
                                title=f"{rule['label']} exposed on {port}/{proto}" + (" (unauthenticated read)" if cat == "snmp-weak-community" else ""),
                                evidence=f"nmap: {port}/{proto} open, service '{svcname} {product}'".strip()
                                         + (" | " + " | ".join(f"{k}: {v.strip()[:160]}" for k, v in scripts.items()) if scripts else ""),
                                exploit_available=False))
    return out

def rule_applies(when, asset, scripts, source_zone):
    if not when: return True
    for cond in when.split("|"):
        if cond == "internet_facing" and asset["internet_facing"]: return True
        if cond == "not_ot_source" and source_zone.upper() != "OT": return True
        if cond.startswith("script:"):
            parts = cond.split(":", 2)
            sid = parts[1]; needle = parts[2] if len(parts) > 2 else None
            if sid in scripts and (needle is None or needle in scripts[sid]): return True
    return False

def parse_nessus(path, catalog, assets):
    out = []
    for rh in ET.parse(path).getroot().iter("ReportHost"):
        name = rh.get("name")
        props = {t.get("name"): t.text for t in rh.findall("HostProperties/tag")}
        ip = props.get("host-ip", name)
        asset = lookup_asset(assets, ip, props.get("host-fqdn", name))
        SCANNED.add(("nessus", host_key(asset, ip, name)))
        for it in rh.findall("ReportItem"):
            sev = int(it.get("severity", "0"))
            if sev == 0: continue
            pname = it.get("pluginName", "")
            cves = sorted(set(c.text for c in it.findall("cve") if c.text))
            low = pname.lower()
            if "smb" in low: cat = "legacy-smb"
            elif "ssl" in low or "tls" in low: cat = "weak-tls"
            elif "default" in low and ("password" in low or "credential" in low): cat = "default-credentials"
            elif "telnet" in low or "cleartext" in low or "ftp" in low: cat = "cleartext-protocol"
            elif "snmp" in low: cat = "snmp-weak-community"
            elif cves: cat = "vulnerable-software"
            else: cat = "vulnerable-software"
            vec = (it.findtext("cvss4_vector") or "").strip()
            sc = it.findtext("cvss4_base_score")
            out.append(dict(source="nessus", host=name, ip=ip, port=int(it.get("port", "0")), proto=it.get("protocol"),
                            service=it.get("svc_name", ""), asset=asset, category=cat, cves=cves,
                            title=pname, evidence=("Nessus plugin " + it.get("pluginID", "") + ": " + (it.findtext("plugin_output") or "").strip())[:400],
                            exploit_available=(it.findtext("exploit_available") or "").lower() == "true",
                            cvss4_vector=("CVSS:4.0/" + vec) if vec and not vec.startswith("CVSS:4.0") else vec or None,
                            cvss4_score=float(sc) if sc else None, tool_solution=(it.findtext("solution") or "").strip()))
    return out

def parse_zap(path, catalog, assets):
    out = []
    rules = catalog["zap_plugin_rules"]
    cwe_map = {"89": "web-injection", "78": "web-injection", "79": "web-xss", "639": "broken-access-control",
               "200": "sensitive-data-exposure", "693": "security-misconfiguration-web", "614": "security-misconfiguration-web",
               "1004": "security-misconfiguration-web", "319": "weak-tls"}
    for site in ET.parse(path).getroot().iter("site"):
        host = site.get("host"); asset = lookup_asset(assets, None, host)
        SCANNED.add(("zap", host_key(asset, None, host)))
        for a in site.iter("alertitem"):
            risk = int(a.findtext("riskcode", "0"))
            if risk == 0: continue
            pid = a.findtext("pluginid", ""); cwe = a.findtext("cweid", "")
            cat = rules.get(pid) or cwe_map.get(cwe, "security-misconfiguration-web")
            uris = [i.findtext("uri") for i in a.iter("instance")]
            attacked = any((i.findtext("attack") or "").strip() for i in a.iter("instance"))
            confirmed = attacked and risk >= 3 and int(a.findtext("confidence", "0")) >= 2
            ev = [i.findtext("evidence") or i.findtext("param") or "" for i in a.iter("instance")]
            out.append(dict(source="zap", host=host, ip=None, port=int(site.get("port", "443")), proto="tcp",
                            service="https" if site.get("ssl") == "true" else "http", asset=asset, category=cat, cves=[],
                            url=uris[0] if uris else "", cwe=[int(cwe)] if cwe.isdigit() and int(cwe) > 0 else None,
                            title=f"{a.findtext('alert')}" + (f" ({len(uris)} URLs)" if len(uris) > 1 else ""),
                            evidence=f"ZAP plugin {pid}, risk {risk}: " + "; ".join(u for u in uris[:3] if u) + (f" | evidence: {ev[0][:120]}" if ev and ev[0] else ""),
                            exploit_available=confirmed))
    return out

BURP_TYPES = {"1049088": "web-injection", "1048832": "web-injection", "2097920": "web-xss", "2097936": "web-xss", "2097408": "web-xss"}
BURP_WORDS = [("sql injection", "web-injection"), ("command injection", "web-injection"), ("cross-site scripting", "web-xss"),
              ("access control", "broken-access-control"), ("idor", "broken-access-control"), ("cookie", "security-misconfiguration-web"),
              ("header", "security-misconfiguration-web"), ("tls", "weak-tls"), ("ssl", "weak-tls"), ("disclosure", "sensitive-data-exposure")]

def parse_burp(path, catalog, assets):
    """Burp Suite 'Report issues' XML export (issues/issue)."""
    out = []
    for i in ET.parse(path).getroot().iter("issue"):
        sev = (i.findtext("severity") or "").lower()
        if sev in ("information", "info", ""): continue
        h = i.find("host"); base = (h.text or "").strip() if h is not None else ""
        hostname = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
        ip = h.get("ip") if h is not None else None
        asset = lookup_asset(assets, ip, hostname)
        SCANNED.add(("burp", host_key(asset, ip, hostname)))
        name = i.findtext("name") or "Burp issue"; low = name.lower()
        cat = BURP_TYPES.get(i.findtext("type") or "") or next((c for w, c in BURP_WORDS if w in low), "security-misconfiguration-web")
        port = int(base.rsplit(":", 1)[1]) if re.search(r":\d+$", base) else (443 if base.startswith("https") else 80)
        conf = (i.findtext("confidence") or "").lower()
        out.append(dict(source="burp", host=hostname, ip=ip, port=port, proto="tcp", service="https" if port == 443 else "http",
                        asset=asset, category=cat, cves=[], url=base + (i.findtext("path") or ""), cwe=None, title=name,
                        evidence=f"Burp {sev}/{conf}: {i.findtext('location') or i.findtext('path') or ''}",
                        exploit_available=sev == "high" and conf == "certain"))
    return out

def parse_generic_csv(path, catalog, assets):
    out = []
    for r in read_csv(path):
        cat = r.get("category") or "vulnerable-software"
        if cat not in catalog["categories"]:
            print(f"[warn] unknown category '{cat}' in {path}; routed as vulnerable-software", file=sys.stderr); cat = "vulnerable-software"
        asset = lookup_asset(assets, r.get("ip"), r.get("host"))
        SCANNED.add((r.get("source") or "manual", host_key(asset, r.get("ip"), r.get("host"))))
        out.append(dict(source=r.get("source") or "manual", host=r.get("host") or r.get("ip"), ip=r.get("ip") or None,
                        port=int(r["port"]) if r.get("port", "").isdigit() else None, proto="tcp", service=r.get("service", ""),
                        asset=asset, category=cat, cves=CVE_RE.findall(r.get("cve", "")), url=r.get("url", ""),
                        title=r.get("title") or catalog["categories"][cat]["title"], evidence=r.get("evidence", ""),
                        exploit_available=truthy(r.get("exploit_available", "")),
                        cvss4_vector=r.get("cvss4_vector") or None,
                        cvss4_score=float(r["cvss4_score"]) if r.get("cvss4_score") else None,
                        wstg_extra=[x for x in r.get("wstg", "").split(";") if x],
                        cwe=[int(x) for x in r.get("cwe", "").split(";") if x.isdigit()] or None,
                        tester_notes=r.get("notes", ""), tester_ref=r.get("id", "")))
    return out

# ------------------------------------------------------------------ assets
DEFAULT_ASSET = dict(asset_id="UNKNOWN", asset_name="(not in inventory)", business_service="unknown", criticality=3,
                     environment="unknown", zone="IT", internet_facing=False, data_classification="unknown", owner_dept="", in_inventory=False)

def load_assets(path):
    idx = {}
    if not path: return idx
    for r in read_csv(path):
        a = dict(asset_id=r.get("asset_id", ""), asset_name=r.get("asset_name", ""), business_service=r.get("business_service", ""),
                 criticality=int(r.get("criticality") or 3), environment=r.get("environment", ""), zone=(r.get("zone") or "IT").upper(),
                 internet_facing=truthy(r.get("internet_facing", "")), data_classification=r.get("data_classification", ""),
                 owner_dept=r.get("owner_dept", ""), in_inventory=True)
        for k in (r.get("ip"), r.get("hostname")):
            if k: idx[k.lower()] = a
    return idx

def host_key(asset, ip, host):
    return asset["asset_id"] if asset.get("in_inventory") and asset.get("asset_id") else (ip or host or "").lower()

def lookup_asset(idx, ip, host):
    for k in (ip, host):
        if k and k.lower() in idx: return idx[k.lower()]
    d = dict(DEFAULT_ASSET); d["asset_name"] = f"{host or ip} (not in inventory)"
    return d

# ------------------------------------------------------------------ enrichment
def load_kev(path, online):
    data = None
    if online:
        try:
            with urllib.request.urlopen(KEV_URL, timeout=30) as r: data = json.load(r)
        except Exception as e: print(f"[warn] KEV fetch failed: {e}", file=sys.stderr)
    if data is None and path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh: data = json.load(fh)
    if not data: return {}, None
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("catalogVersion")

def load_epss(path, online, cves):
    res = {}
    if online and cves:
        try:
            lst = sorted(cves)
            for i in range(0, len(lst), 100):
                with urllib.request.urlopen(EPSS_URL + ",".join(lst[i:i + 100]), timeout=30) as r:
                    for d in json.load(r).get("data", []): res[d["cve"]] = (float(d["epss"]), float(d["percentile"]), d.get("date"))
        except Exception as e: print(f"[warn] EPSS fetch failed: {e}", file=sys.stderr)
    if not res and path and os.path.exists(path):
        if path.endswith(".json"):
            with open(path, encoding="utf-8") as fh:
                for d in json.load(fh).get("data", []): res[d["cve"]] = (float(d["epss"]), float(d["percentile"]), d.get("date"))
        else:
            with open(path, encoding="utf-8") as fh:
                for r in csv.DictReader(l for l in fh if not l.startswith("#")):
                    res[r["cve"]] = (float(r["epss"]), float(r["percentile"]), None)
    return res

# ------------------------------------------------------------------ prioritisation
def decide(f):
    """SSVC-inspired decision (own simplified tree). Returns (decision, reasons)."""
    a = f["asset"]; score = f["cvss4_score"] or 0
    expl = "active" if f["kev"] else "poc" if (f["epss"] or 0) >= 0.1 or f["exploit_available"] else "none"
    exposure = "internet" if a["internet_facing"] else "ot" if a["zone"] == "OT" else "internal"
    total = score >= 8.5
    crit = int(a["criticality"])
    if expl == "active" and (exposure in ("internet", "ot") or total): d = "ACT"
    elif expl == "active": d = "ATTEND"
    elif expl == "poc" and exposure != "internal" and score >= 7: d = "ATTEND"
    elif exposure == "ot" and crit >= 4 and score >= 7: d = "ATTEND"
    elif exposure == "internet" and score >= 9: d = "ATTEND"
    elif score >= 7 or expl == "poc": d = "TRACK*"
    else: d = "TRACK"
    if d == "TRACK" and exposure == "internet" and "personal" in (a["data_classification"] or "").lower(): d = "TRACK*"
    order = ["TRACK", "TRACK*", "ATTEND", "ACT"]
    if crit >= 5 and d in ("TRACK", "TRACK*"): d = order[order.index(d) + 1]
    if crit <= 1 and d != "ACT" and d != "TRACK": d = order[order.index(d) - 1]
    reasons = [f"exploitation={expl}", f"exposure={exposure}", f"technical_impact={'total' if total else 'partial'}", f"asset_criticality={crit}/5"]
    risk = min(100, round(score * 6 + (f["epss"] or 0) * 15 + (15 if f["kev"] else 0)
                          + {"internet": 8, "ot": 10, "internal": 0}[exposure] + crit * 2, 1))
    return d, reasons, risk, exposure

def explain(f):
    """One plain-language sentence a manager can read: why this priority."""
    bits = []
    if f["kev"]: bits.append("it is on the CISA KEV list, so attackers are already exploiting it" + (" in ransomware campaigns" if f["kev_ransomware"] else ""))
    elif f["epss"] is not None and f["epss"] >= 0.1: bits.append(f"EPSS gives a {f['epss']:.0%} probability of exploitation activity in the next 30 days")
    elif f["exploit_available"]: bits.append("the tester or the scanner confirmed it can be exploited")
    bits.append({"internet": "the asset is reachable from the internet", "ot": "the asset sits in the plant control (OT) zone",
                 "internal": "the asset is internal (not internet-facing)"}[f["exposure"]])
    if f["cvss4_score"] >= 8.5: bits.append("a successful attack means full compromise of the system")
    bits.append(f"its business criticality is {f['asset']['criticality']}/5")
    out = f"{f['priority']} because " + ", ".join(bits[:-1]) + " and " + bits[-1] + f" (CVSS v4 {f['cvss4_score']})."
    if f.get("floor_reason"): out += " " + f["floor_reason"]
    return out

# ------------------------------------------------------------------ routing
def route(f, raci):
    row = raci["categories"][f["category"]]
    R = list(row.get("R") or []); C = list(row.get("C") or []); I = list(row.get("I") or [])
    A = row.get("A") or "MGMT"; detect = row.get("detect") or "none"
    notes = []
    ov = raci.get("overrides") or {}
    a = f["asset"]
    if a["zone"] == "OT" and "ot_zone" in ov:
        o = ov["ot_zone"]
        if o.get("move_R_to_C"): C = R + C
        R = list(o.get("R") or ["OT-ENG"])
        if o.get("note"): notes.append(o["note"])
    if "personal" in (a["data_classification"] or "").lower() and "personal_data" in ov:
        C += ov["personal_data"].get("add_C") or []
    if a["internet_facing"] and "internet_facing" in ov:
        I += ov["internet_facing"].get("add_I") or []
    if a.get("owner_dept") and a["owner_dept"] in raci["departments"]: I.append(a["owner_dept"])
    if not a.get("in_inventory"):
        notes.append("Asset not found in inventory: IT-INFRA must register it in the CMDB (unknown assets are a finding by themselves).")
        I.append("IT-INFRA")
    dedup = lambda xs, excl: [x for i, x in enumerate(xs) if x and x not in xs[:i] and x not in excl]
    R = dedup(R, []); C = dedup(C, R); I = dedup(I, R + C)
    if A in I: I.remove(A)
    return dict(R=R, A=A, C=C, I=I, detect=detect), notes

# ------------------------------------------------------------------ build
def build(args):
    catalog = json.load(open(args.catalog, encoding="utf-8"))
    raci = load_yaml(args.raci)
    assets = load_assets(args.assets)
    org = {r["dept_code"]: r for r in read_csv(args.org)} if args.org else {}
    raw = []
    for p in args.nmap or []: raw += parse_nmap(p, catalog, assets, args.scan_source_zone)
    for p in args.nessus or []: raw += parse_nessus(p, catalog, assets)
    for p in args.zap or []: raw += parse_zap(p, catalog, assets)
    for p in args.burp or []: raw += parse_burp(p, catalog, assets)
    for p in args.findings or []: raw += parse_generic_csv(p, catalog, assets)
    sources = sorted({r["source"] for r in raw})

    # de-duplicate by fingerprint, merge sources/evidence
    merged = OrderedDict()
    for r in raw:
        a = r["asset"]
        key_host = host_key(a, r.get("ip"), r["host"]); r["host_key"] = key_host
        url_key = r.get("url") if r["category"] in ("web-injection", "web-xss", "broken-access-control") else ""
        fp = fingerprint(r["category"], key_host, r.get("port"), url_key)
        if fp in merged:
            m = merged[fp]; same_tool = r["source"] in m["sources"]
            m["sources"] = sorted(set(m["sources"] + [r["source"]]))
            m["cves"] = sorted(set(m["cves"]) | set(r["cves"]))
            m["exploit_available"] = m["exploit_available"] or r["exploit_available"]
            for k in ("cvss4_vector", "cvss4_score", "tool_solution", "tester_notes"):
                if not m.get(k) and r.get(k): m[k] = r[k]
            m.setdefault("merged_titles", [m["title"]])
            if same_tool and r["title"] not in m["merged_titles"]:
                m["merged_titles"].append(r["title"])
                m["title"] = f"{clip(catalog['categories'][r['category']]['title'], 60)} ({len(m['merged_titles'])} issues)"
            m["evidence"] += " || " + r["evidence"]; continue
        r["fingerprint"] = fp; r["sources"] = [r["source"]]; r["title"] = clip(r["title"], 80); merged[fp] = r

    all_cves = {c for r in merged.values() for c in r["cves"]}
    kev, kev_ver = load_kev(args.kev, args.online)
    epss = load_epss(args.epss, args.online, all_cves)
    today = dt.date.fromisoformat(args.date) if args.date else dt.date.today()

    findings = []
    for r in merged.values():
        cat = catalog["categories"][r["category"]]
        vec = r.get("cvss4_vector") or cat["cvss4_default"]
        score = r.get("cvss4_score")
        if score is None: score = cvss4_score(vec, cat["cvss4_default_score"])
        score_src = "tool/tester" if r.get("cvss4_score") is not None else "category default (assessor must confirm)"
        # most dangerous CVE first: KEV, then EPSS
        r["cves"] = sorted(r["cves"], key=lambda c: (c not in kev, -(epss.get(c, (0,))[0]), c))
        if r.get("auto_title") and "merged_titles" not in r: r["title"] = short_title(r["auto_title"][0], r["auto_title"][1], r["cves"])
        kev_hits = [kev[c] for c in r["cves"] if c in kev]
        ep = [epss[c] for c in r["cves"] if c in epss]
        best = max(ep, key=lambda x: x[0]) if ep else None
        f = dict(r)
        f.update(cvss4_vector=vec, cvss4_score=score, cvss4_source=score_src, severity=sev_from_score(score),
                 kev=bool(kev_hits), kev_cves=[k["cveID"] for k in kev_hits],
                 kev_ransomware=any(k.get("knownRansomwareCampaignUse") == "Known" for k in kev_hits),
                 epss=best[0] if best else None, epss_percentile=best[1] if best else None,
                 attack=cat["attack"], attack_mitigations=cat["attack_mitigations"], d3fend=cat["d3fend"],
                 wstg=sorted(set(cat["wstg"] + r.get("wstg_extra", []))) if cat["domain"] == "appsec" or r.get("wstg_extra") else cat["wstg"],
                 cwe=r.get("cwe") or cat["cwe"], fix=list(cat["fix"]), verify=list(cat["verify"]), detect=cat["detect"],
                 domain=cat["domain"], category_title=cat["title"])
        if r.get("tool_solution"): f["fix"].insert(1, "Scanner guidance: " + r["tool_solution"][:300])
        f["decision"], f["decision_reasons"], f["risk_score"], f["exposure"] = decide(f)
        f["priority"] = DECISION_TO_PRIO[f["decision"]]
        floor = cat.get("min_priority")
        if floor and PRIO_ORDER[f["priority"]] > PRIO_ORDER[floor]:
            f["priority"] = floor; f["decision"] = {v: k for k, v in DECISION_TO_PRIO.items()}[floor]
            f["decision_reasons"].append(f"category floor {floor}")
            f["floor_reason"] = f"Raised to {floor} by policy: this category never ranks lower."
        f["raci"], f["routing_notes"] = route(f, raci)
        if f["asset"]["zone"] == "OT" and f["priority"] in ("P1", "P2"):
            f["routing_notes"].append("OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, "
                                      "increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.")
        f["why"] = explain(f)
        sla = raci["ot_sla"] if f["asset"]["zone"] == "OT" else raci["sla"]
        f["sla_days"] = int(sla[f["priority"]])
        f["due_date"] = (today + dt.timedelta(days=f["sla_days"])).isoformat()
        a = f["asset"]
        f["business_impact"] = (f"{a['asset_name']} supports '{a['business_service']}' (criticality {a['criticality']}/5, "
                                f"{a['environment']}, zone {a['zone']}{', internet-facing' if a['internet_facing'] else ''}; data: {a['data_classification']}). "
                                f"If exploited, {catalog['impact_phrases'][cat['domain']]}."
                                + (" CVE used by ransomware campaigns (KEV)." if f["kev_ransomware"] else ""))
        findings.append(f)
    findings.sort(key=lambda f: (PRIO_ORDER[f["priority"]], -f["risk_score"], -SEV_ORDER[f["severity"]]))
    baseline = json.load(open(args.baseline, encoding="utf-8")) if args.baseline else None
    prev_ids = {b["fingerprint"]: b["id"] for b in baseline["findings"]} if baseline else {}
    nxt = max([int(i[2:]) for i in prev_ids.values()] + [0]) + 1
    for f in findings:  # IDs stay stable across retests so tickets keep their reference
        if f["fingerprint"] in prev_ids: f["id"] = prev_ids[f["fingerprint"]]
        else: f["id"] = f"F-{nxt:03d}"; nxt += 1
    if not kev: print("[warn] no KEV catalog loaded: use --kev <snapshot> or --online; exploitation evidence will be incomplete", file=sys.stderr)
    if all_cves and not epss: print("[warn] no EPSS scores loaded: use --epss <snapshot> or --online", file=sys.stderr)

    tickets = make_tickets(findings, raci, org, today)
    write_all(args, findings, tickets, raci, org, catalog, sources, kev_ver, epss, baseline, today)
    return findings, tickets

def make_tickets(findings, raci, org, today):
    tickets = []; counters = defaultdict(int)
    def new(dept, kind, f, summary, steps, verify, due, prio):
        counters[dept] += 1
        t = dict(ticket_id=f"{dept}-{counters[dept]:03d}", department=dept,
                 department_name=raci["departments"].get(dept, {}).get("name", dept),
                 queue=org.get(dept, {}).get("jira_component", dept), assignee_group=org.get(dept, {}).get("servicenow_group", dept),
                 lead=org.get(dept, {}).get("lead", ""), lead_email=org.get(dept, {}).get("email", ""),
                 type=kind, finding_id=f["id"] if f else "", fingerprint=f["fingerprint"] if f else "", priority=prio,
                 jira_priority=JIRA_PRIO[prio], snow_urgency=SNOW_UI[prio][0], snow_impact=SNOW_UI[prio][1],
                 due_date=due, summary=summary, steps=steps, verify=verify,
                 labels=([f["category"]] + f["attack"] + f["wstg"] + (["KEV"] if f["kev"] else []) + (["OT"] if f["asset"]["zone"] == "OT" else [])) if f else ["governance"],
                 accountable=f["raci"]["A"] if f else "MGMT", consulted=f["raci"]["C"] if f else [], informed=f["raci"]["I"] if f else [])
        tickets.append(t); return t
    for f in findings:
        asset = f["asset"]["asset_name"]
        for dept in f["raci"]["R"]:
            new(dept, "fix", f, f"[{f['priority']}] {f['category_title']} on {asset} ({f['host']}{':' + str(f['port']) if f.get('port') else ''})",
                f["fix"], f["verify"], f["due_date"], f["priority"])
        det = f["raci"]["detect"]
        if det and det != "none" and det not in f["raci"]["R"] and f["priority"] in ("P1", "P2"):
            due = (today + dt.timedelta(days=min(2, f["sla_days"]))).isoformat()
            new(det, "detection", f, f"[{f['priority']}] Interim detection while {f['id']} is open: {', '.join(f['attack'])} on {asset}",
                [f["detect"], f"Map the rule to ATT&CK {', '.join(f['attack'])} and tag alerts with {f['id']}.",
                 "Keep the rule active until the fix ticket is verified closed."],
                ["Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue."], due, f["priority"])
        if "GRC-DPO" in f["raci"]["C"] and "personal" in (f["asset"]["data_classification"] or "").lower() and f["priority"] in ("P1", "P2"):
            new("GRC-DPO", "compliance", f, f"[{f['priority']}] Assess personal-data impact of {f['id']} on {asset}",
                ["Check access logs for the exposure window together with SOC.",
                 "Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.",
                 "Record the finding and treatment in the risk register / RoPA."],
                ["Decision recorded with date and signatory."], f["due_date"], f["priority"])
    p12 = [f for f in findings if f["priority"] in ("P1", "P2")]
    if p12:
        new("MGMT", "governance", None, f"Approve remediation plan: {len(p12)} P1/P2 findings, resources and risk acceptances",
            ["Review the executive summary and the department distribution table.",
             "Confirm owners and SLAs, or formally accept residual risk per finding (named owner + expiry date).",
             "Schedule a weekly 15-minute remediation stand-up until all P1/P2 are verified closed."],
            ["Signed approval or risk acceptance attached to every P1/P2 finding."], (today + dt.timedelta(days=2)).isoformat(), "P1")
    return tickets

# ------------------------------------------------------------------ writers
def fill(tpl, mapping):
    for k, v in mapping.items(): tpl = tpl.replace("{{" + k + "}}", str(v))
    return tpl

def template(args, name):
    for d in ([os.path.join(ROOT, "i18n", args.lang, "templates")] if args.lang != "en" else []) + [os.path.join(ROOT, "templates")]:
        p = os.path.join(d, name)
        if os.path.exists(p): return open(p, encoding="utf-8").read()
    raise FileNotFoundError(name)

def md_list(items, ordered=True):
    return "\n".join((f"{i}. " if ordered else "- ") + s for i, s in enumerate(items, 1))

def write_all(args, findings, tickets, raci, org, catalog, sources, kev_ver, epss, baseline, today):
    lab = L[args.lang]; out = args.out
    os.makedirs(os.path.join(out, "tickets"), exist_ok=True)
    os.makedirs(os.path.join(out, "navigator"), exist_ok=True)
    clean = lambda f: {k: v for k, v in f.items() if k not in ("wstg_extra", "source", "auto_title", "floor_reason")}
    json.dump(dict(generated=today.isoformat(), company=args.company, attack_version=catalog["_meta"]["attack_version"],
                   kev_catalog_version=kev_ver, findings=[clean(f) for f in findings]),
              open(os.path.join(out, "findings.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    cols = ["id", "priority", "decision", "severity", "cvss4_score", "risk_score", "kev", "epss", "category", "title", "host", "port",
            "asset", "zone", "responsible", "accountable", "consulted", "informed", "due_date", "attack", "wstg", "d3fend", "fingerprint"]
    with open(os.path.join(out, "findings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for f in findings:
            w.writerow([f["id"], f["priority"], f["decision"], f["severity"], f["cvss4_score"], f["risk_score"], f["kev"], f["epss"] or "",
                        f["category"], f["title"], f["host"], f.get("port") or "", f["asset"]["asset_name"], f["asset"]["zone"],
                        ";".join(f["raci"]["R"]), f["raci"]["A"], ";".join(f["raci"]["C"]), ";".join(f["raci"]["I"]), f["due_date"],
                        ";".join(f["attack"]), ";".join(f["wstg"]), ";".join(f["d3fend"]), f["fingerprint"]])

    # tickets per department
    by_dept = defaultdict(list)
    for t in tickets: by_dept[t["department"]].append(t)
    ttpl = template(args, "department_ticket.md")
    fmap = {f["id"]: f for f in findings}
    tcols = ["ticket_id", "type", "priority", "jira_priority", "due_date", "department", "summary", "finding_id", "labels", "accountable", "consulted", "informed"]
    for dept, ts in by_dept.items():
        blocks = []
        for t in ts:
            f = fmap.get(t["finding_id"])
            refs = (f"ATT&CK v20: {', '.join(f['attack'])} | Mitigations: {', '.join(f['attack_mitigations'])} | D3FEND: {', '.join(f['d3fend'])}"
                    + (f" | WSTG: {', '.join(f['wstg'])}" if f["wstg"] else "") + (f" | CWE: {', '.join('CWE-' + str(c) for c in f['cwe'])}" if f["cwe"] else "")
                    + (f" | CVE: {', '.join(f['cves'][:8])}" if f["cves"] else "")) if f else "Report: report.md"
            ctx = (f"{f['asset']['asset_name']} | {f['host']}{':' + str(f['port']) if f.get('port') else ''} | {f['severity']} CVSS v4 {f['cvss4_score']} "
                   f"| KEV: {lab['yes'] if f['kev'] else lab['no']} | EPSS: {f['epss'] if f['epss'] is not None else 'n/a'} | {f['decision']} ({', '.join(f['decision_reasons'])})"
                   + ("".join(f"\n\n> {n}" for n in f["routing_notes"]))) if f else "Cross-department governance item."
            blocks.append(fill(ttpl, dict(TICKET_ID=t["ticket_id"], SUMMARY=t["summary"], TYPE=t["type"], PRIORITY=t["priority"],
                DUE=t["due_date"], DEPARTMENT=f"{t['department_name']} ({dept})", FINDING_ID=t["finding_id"] or "-",
                CONTEXT=ctx, IMPACT=f["business_impact"] if f else "-", STEPS=md_list(t["steps"]), VERIFY=md_list(t["verify"], False),
                RACI=f"R: {dept} | A: {t['accountable']} | C: {', '.join(t['consulted']) or '-'} | I: {', '.join(t['informed']) or '-'}",
                REFS=refs, EVIDENCE=(f["evidence"][:500] if f else "-"))))
        head = f"# {raci['departments'].get(dept, {}).get('name', dept)} ({dept})\n\n{args.company} | {today.isoformat()} | {len(ts)} {lab['tickets']}\n"
        if org.get(dept): head += f"\nLead: {org[dept].get('lead', '')} <{org[dept].get('email', '')}>\n"
        open(os.path.join(out, "tickets", f"{dept}.md"), "w", encoding="utf-8").write(head + "\n---\n\n" + "\n\n---\n\n".join(blocks) + "\n")
        with open(os.path.join(out, "tickets", f"{dept}.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh); w.writerow(tcols)
            for t in ts: w.writerow([t[c] if not isinstance(t[c], list) else ";".join(t[c]) for c in tcols])
        json.dump(ts, open(os.path.join(out, "tickets", f"{dept}.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    # Jira CSV (import via External System Import, map columns once)
    with open(os.path.join(out, "jira_import.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Summary", "Issue Type", "Priority", "Component/s", "Due Date", "Labels", "Labels", "Labels", "Description"])
        for t in tickets:
            labels = (t["labels"] + ["", "", ""])[:3]
            desc = (f"Finding {t['finding_id']} | type {t['type']}\n\nSteps:\n" + "\n".join(f"# {s}" for s in t["steps"])
                    + "\n\nAcceptance criteria:\n" + "\n".join(f"* {s}" for s in t["verify"])
                    + f"\n\nRACI: A={t['accountable']} C={','.join(t['consulted'])} I={','.join(t['informed'])}")
            w.writerow([t["summary"], "Task", t["jira_priority"], t["queue"], t["due_date"]] + [l.replace(" ", "_") for l in labels] + [desc])
    # ServiceNow import set JSON
    json.dump({"records": [dict(short_description=t["summary"][:160], assignment_group=t["assignee_group"], urgency=t["snow_urgency"],
                                impact=t["snow_impact"], due_date=t["due_date"], category="security", u_finding_id=t["finding_id"],
                                u_ticket_ref=t["ticket_id"], u_type=t["type"], u_labels=",".join(t["labels"]),
                                description="\n".join(t["steps"]), u_acceptance_criteria="\n".join(t["verify"])) for t in tickets]},
              open(os.path.join(out, "servicenow_import.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    # DefectDojo Generic Findings Import
    json.dump({"findings": [dict(title=f"{f['id']} {f['title']}"[:500], severity=f["severity"] if f["severity"] != "None" else "Info",
                                 description=f"{f['category_title']}\n\nEvidence: {f['evidence'][:1500]}", mitigation="\n".join(f["fix"]),
                                 impact=f["business_impact"], date=today.isoformat(), active=True, verified=False,
                                 cve=f["cves"][0] if f["cves"] else None, cwe=f["cwe"][0] if f["cwe"] else None,
                                 unique_id_from_tool=f["fingerprint"], vuln_id_from_tool=f["category"],
                                 component_name=f.get("service") or None,
                                 tags=[f["priority"], *f["raci"]["R"], *f["attack"]],
                                 references="\n".join(f["attack"] + f["wstg"] + f["d3fend"])) for f in findings]},
              open(os.path.join(out, "defectdojo_generic.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    # ATT&CK Navigator layers
    for dom, pred in (("enterprise-attack", lambda t: not re.match(r"T0\d{3}", t) and t not in ("T1692",)), ("ics-attack", None)):
        tech = defaultdict(lambda: [0, []])
        for f in findings:
            ics = f["domain"] == "ot"
            if (dom == "ics-attack") != ics: continue
            for t in f["attack"]:
                tech[t][0] = max(tech[t][0], f["risk_score"]); tech[t][1].append(f["id"])
        if not tech: continue
        layer = {"name": f"{args.company} findings ({dom})", "versions": {"attack": catalog["_meta"]["attack_version"], "navigator": "5.1.0", "layer": "4.5"},
                 "domain": dom, "description": "Generated by remediation_pack.py; score = max risk score of findings using the technique.",
                 "techniques": [{"techniqueID": t, "score": s, "comment": "Findings: " + ", ".join(ids), "enabled": True} for t, (s, ids) in sorted(tech.items())],
                 "gradient": {"colors": ["#1f6feb", "#f0b429", "#ff3b5c"], "minValue": 0, "maxValue": 100},
                 "showTacticRowBackground": True, "tacticRowBackground": "#0b0f1a"}
        json.dump(layer, open(os.path.join(out, "navigator", f"layer_{dom}.json"), "w"), indent=2)

    # metrics (OSSTMM-inspired, simplified)
    hosts = {f.get("ip") or f["host"] for f in findings}
    services = {(f.get("ip") or f["host"], f.get("port")) for f in findings if f.get("port")}
    trust_cats = {"default-credentials", "ot-protocol-exposed", "exposed-database", "snmp-weak-community", "cleartext-protocol", "broken-access-control"}
    trust = {(f.get("ip") or f["host"], f.get("port")) for f in findings if f["category"] in trust_cats}
    porosity = len(hosts) + len(services) + len(trust)

    # retest delta
    delta_md = ""; delta = None
    if baseline:
        prev = {f["fingerprint"]: f for f in baseline["findings"]}; cur = {f["fingerprint"]: f for f in findings}
        gone = [prev[k] for k in prev if k not in cur]
        covered = lambda b: any((src, b.get("host_key", "")) in SCANNED for src in b.get("sources", []))
        fixed = [b for b in gone if covered(b)]; untested = [b for b in gone if not covered(b)]
        still = [cur[k] for k in cur if k in prev]; new_ = [cur[k] for k in cur if k not in prev]
        delta = dict(fixed=len(fixed), still_open=len(still), new=len(new_), not_retested=len(untested))
        delta_md = (f"| Status | Count |\n|---|---|\n| Fixed and verified by rescan | {len(fixed)} |\n| Still open | {len(still)} |\n| New | {len(new_)} |"
                    f"\n| Not retested (tool or host not in this run, stays open) | {len(untested)} |\n\n"
                    + "\n".join(f"- FIXED: {f['id']} {f['title']} on {f['host']}" for f in fixed)
                    + ("\n" if fixed else "") + "\n".join(f"- NOT RETESTED: {f['id']} {f['title']} on {f['host']} (source: {', '.join(f['sources'])})" for f in untested)
                    + ("\n" if fixed else "") + "\n".join(f"- STILL OPEN: {f['id']} {f['title']} on {f['host']} (due {f['due_date']})" for f in still)
                    + ("\n" if still else "") + "\n".join(f"- NEW: {f['id']} {f['title']} on {f['host']}" for f in new_))
        json.dump(dict(delta, fixed_items=[f["fingerprint"] for f in fixed], not_retested_items=[f["fingerprint"] for f in untested], still_open_items=[f["fingerprint"] for f in still], new_items=[f["fingerprint"] for f in new_]),
                  open(os.path.join(out, "retest_delta.json"), "w"), indent=2)
        open(os.path.join(out, "retest_delta.md"), "w", encoding="utf-8").write(f"# Retest delta {today.isoformat()}\n\n" + delta_md + "\n")

    # report
    pc = defaultdict(int)
    for f in findings: pc[f["priority"]] += 1
    dept_rows = []
    for dept in raci["departments"]:
        ts = by_dept.get(dept, [])
        if not ts: continue
        c = defaultdict(int)
        for t in ts: c[t["priority"]] += 1
        dept_rows.append((dept, len(ts), c, min(t["due_date"] for t in ts)))
    fixload = defaultdict(int)
    for t in tickets:
        if t["type"] == "fix": fixload[t["department"]] += 1
    top = max(fixload, key=fixload.get) if fixload else "-"
    exec_ = "\n\n".join([lab["exec1"].format(n=len(findings), h=len(hosts), s=len(sources), p1=pc["P1"], p2=pc["P2"]),
                         lab["exec2"].format(k=sum(f["kev"] for f in findings), ot=sum(f["asset"]["zone"] == "OT" for f in findings)),
                         lab["exec3"].format(d=len(dept_rows), t=len(tickets), top=f"{raci['departments'][top]['name']} ({top}, {fixload[top]} fix tickets)" if top != "-" else "-")])
    if delta: exec_ += (f"\n\nRetest vs baseline: {delta['fixed']} fixed and verified, {delta['still_open']} still open, {delta['new']} new, "
                        f"{delta['not_retested']} not retested in this run (they remain open).")
    kpi = (f"| P1 | P2 | P3 | P4 | KEV | OT | {lab['tickets']} |\n|---|---|---|---|---|---|---|\n"
           f"| {pc['P1']} | {pc['P2']} | {pc['P3']} | {pc['P4']} | {sum(f['kev'] for f in findings)} | {sum(f['asset']['zone'] == 'OT' for f in findings)} | {len(tickets)} |")
    metrics = (f"| Visibility (hosts with findings) | Access (exposed services) | Trust (services accepting unauthenticated or implicit-trust interaction) | Porosity V+A+T |\n|---|---|---|---|\n"
               f"| {len(hosts)} | {len(services)} | {len(trust)} | **{porosity}** |\n\n"
               "_Simplified indicator inspired by OSSTMM 3 operational-security metrics (visibility, access, trust). It is not an OSSTMM rav calculation; use it to track the trend between retests._")
    ptable = f"| {lab['id']} | {lab['prio']} | {lab['sev']} | {lab['cvss']} | {lab['kev']} | {lab['epss']} | {lab['title']} | {lab['asset']} | {lab['owner']} | {lab['due']} | {lab['attack']} |\n|---|---|---|---|---|---|---|---|---|---|---|\n"
    ptable += "\n".join(f"| {f['id']} | **{f['priority']}** | {f['severity']} | {f['cvss4_score']} | {'Y' if f['kev'] else '-'} | {fmt_epss(f['epss'])} | {clip(f['title'], 70)} | {clip(f['asset']['asset_name'], 36)} | {', '.join(f['raci']['R'])} | {f['due_date']} | {', '.join(f['attack'])} |" for f in findings)
    dtable = f"| {lab['dept']} | {lab['tickets']} | P1 | P2 | P3 | P4 | Next due |\n|---|---|---|---|---|---|---|\n" + "\n".join(
        f"| {raci['departments'][d]['name']} ({d}) | {n} | {c['P1']} | {c['P2']} | {c['P3']} | {c['P4']} | {nd} |" for d, n, c, nd in dept_rows)
    details = []
    for f in findings:
        details.append(
            f"### {f['id']} [{f['priority']} / {f['decision']}] {f['title']}\n\n"
            f"- **{lab['asset']}:** {f['asset']['asset_name']} ({f['host']}{':' + str(f['port']) if f.get('port') else ''}{' ' + f['url'] if f.get('url') else ''})\n"
            f"- **{lab['sev']}:** {f['severity']} | CVSS v4 {f['cvss4_score']} (`{f['cvss4_vector']}`, {f['cvss4_source']})\n"
            f"- **KEV / EPSS:** {'KEV ' + ', '.join(f['kev_cves']) if f['kev'] else 'not in KEV'} | EPSS {f['epss'] if f['epss'] is not None else 'n/a'}"
            f"{' (pctl ' + str(round(f['epss_percentile'], 3)) + ')' if f['epss_percentile'] else ''}\n"
            f"- **Decision:** {f['decision']} ({'; '.join(f['decision_reasons'])}), risk score {f['risk_score']}/100\n"
            f"- **Why:** {f['why']}\n"
            f"- **{lab['impact']}:** {f['business_impact']}\n"
            f"- **{lab['refs']}:** ATT&CK {', '.join(f['attack'])}; mitigations {', '.join(f['attack_mitigations'])}; D3FEND {', '.join(f['d3fend'])}"
            f"{'; WSTG ' + ', '.join(f['wstg']) if f['wstg'] else ''}{'; CWE ' + ', '.join(map(str, f['cwe'])) if f['cwe'] else ''}"
            f"{'; CVE ' + ', '.join(f['cves'][:10]) if f['cves'] else ''}\n"
            f"- **{lab['raci']}:** R {', '.join(f['raci']['R'])} | A {f['raci']['A']} | C {', '.join(f['raci']['C']) or '-'} | I {', '.join(f['raci']['I']) or '-'} | SLA {f['sla_days']} d, {lab['due']} {f['due_date']}\n"
            + "".join(f"- > {n}\n" for n in f["routing_notes"])
            + f"\n**{lab['fix']}**\n\n{md_list(f['fix'])}\n\n**{lab['verify']}**\n\n{md_list(f['verify'], False)}\n\n**{lab['detect']}:** {f['detect']}\n\n"
            f"<details><summary>{lab['evidence']}</summary>\n\n```\n{f['evidence'][:900]}\n```\n</details>\n")
    retest = ("| Finding | Owner | Retest command / check | When |\n|---|---|---|---|\n" +
              "\n".join(f"| {f['id']} | {', '.join(f['raci']['R'])} | {f['verify'][0].replace('|', '/')} | after fix, before {f['due_date']} |" for f in findings))
    method = ("PTES phases as process spine (pre-engagement to reporting); NIST SP 800-115 for planning, rules of engagement and reporting structure; "
              "OWASP WSTG v4.2 test IDs for web findings; MITRE ATT&CK v20 technique and mitigation IDs plus MITRE D3FEND 1.6.0 countermeasures for mapping; "
              "OSSTMM-inspired visibility/access/trust indicator for trend. Prioritisation: CVSS v4.0 base score, CISA KEV, FIRST EPSS and an SSVC-inspired decision tree "
              "(ACT / ATTEND / TRACK* / TRACK) adjusted by asset criticality and exposure.")
    srcs = (f"Sources parsed: {', '.join(sources)}. KEV catalog version: {kev_ver or 'not loaded'}. EPSS scores loaded: {len(epss)}"
            f"{' (date ' + str(next(iter(epss.values()))[2]) + ')' if epss and next(iter(epss.values()))[2] else ''}.")
    rpt = fill(template(args, "report.md"), dict(COMPANY=args.company, DATE=today.isoformat(), SCOPE=args.scope, EXEC_SUMMARY=exec_, KPI_TABLE=kpi,
               METRICS=metrics, PRIORITY_TABLE=ptable, DEPARTMENT_TABLE=dtable, FINDINGS_DETAIL="\n".join(details), RETEST_PLAN=retest,
               DELTA=delta_md or "_No baseline supplied. Run again with `--baseline <previous findings.json>` after fixes._", METHOD=method, SOURCES=srcs))
    open(os.path.join(out, "report.md"), "w", encoding="utf-8").write(rpt)
    print(f"[ok] {len(findings)} findings, {len(tickets)} tickets for {len(by_dept)} departments -> {out}")

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nmap", action="append"); ap.add_argument("--nessus", action="append")
    ap.add_argument("--zap", action="append"); ap.add_argument("--burp", action="append", help="Burp Suite issues XML"); ap.add_argument("--findings", action="append", help="generic findings CSV")
    ap.add_argument("--assets"); ap.add_argument("--org", help="departments CSV (dept_code, lead, email, jira_component, servicenow_group)")
    ap.add_argument("--raci", default=os.path.join(ROOT, "routing", "raci_matrix.yaml"))
    ap.add_argument("--catalog", default=os.path.join(ROOT, "knowledge", "catalog.json"))
    ap.add_argument("--kev", help="KEV JSON snapshot"); ap.add_argument("--epss", help="EPSS JSON (API format) or CSV snapshot")
    ap.add_argument("--online", action="store_true", help="fetch live KEV and EPSS (falls back to snapshots)")
    ap.add_argument("--scan-source-zone", default="IT", help="network zone the nmap scan was launched from (IT|OT|INTERNET)")
    ap.add_argument("--baseline", help="previous findings.json for retest delta")
    ap.add_argument("--company", default="Example Corp"); ap.add_argument("--scope", default="(scope not stated)")
    ap.add_argument("--date", help="report date YYYY-MM-DD (default today)")
    ap.add_argument("--lang", default="en", choices=sorted(L)); ap.add_argument("--out", default="out")
    args = ap.parse_args(argv)
    if not any([args.nmap, args.nessus, args.zap, args.burp, args.findings]): ap.error("give at least one input (--nmap/--nessus/--zap/--burp/--findings)")
    build(args)

if __name__ == "__main__":
    main()
