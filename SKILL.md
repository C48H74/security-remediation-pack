---
name: security-remediation-pack
description: Turns raw security testing output (nmap, Nessus, OWASP ZAP, Burp, a findings CSV or pentest notes) into a ready-to-apply remediation package routed to the departments that must act. Use it when someone has scan results or a pentest/red-team report and needs prioritized findings (CVSS v4, CISA KEV, FIRST EPSS, business impact), MITRE ATT&CK / D3FEND / OWASP WSTG mapping, fix and verification steps, a RACI owner and SLA per finding, and per-department tickets for Jira, ServiceNow or DefectDojo, plus a retest delta. Covers IT, web, identity, people and OT/ICS findings.
---

# Security remediation pack

Languages: **English** | [Español](i18n/es/SKILL.md) | [Português (Brasil)](i18n/pt-BR/SKILL.md)

A test only pays off when the fix lands. This skill takes what the testers found and produces what each team needs to act on: one report for management, and one ticket queue for each department, with the steps, the deadline and the evidence they need to close it.

## When to use it

- You have scanner output (nmap, Nessus, ZAP, Burp) or a findings CSV from a pentest and need to hand it over to the company.
- A client asks "who fixes what, by when?" after an assessment.
- You need to re-run the same scope later and show what was really fixed.
- **Not for:** running attacks or scans. Testing must already have happened, within an authorized scope and rules of engagement (NIST SP 800-115 planning; PTES pre-engagement).

## Inputs

| Input | Flag | Required | Notes |
|---|---|---|---|
| nmap XML (`-oX`) | `--nmap` | at least one source | Uses `vulners` and `smb-vuln-*` NSE output for CVEs; port rules for risky services (RDP, SMB, Telnet, Modbus, S7, OPC UA...) |
| Nessus `.nessus` | `--nessus` | | CVE, CVSS v4/v3 vectors, plugin output |
| OWASP ZAP XML report | `--zap` | | Plugin id and CWE → category; confirmed attacks count as exploit evidence |
| Burp Suite issues XML | `--burp` | | Issue type and name → category; Info issues skipped |
| Findings CSV | `--findings` | | Manual and pentest findings. Columns: `id,source,title,category,host,ip,port,url,cve,cwe,cvss4_vector,cvss4_score,severity,evidence,wstg,exploit_available,notes` |
| Asset inventory CSV | `--assets` | strongly advised | `asset_id,ip,hostname,asset_name,business_service,criticality(1-5),environment,zone,internet_facing,data_classification,owner_dept`. A zone containing `OT` marks plant assets |
| Departments CSV | `--org` | advised | `dept_code,name,lead,email,jira_component,servicenow_group` |
| RACI matrix | `--raci` | default `routing/raci_matrix.yaml` | Category → R/A/C/I and detection owner, SLAs, overrides |
| KEV / EPSS | `--kev`, `--epss`, or `--online` | advised | Snapshots keep runs reproducible; `--online` fetches the CISA KEV feed and the FIRST EPSS API |
| Baseline | `--baseline <previous findings.json>` | for retests | Produces `retest_delta.md/.json` |

All flags may be repeated (`--nmap a.xml --nmap b.xml`). Findings from different tools on the same service or URL are merged into one finding (CVEs and sources combined).

## How to run it

```bash
python3 scripts/remediation_pack.py \
  --nmap scans/nmap.xml --nessus scans/scan.nessus --zap scans/zap.xml --burp scans/burp.xml \
  --findings notes/findings.csv --assets cmdb/assets.csv --org cmdb/org_departments.csv \
  --kev data/kev.json --epss data/epss.json \
  --company "ACME" --scope "External perimeter and supplier portal" --lang en --out out/
python3 scripts/selftest.py out/ --org cmdb/org_departments.csv   # quality gate, exit 1 on failure
```

Python 3.9+ standard library only. `--lang es` or `--lang pt-BR` renders the report and tickets with the translated templates in `i18n/`.

## Procedure for the agent

1. **Check the scope.** Confirm the user has authorization for the targets in the input. If the asset list or departments CSV is missing, ask for them. Without them you can still run, but you must say that business impact and ownership are generic.
2. **Normalize the notes.** Convert free-text pentest notes into rows of the findings CSV. Pick `category` from `knowledge/catalog.json` (18 categories), keep the tester's evidence word for word, and add a CVSS v4.0 vector only if the tester gave one.
3. **Run the script** with every source you have, plus KEV/EPSS (snapshot or `--online`).
4. **Run `selftest.py`.** Fix the inputs and re-run until all checks pass. Do not hand over a package with failures. A `WARN` (for example, no KEV loaded) must be reported to the user.
5. **Review the top of the report like a manager would.** Read section 1 and the P1/P2 rows. Every finding has a plain-language "Why" line. If a priority looks wrong, fix the input (asset criticality, zone, internet exposure) rather than editing the output.
6. **Hand over**:
   - `report.md` to management (section 1 lists the decisions needed this week),
   - `tickets/<DEPT>.md` to each department lead,
   - `jira_import.csv` / `servicenow_import.json` / `defectdojo_generic.json` to the tool owners,
   - `navigator/*.json` to the SOC or threat-intel team (load them in ATT&CK Navigator).
7. **Retest.** After fixes, re-run with `--baseline out/findings.json`. Only findings whose tool and host were included in the new run can be marked *fixed*. Anything else is listed as *not retested* and stays open.

## How it decides (summary)

**Priority.** This is an SSVC-inspired decision, written for this skill:

- *Exploitation*:
  - `active`: the CVE is in CISA KEV,
  - `poc`: EPSS ≥ 0.1, or the exploit was confirmed in the test,
  - `none`: otherwise.
- *Exposure*: internet, OT or internal.
- *Technical impact*: CVSS v4 ≥ 8.5 means total.
- *Asset criticality*: 1 to 5.

The result is ACT → **P1**, ATTEND → **P2**, TRACK\* → **P3** or TRACK → **P4**. Some categories have a floor (default credentials never fall below P2; detection gaps never below P3). KEV findings are always P1 or P2.

**SLA (calendar days)**

| Priority | IT | OT |
|---|---|---|
| P1 | 3 | 3 (containment); permanent fix through MOC |
| P2 | 14 | 30 |
| P3 | 45 | 90 |
| P4 | 90 | 180 |

All SLAs are editable in `routing/raci_matrix.yaml`. Use the shorter of these and any regulatory deadline that applies to you, such as CISA BOD 26-04 dates for US federal agencies or GDPR Art. 33 (72 h) for personal-data breaches.

**Routing**

- Each category has R (who fixes), one A (accountable, MGMT by default), C, I, and a detection owner.
- Overrides:
  - OT zone assets move R to **OT-ENG** and require Management of Change and process-safety sign-off.
  - Personal data adds **GRC-DPO** as Consulted.
  - Internet-facing assets inform **NETWORK**.
  - Unknown assets get a CMDB note and IT-INFRA is informed.

**Tickets** come in four types:

- **fix**, one per Responsible department,
- **detection**, for the SOC on each P1/P2 while the fix is pending,
- **compliance**, for GRC-DPO when a P1/P2 touches personal data,
- **governance**, one MGMT ticket to approve the plan.

## Output package

| File | For whom | What |
|---|---|---|
| `report.md` | Management, all leads | Executive summary, KPI row, decisions needed, prioritized table, department workload, OSSTMM-inspired exposure indicator, finding details (why, impact, ATT&CK/D3FEND/WSTG/CWE, fix steps, verification, interim detection, evidence), retest plan, method and sources |
| `tickets/<DEPT>.md/.csv/.json` | Each department | Its own queue only: steps, deadline, RACI, definition of done |
| `jira_import.csv` | Jira admin | Summary, Issue Type, Priority (Highest/High/Medium/Low), Component/s, Due Date, Labels, Description |
| `servicenow_import.json` | ServiceNow admin | `records[]` with urgency/impact, assignment group, due date |
| `defectdojo_generic.json` | AppSec / vuln management | DefectDojo Generic Findings Import format |
| `navigator/layer_*-attack.json` | SOC / CTI | ATT&CK Navigator layers (Enterprise and ICS) scored by priority |
| `findings.json` / `findings.csv` | Automation, retest baseline | Normalized findings with stable fingerprints and IDs |
| `retest_delta.md/.json` | Management, auditors | Fixed and verified / still open / new / not retested |

## Files in this skill

- `scripts/remediation_pack.py`: parsers, enrichment, decision, routing, ticket and export writers.
- `scripts/selftest.py`: 27-rule quality gate (owner, SLA, mappings, steps, OT and DPO rules, order, due dates, placeholders, exports).
- `scripts/verify_ids.py`: checks every ATT&CK, D3FEND and WSTG identifier in the catalog against the official data.
- `knowledge/catalog.json`: 18 finding categories with CWE, ATT&CK techniques and mitigations, D3FEND, WSTG IDs, default CVSS v4 vector, fix steps, verification and detection advice.
- `routing/raci_matrix.yaml`: departments, RACI per category, SLAs, overrides. Edit this to match your organisation.
- `templates/report.md`, `templates/department_ticket.md`, plus `i18n/es/` and `i18n/pt-BR/` translations.
- `examples/novarefino/`: a fictitious refinery operator with real-format inputs and the generated outputs (`run_example.sh` rebuilds them).

## Rules for the agent

- Never invent CVEs, CVSS scores, KEV status or EPSS values. Use the input data, the snapshots or the live feeds. If a CVSS v4 vector is the category default, the report says so and the assessor must confirm it.
- Keep the tester's evidence unchanged. Redact secrets (passwords, tokens, full card or bank numbers) before sharing tickets outside the security team.
- OT/ICS: do not recommend active scanning or patching of live controllers. Contain at the IT/OT boundary first, and plan permanent fixes for an approved window.
- Each department receives only its own ticket file. The full report is restricted to management and the security team.
- Framework identifiers (ATT&CK, D3FEND, WSTG, CWE) are references. The fix text in the catalog is original guidance, not a copy of the standards.
