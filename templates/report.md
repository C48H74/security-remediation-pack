# Security Remediation Package: {{COMPANY}}

**Report date:** {{DATE}}  
**Scope:** {{SCOPE}}  
**Classification:** CONFIDENTIAL. Share per department on a need-to-know basis.

---

## 1. Executive summary

{{EXEC_SUMMARY}}

{{KPI_TABLE}}

### What management needs to decide this week

1. Approve the owners and due dates in section 3 (ticket `MGMT-001`).
2. Free capacity for every P1 item: the target is containment within 72 hours.
3. Formally accept, with a named owner and an expiry date, any risk that will not be fixed inside its SLA.

## 2. Prioritised findings

Priority is **P1 (ACT)**, **P2 (ATTEND)**, **P3 (TRACK\*)** or **P4 (TRACK)**. It comes from an SSVC-inspired decision that weighs exploitation evidence (CISA KEV, FIRST EPSS, public exploit), exposure (internet / OT / internal), technical impact (CVSS v4.0) and the asset's business criticality.

{{PRIORITY_TABLE}}

## 3. Work distribution by department

Every finding has exactly one Accountable role and at least one Responsible department. While a P1/P2 fix is pending, the SOC receives a parallel detection ticket.

{{DEPARTMENT_TABLE}}

Ticket files: `tickets/<DEPT>.md` (human readable), `tickets/<DEPT>.csv` and `.json`; consolidated `jira_import.csv`, `servicenow_import.json` and `defectdojo_generic.json`.

## 4. Operational security indicator

{{METRICS}}

## 5. Finding details and fix steps

{{FINDINGS_DETAIL}}

## 6. Retest plan

{{RETEST_PLAN}}

## 7. Retest delta

{{DELTA}}

## 8. Method and sources

{{METHOD}}

{{SOURCES}}

Identifiers cited: MITRE ATT&CK® and MITRE D3FEND™ (© The MITRE Corporation), OWASP WSTG test IDs, CWE, CVE, CISA KEV, FIRST EPSS and CVSS v4.0. All explanatory wording in this report is original. See NOTICE.md in the skill repository.
