# Framework analysis: which ones can drive a remediation skill?

Starting point: the six testing methodologies listed in Cisco NetAcad *Ethical Hacker*, module 1.2.5. Question: which of them can an AI agent turn into **fixes routed to the right department**, not only into a test plan?

Scoring (1 to 5) is my own judgement, based on the public documents listed at the end (checked on 2026-11-02).

- **Machine-actionable** means stable identifiers plus structured data an agent can parse.
- **Remediation value** means guidance that helps someone fix a problem, not just find it.

| Framework | Current version (as of 2026-11-02) | Kept up to date? | Phases covered | Machine-actionable | Remediation value | Role in this skill |
|---|---|---|---|---|---|---|
| **MITRE ATT&CK** (Enterprise + ICS) | v20.0, released 13 Oct 2026 | Yes, two releases a year | Adversary behaviour from recon to impact (not a test process) | **5**: STIX 2.1 bundles, stable `Txxxx` / `Mxxxx` IDs, Navigator layers | 4: mitigations (`M1xxx` / `M0xxx`) and detection data per technique | Mapping language for every finding, SOC detection tickets, Navigator heat maps. ICS matrix for plant findings |
| **OWASP WSTG** | v4.2 stable (2020); v5 in development | Yes, actively edited | Web testing: info gathering, config, identity, authn, authz, session, input validation, crypto, business logic, client side, APIs | **4**: `WSTG-<CAT>-<NN>` IDs, JSON checklist | 3: each test has remediation notes; the fixes themselves live in ASVS and the Cheat Sheets | Test IDs for every AppSec finding (with version prefix `WSTG-v42-`) |
| **NIST SP 800-115** | 2008 final, never revised | No | Planning, discovery, attack, reporting; rules of engagement, roles, data handling | 2: prose only | 3: reporting and mitigation-tracking advice | Engagement planning, rules of engagement, report structure, "post-test mitigation" activities |
| **OSSTMM** | 3.0 (2010); version 4 still a draft | Slow | Channels (human, physical, wireless, telecom, data networks); operational-security metrics | 2: prose and spreadsheets | 2: measures exposure rather than prescribing fixes | Inspiration for the Visibility / Access / Trust indicator in the report (simplified, not a rav calculation) |
| **PTES** | 7 phases; site last edited around 2014 | No | Pre-engagement → intelligence gathering → threat modeling → vulnerability analysis → exploitation → post-exploitation → reporting | 2: wiki prose | 2: the reporting section asks for remediation, without a structure | Process spine: the skill starts where PTES "Reporting" begins |
| **ISSAF** | 0.2.1 (around 2006); project inactive | No | Planning, assessment, reporting, clean-up | 1 | 1 | Excluded: obsolete tool references and no maintained source |

## Supporting standards that make the output usable (not in the NetAcad list)

| Standard | Why it is needed |
|---|---|
| **CVSS v4.0** (FIRST) | Technical severity. Ratings: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0 |
| **CISA KEV** catalog | Proof of active exploitation. Version 2026.10.30 had 1,766 entries. BOD 22-01 and BOD 26-04 deadlines apply to US federal agencies |
| **FIRST EPSS** | Probability of exploitation activity in the next 30 days. The model has been at v5 since 2026-06-15 |
| **SSVC** (CERT/CC, CISA) | Decision tree idea: exploitation × exposure × impact → act now, or track. The skill uses its own simplified variant |
| **MITRE D3FEND** 1.6.0 | Defensive technique IDs that tell IT and the SOC *what kind* of control to add |
| **CWE** | Weakness class, links the finding to developer training and ASVS |

## Conclusion

No single framework gets you from finding to fix. The combination that works:

- **PTES** as the process spine,
- **NIST SP 800-115** for planning, rules of engagement and reporting,
- **OWASP WSTG v4.2** IDs for anything web,
- **MITRE ATT&CK v20** (Enterprise and ICS) plus **D3FEND** as the shared language for mapping, mitigations and SOC detections,
- OSSTMM 3 for exposure metrics, used as an idea only.

ATT&CK and WSTG are the most machine-actionable: they publish stable IDs and structured data, so the agent can validate them (`scripts/verify_ids.py`). ISSAF is obsolete and is left out. None of the six covers prioritization or ownership, so the skill adds CVSS v4, KEV, EPSS, an SSVC-style decision, and a RACI matrix by department. That ownership layer is what turns a test report into work a company can actually do.

## Sources

- MITRE ATT&CK updates and v20 release notes: https://attack.mitre.org/resources/updates/ and STIX data: https://github.com/mitre-attack/attack-stix-data
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/ and https://github.com/OWASP/wstg
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
- OSSTMM 3: https://www.isecom.org/research.html
- PTES: http://www.pentest-standard.org/ (secondary summaries were used where the site timed out)
- ISSAF 0.2.1 (OISSG, archived copies)
- CVSS v4.0: https://www.first.org/cvss/v4-0/
- EPSS: https://www.first.org/epss/ and API https://api.first.org/data/v1/epss
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- SSVC: https://certcc.github.io/SSVC/
- MITRE D3FEND: https://d3fend.mitre.org/
