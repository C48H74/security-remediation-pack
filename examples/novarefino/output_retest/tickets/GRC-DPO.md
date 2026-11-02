# Legal, Compliance & Data Protection Officer (GRC-DPO)

NovaRefino Demo Corp (fictitious) | 2026-11-09 | 2 Tickets

Lead: Elena Sanz (fictitious) <dpo@novarefino.example>

---

## GRC-DPO-001: [P2] Assess personal-data impact of F-018 on ERP database

| Field | Value |
|---|---|
| Type | compliance |
| Priority | **P2** |
| Due date | **2026-11-23** |
| Department | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Finding | F-018 |
| RACI | R: GRC-DPO | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Context:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Steps to apply

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Definition of done (verification)

- Decision recorded with date and signatory.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidence from the test</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>


---

## GRC-DPO-002: [P2] Assess personal-data impact of F-019 on ERP database

| Field | Value |
|---|---|
| Type | compliance |
| Priority | **P2** |
| Due date | **2026-11-23** |
| Department | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Finding | F-019 |
| RACI | R: GRC-DPO | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Context:** ERP database | erp-db01.corp.novarefino.example:5432 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Steps to apply

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Definition of done (verification)

- Decision recorded with date and signatory.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidence from the test</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>

