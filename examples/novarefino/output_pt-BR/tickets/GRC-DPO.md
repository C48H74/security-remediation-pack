# Legal, Compliance & Data Protection Officer (GRC-DPO)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 7 Tickets

Lead: Elena Sanz (fictitious) <dpo@novarefino.example>

---

## GRC-DPO-001: [P1] Assess personal-data impact of F-004 on HR file server

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P1** |
| Prazo | **2026-11-05** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-004 |
| RACI | R: GRC-DPO | A: MGMT | C: NETWORK, GRC-DPO | I: SOC |

**Contexto:** HR file server | fs01.corp.novarefino.example:445 | Critical CVSS v4 10.0 | KEV: sim | EPSS: 0.9923 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto no negócio:** HR file server supports 'HR records and payroll exports' (criticality 4/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1210, T1021.002 | Mitigations: M1042, M1051, M1037 | D3FEND: D3-SU, D3-ACH, D3-ITF | CWE: CWE-477 | CVE: CVE-2017-0144, CVE-2017-0143, CVE-2017-0145

<details><summary>Evidência do teste</summary>

```
nmap NSE smb-vuln-ms17-010: VULNERABLE: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) |     State: VULNERABLE |     IDs:  CVE:CVE-2017-0143 || Nessus plugin 97833: The remote host is affected by the SMBv1 remote code execution vulnerabilities.
```
</details>


---

## GRC-DPO-002: [P2] Assess personal-data impact of F-013 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-013 |
| RACI | R: GRC-DPO | A: MGMT | C: IT-INFRA, GRC-DPO | I: SOC, NETWORK |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: não | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto no negócio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1190 | Mitigations: M1048, M1050, M1016 | D3FEND: D3-ACH | WSTG: WSTG-v42-INPV-05, WSTG-v42-INPV-12 | CWE: CWE-89

<details><summary>Evidência do teste</summary>

```
ZAP plugin 40018, risk 3: https://suppliers.novarefino.example/catalog/search?q=valve | evidence: q || Burp high/certain: /catalog/search [q parameter]
```
</details>


---

## GRC-DPO-003: [P2] Assess personal-data impact of F-015 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-015 |
| RACI | R: GRC-DPO | A: MGMT | C: GRC-DPO | I: SOC, NETWORK, APPSEC-DEV |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 8.7 | KEV: não | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto no negócio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, confidential or personal data could be read by unauthorised parties, with regulatory exposure (GDPR).

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1530, T1552.001 | Mitigations: M1041, M1022 | D3FEND: D3-FE, D3-UAP | WSTG: WSTG-v42-CONF-04, WSTG-v42-CONF-11 | CWE: CWE-538

<details><summary>Evidência do teste</summary>

```
/.git/config returned 200 with remote URL and branch names
```
</details>


---

## GRC-DPO-004: [P2] Assess personal-data impact of F-017 on ERP database

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-017 |
| RACI | R: GRC-DPO | A: MGMT | C: APPSEC-DEV, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.7 | KEV: não | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto no negócio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104

<details><summary>Evidência do teste</summary>

```
Nessus plugin 73756: Installed version: 13.0.5026.0 (SQL Server 2016 SP2). Mainstream and extended support status should be checked against vendor lifecycle.
```
</details>


---

## GRC-DPO-005: [P2] Assess personal-data impact of F-018 on ERP database

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-018 |
| RACI | R: GRC-DPO | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.3 | KEV: não | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto no negócio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidência do teste</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>


---

## GRC-DPO-006: [P2] Assess personal-data impact of F-019 on ERP database

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-019 |
| RACI | R: GRC-DPO | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:5432 | High CVSS v4 8.3 | KEV: não | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto no negócio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidência do teste</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>


---

## GRC-DPO-007: [P2] Assess personal-data impact of F-020 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | compliance |
| Prioridade | **P2** |
| Prazo | **2026-11-16** |
| Departamento | Legal, Compliance & Data Protection Officer (GRC-DPO) |
| Achado | F-020 |
| RACI | R: GRC-DPO | A: MGMT | C: IAM, GRC-DPO | I: SOC, NETWORK |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 7.1 | KEV: não | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Impacto no negócio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Passos para aplicar

1. Check access logs for the exposure window together with SOC.
2. Decide whether the incident threshold for GDPR Art. 33 notification (72 h to the authority) is met and document the decision.
3. Record the finding and treatment in the risk register / RoPA.

### Critério de pronto (verificação)

- Decision recorded with date and signatory.

- Anexe a evidência da verificação a este ticket e mova para *Pronto para reteste*. O avaliador fecha após o novo scan.

**Referências:** ATT&CK v20: T1190, T1213 | Mitigations: M1026, M1048 | D3FEND: D3-UAP | WSTG: WSTG-v42-ATHZ-02, WSTG-v42-ATHZ-04 | CWE: CWE-639

<details><summary>Evidência do teste</summary>

```
GET /api/v2/suppliers/1043/bank as supplier 2210 returned IBAN of supplier 1043 (HTTP 200)
```
</details>

