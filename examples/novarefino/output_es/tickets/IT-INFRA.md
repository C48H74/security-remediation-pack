# IT Infrastructure & Operations (IT-INFRA)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 15 Tickets

Lead: Jordi Puig (fictitious) <it-infra@novarefino.example>

---

## IT-INFRA-001: [P1] Outdated software with known vulnerabilities on Perimeter firewall / VPN (vpn.novarefino.example:443)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-001 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC, NETWORK |

**Contexto:** Perimeter firewall / VPN | vpn.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internet, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Perimeter firewall / VPN supports 'Remote access for staff and contractors' (criticality 5/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2024-3400

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:paloaltonetworks:pan-os:10.2.9: |     	CVE-2024-3400	10.0	https://vulners.com/cve/CVE-2024-3400	*EXPLOIT*
```
</details>


---

## IT-INFRA-002: [P1] Outdated software with known vulnerabilities on Citrix gateway (portal.novarefino.example:443)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-002 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC, NETWORK |

**Contexto:** Citrix gateway | portal.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-4966

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:citrix:netscaler_gateway:13.1: |     	CVE-2023-4966	9.4	https://vulners.com/cve/CVE-2023-4966	*EXPLOIT*
```
</details>


---

## IT-INFRA-003: [P1] Legacy SMBv1 enabled / SMB exposed on HR file server (fs01.corp.novarefino.example:445)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-004 |
| RACI | R: IT-INFRA | A: MGMT | C: NETWORK, GRC-DPO | I: SOC |

**Contexto:** HR file server | fs01.corp.novarefino.example:445 | Critical CVSS v4 10.0 | KEV: sí | EPSS: 0.9923 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** HR file server supports 'HR records and payroll exports' (criticality 4/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Disable SMBv1 on the server and clients (Windows feature removal or GPO) after checking that no legacy device still depends on it.
2. Scanner guidance: Apply the vendor security update for SMB server and disable SMBv1.
3. Install the cumulative security update that covers the listed CVEs.
4. Restrict TCP 445 to the subnets that need file services; never expose it to the internet or to the OT zone.

### Criterio de cierre (verificación)

- nmap -p445 --script smb-protocols <host> must not list SMBv1 (NT LM 0.12).
- nmap -p445 --script smb-vuln-ms17-010 <host> must report not vulnerable.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1210, T1021.002 | Mitigations: M1042, M1051, M1037 | D3FEND: D3-SU, D3-ACH, D3-ITF | CWE: CWE-477 | CVE: CVE-2017-0144, CVE-2017-0143, CVE-2017-0145

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE smb-vuln-ms17-010: VULNERABLE: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) |     State: VULNERABLE |     IDs:  CVE:CVE-2017-0143 || Nessus plugin 97833: The remote host is affected by the SMBv1 remote code execution vulnerabilities.
```
</details>


---

## IT-INFRA-004: [P1] Outdated software with known vulnerabilities on Domain controller (dc01.corp.novarefino.example:445)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-005 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC, IAM |

**Contexto:** Domain controller | dc01.corp.novarefino.example:445 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99389 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2020-1472

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_server_2016: |     	CVE-2020-1472	10.0	https://vulners.com/cve/CVE-2020-1472	*EXPLOIT*
```
</details>


---

## IT-INFRA-005: [P1] Outdated software with known vulnerabilities on Message broker (mq01.corp.novarefino.example:61616)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-006 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Message broker | mq01.corp.novarefino.example:61616 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Message broker supports 'ERP to MES integration' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-46604

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:activemq:5.17.5: |     	CVE-2023-46604	10.0	https://vulners.com/cve/CVE-2023-46604	*EXPLOIT*
```
</details>


---

## IT-INFRA-006: [P1] Outdated software with known vulnerabilities on Maintenance planning app (maint-app.corp.novarefino.example:8080)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-007 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Maintenance planning app | maint-app.corp.novarefino.example:8080 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-44228

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:log4j:2.14.1: |     	CVE-2021-44228	10.0	https://vulners.com/cve/CVE-2021-44228	*EXPLOIT*
```
</details>


---

## IT-INFRA-007: [P1] Outdated software with known vulnerabilities on Intranet web server (intranet.corp.novarefino.example:80)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-008 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Intranet web server | intranet.corp.novarefino.example:80 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=2/5)

**Impacto de negocio:** Intranet web server supports 'Employee intranet' (criticality 2/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-41773, CVE-2021-42013, CVE-2023-25690, CVE-2022-22720

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:http_server:2.4.49: |     	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773	*EXPLOIT* |     	CVE-2021-42013	9.8	https://vulners.com/cve/CVE-2021-42013	*EXPLOIT* |     	CVE-2022-22720	9.8	https://vulners.com/cve/CVE-2022-22720 |     	CVE-2023-25690	9.8	https://vulners.com/cve/CVE-2023-25690
```
</details>


---

## IT-INFRA-008: [P2] Sensitive or personal data exposed (public storage, backups, listings) on Supplier portal (suppliers.novarefino.example:443)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-11-16** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-015 |
| RACI | R: IT-INFRA | A: MGMT | C: GRC-DPO | I: SOC, NETWORK, APPSEC-DEV |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 8.7 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, confidential or personal data could be read by unauthorised parties, with regulatory exposure (GDPR).

### Pasos a aplicar

1. Remove public access to the storage/backup location immediately and keep a copy of access logs as evidence.
2. Rotate any secrets found inside the exposed files.
3. DPO assesses whether personal data was accessed and whether a GDPR Art. 33 notification (72 hours) is required.
4. Enable encryption at rest and a policy that blocks public buckets/shares by default.

### Criterio de cierre (verificación)

- Anonymous request to the object/share URL returns 403.
- Cloud posture scan shows the 'block public access' control enabled.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1530, T1552.001 | Mitigations: M1041, M1022 | D3FEND: D3-FE, D3-UAP | WSTG: WSTG-v42-CONF-04, WSTG-v42-CONF-11 | CWE: CWE-538

<details><summary>Evidencia de la prueba</summary>

```
/.git/config returned 200 with remote URL and branch names
```
</details>


---

## IT-INFRA-009: [P2] Outdated software with known vulnerabilities on ERP database (erp-db01.corp.novarefino.example:1433)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-11-16** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-017 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.7 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Scanner guidance: Upgrade to a supported version of SQL Server.
3. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
4. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
5. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104

<details><summary>Evidencia de la prueba</summary>

```
Nessus plugin 73756: Installed version: 13.0.5026.0 (SQL Server 2016 SP2). Mainstream and extended support status should be checked against vendor lifecycle.
```
</details>


---

## IT-INFRA-010: [P2] Database or cache service reachable without network restriction on ERP database (erp-db01.corp.novarefino.example:1433)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-11-16** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-018 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Bind the service to the application subnet only and add a host firewall rule allowing just the app servers.
2. Require authentication and TLS for every client connection; remove anonymous or default accounts.
3. Move the database into a dedicated data tier segment if it currently shares the user VLAN.

### Criterio de cierre (verificación)

- From a user-VLAN host, nmap -p <db port> <host> must report filtered.
- Unauthenticated connection attempt must be refused.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidencia de la prueba</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>


---

## IT-INFRA-011: [P2] Database or cache service reachable without network restriction on ERP database (erp-db01.corp.novarefino.example:5432)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-11-16** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-019 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:5432 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Bind the service to the application subnet only and add a host firewall rule allowing just the app servers.
2. Require authentication and TLS for every client connection; remove anonymous or default accounts.
3. Move the database into a dedicated data tier segment if it currently shares the user VLAN.

### Criterio de cierre (verificación)

- From a user-VLAN host, nmap -p <db port> <host> must report filtered.
- Unauthenticated connection attempt must be refused.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidencia de la prueba</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>


---

## IT-INFRA-012: [P3] Outdated software with known vulnerabilities on Maintenance planning app (maint-app.corp.novarefino.example:22)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P3** |
| Fecha límite | **2026-12-17** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-021 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Maintenance planning app | maint-app.corp.novarefino.example:22 | Critical CVSS v4 9.3 | KEV: no | EPSS: 0.99506 | TRACK* (exploitation=poc, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2024-6387, CVE-2023-48795

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:openbsd:openssh:8.9p1: |     	CVE-2024-6387	8.1	https://vulners.com/cve/CVE-2024-6387 |     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
```
</details>


---

## IT-INFRA-013: [P4] Weak TLS configuration (old protocol versions or ciphers) on Citrix gateway (portal.novarefino.example:443)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P4** |
| Fecha límite | **2027-01-31** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-029 |
| RACI | R: IT-INFRA | A: MGMT | C: APPSEC-DEV | I: NETWORK |

**Contexto:** Citrix gateway | portal.novarefino.example:443 | Medium CVSS v4 6.3 | KEV: no | EPSS: n/a | TRACK (exploitation=none, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Impacto de negocio:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Disable SSLv3, TLS 1.0 and TLS 1.1; keep TLS 1.2 with AEAD ciphers and TLS 1.3.
2. Scanner guidance: Enable TLS 1.2 or 1.3 only.
3. Replace self-signed or expiring certificates with certificates from the corporate or public CA and automate renewal.
4. Apply the change through a shared hardening baseline (Ansible/GPO) so every web front end gets it.

### Criterio de cierre (verificación)

- nmap --script ssl-enum-ciphers -p443 <host> must show no TLS 1.0/1.1 and grade A ciphers only.
- testssl.sh <host> shows no high or critical items.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1557 | Mitigations: M1041 | D3FEND: D3-ET, D3-CA | WSTG: WSTG-v42-CRYP-01 | CWE: CWE-326

<details><summary>Evidencia de la prueba</summary>

```
Nessus plugin 104743: TLSv1.0 is enabled and the server supports at least one cipher.
```
</details>


---

## IT-INFRA-014: [P4] Cleartext management or file-transfer protocol in use on Control room printer (prn-ctrlroom.corp.novarefino.example:21)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P4** |
| Fecha límite | **2027-01-31** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-030 |
| RACI | R: IT-INFRA | A: MGMT | C: NETWORK | I: SOC |

**Contexto:** Control room printer | prn-ctrlroom.corp.novarefino.example:21 | High CVSS v4 7.1 | KEV: no | EPSS: n/a | TRACK (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=1/5)

**Impacto de negocio:** Control room printer supports 'Shift reports printing' (criticality 1/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Replace Telnet with SSH and FTP with SFTP/FTPS; disable the cleartext daemon after migration.
2. Rotate every credential that was ever used over the cleartext protocol.
3. Block the cleartext port at the host firewall so it cannot be re-enabled silently.

### Criterio de cierre (verificación)

- nmap -p 21,23 <host> must report closed/filtered.
- Confirm that the replacement encrypted service accepts logins with rotated credentials.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1040, T1557 | Mitigations: M1041, M1042 | D3FEND: D3-ET, D3-MENCR | WSTG: WSTG-v42-CRYP-03 | CWE: CWE-319

<details><summary>Evidencia de la prueba</summary>

```
nmap: 21/tcp open, service 'ftp vsftpd 3.0.3'
```
</details>


---

## IT-INFRA-015: [P4] Cleartext management or file-transfer protocol in use on Control room printer (prn-ctrlroom.corp.novarefino.example:23)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P4** |
| Fecha límite | **2027-01-31** |
| Departamento | IT Infrastructure & Operations (IT-INFRA) |
| Hallazgo | F-031 |
| RACI | R: IT-INFRA | A: MGMT | C: NETWORK | I: SOC |

**Contexto:** Control room printer | prn-ctrlroom.corp.novarefino.example:23 | High CVSS v4 7.1 | KEV: no | EPSS: n/a | TRACK (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=1/5)

**Impacto de negocio:** Control room printer supports 'Shift reports printing' (criticality 1/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Replace Telnet with SSH and FTP with SFTP/FTPS; disable the cleartext daemon after migration.
2. Rotate every credential that was ever used over the cleartext protocol.
3. Block the cleartext port at the host firewall so it cannot be re-enabled silently.

### Criterio de cierre (verificación)

- nmap -p 21,23 <host> must report closed/filtered.
- Confirm that the replacement encrypted service accepts logins with rotated credentials.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1040, T1557 | Mitigations: M1041, M1042 | D3FEND: D3-ET, D3-MENCR | WSTG: WSTG-v42-CRYP-03 | CWE: CWE-319

<details><summary>Evidencia de la prueba</summary>

```
nmap: 23/tcp open, service 'telnet Busybox telnetd'
```
</details>

