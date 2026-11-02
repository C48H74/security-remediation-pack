# Security Operations Center (SOC)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 21 Tickets

Lead: Lucia Ferrer (fictitious) <soc@novarefino.example>

---

## SOC-001: [P1] Interim detection while F-001 is open: T1190, T1210 on Perimeter firewall / VPN

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-001 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC, NETWORK |

**Contexto:** Perimeter firewall / VPN | vpn.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internet, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Perimeter firewall / VPN supports 'Remote access for staff and contractors' (criticality 5/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-001.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2024-3400

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:paloaltonetworks:pan-os:10.2.9: |     	CVE-2024-3400	10.0	https://vulners.com/cve/CVE-2024-3400	*EXPLOIT*
```
</details>


---

## SOC-002: [P1] Interim detection while F-002 is open: T1190, T1210 on Citrix gateway

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-002 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC, NETWORK |

**Contexto:** Citrix gateway | portal.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-002.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-4966

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:citrix:netscaler_gateway:13.1: |     	CVE-2023-4966	9.4	https://vulners.com/cve/CVE-2023-4966	*EXPLOIT*
```
</details>


---

## SOC-003: [P1] Interim detection while F-003 is open: T1190, T1210 on Engineering workstation (DCS/PLC programming)

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-003 |
| RACI | R: SOC | A: MGMT | C: IT-INFRA, APPSEC-DEV | I: SOC |

**Contexto:** Engineering workstation (DCS/PLC programming) | ews01.ot.novarefino.example:3389 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** Engineering workstation (DCS/PLC programming) supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-003.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2019-0708

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_7: |     	CVE-2019-0708	9.8	https://vulners.com/cve/CVE-2019-0708	*EXPLOIT*
```
</details>


---

## SOC-004: [P1] Interim detection while F-004 is open: T1210, T1021.002 on HR file server

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-004 |
| RACI | R: SOC | A: MGMT | C: NETWORK, GRC-DPO | I: SOC |

**Contexto:** HR file server | fs01.corp.novarefino.example:445 | Critical CVSS v4 10.0 | KEV: sí | EPSS: 0.9923 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** HR file server supports 'HR records and payroll exports' (criticality 4/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. SOC: alert on SMBv1 negotiation and on lateral SMB connections between workstations.
2. Map the rule to ATT&CK T1210, T1021.002 and tag alerts with F-004.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1210, T1021.002 | Mitigations: M1042, M1051, M1037 | D3FEND: D3-SU, D3-ACH, D3-ITF | CWE: CWE-477 | CVE: CVE-2017-0144, CVE-2017-0143, CVE-2017-0145

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE smb-vuln-ms17-010: VULNERABLE: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) |     State: VULNERABLE |     IDs:  CVE:CVE-2017-0143 || Nessus plugin 97833: The remote host is affected by the SMBv1 remote code execution vulnerabilities.
```
</details>


---

## SOC-005: [P1] Interim detection while F-005 is open: T1190, T1210 on Domain controller

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-005 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC, IAM |

**Contexto:** Domain controller | dc01.corp.novarefino.example:445 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99389 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-005.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2020-1472

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_server_2016: |     	CVE-2020-1472	10.0	https://vulners.com/cve/CVE-2020-1472	*EXPLOIT*
```
</details>


---

## SOC-006: [P1] Interim detection while F-006 is open: T1190, T1210 on Message broker

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-006 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Message broker | mq01.corp.novarefino.example:61616 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Message broker supports 'ERP to MES integration' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-006.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-46604

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:activemq:5.17.5: |     	CVE-2023-46604	10.0	https://vulners.com/cve/CVE-2023-46604	*EXPLOIT*
```
</details>


---

## SOC-007: [P1] Interim detection while F-007 is open: T1190, T1210 on Maintenance planning app

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-007 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Maintenance planning app | maint-app.corp.novarefino.example:8080 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-007.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-44228

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:log4j:2.14.1: |     	CVE-2021-44228	10.0	https://vulners.com/cve/CVE-2021-44228	*EXPLOIT*
```
</details>


---

## SOC-008: [P1] Interim detection while F-008 is open: T1190, T1210 on Intranet web server

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P1** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-008 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Intranet web server | intranet.corp.novarefino.example:80 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=2/5)

**Impacto de negocio:** Intranet web server supports 'Employee intranet' (criticality 2/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-008.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-41773, CVE-2021-42013, CVE-2023-25690, CVE-2022-22720

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/a:apache:http_server:2.4.49: |     	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773	*EXPLOIT* |     	CVE-2021-42013	9.8	https://vulners.com/cve/CVE-2021-42013	*EXPLOIT* |     	CVE-2022-22720	9.8	https://vulners.com/cve/CVE-2022-22720 |     	CVE-2023-25690	9.8	https://vulners.com/cve/CVE-2023-25690
```
</details>


---

## SOC-009: [P2] Interim detection while F-009 is open: T0883, T0886, T1692 on PLC crude distillation unit

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-009 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** PLC crude distillation unit | plc-cdu-01.ot.novarefino.example:502 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** PLC crude distillation unit supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-009.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 502/tcp open, service 'modbus Modbus TCP'
```
</details>


---

## SOC-010: [P2] Interim detection while F-010 is open: T0883, T0886, T1692 on PLC utilities (steam/cooling water)

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-010 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** PLC utilities (steam/cooling water) | plc-utl-02.ot.novarefino.example:102 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** PLC utilities (steam/cooling water) supports 'Utilities' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-010.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 102/tcp open, service 'iso-tsap Siemens S7 PLC'
```
</details>


---

## SOC-011: [P2] Interim detection while F-011 is open: T1078.001 on HMI crude distillation unit

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-011 |
| RACI | R: SOC | A: MGMT | C: IAM, IT-INFRA | I: SOC |

**Contexto:** HMI crude distillation unit | hmi-cdu-01.ot.novarefino.example:80 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** HMI crude distillation unit supports 'Operator console' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could log in as a legitimate user and bypass most other controls.

### Pasos a aplicar

1. SOC: alert on any successful login with a known vendor account name.
2. Map the rule to ATT&CK T1078.001 and tag alerts with F-011.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1078.001 | Mitigations: M1027, M1026 | D3FEND: D3-CH, D3-SPP | WSTG: WSTG-v42-ATHN-02 | CWE: CWE-1392

<details><summary>Evidencia de la prueba</summary>

```
Login with vendor default account succeeded (read-only test, no values changed)
```
</details>


---

## SOC-012: [P2] Interim detection while F-012 is open: T0883, T0886, T1692 on OPC UA historian gateway

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-012 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** OPC UA historian gateway | opc-hist01.ot.novarefino.example:4840 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=4/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** OPC UA historian gateway supports 'Process data to IT (historian)' (criticality 4/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-012.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 4840/tcp open, service 'opcua-tcp OPC UA Server'
```
</details>


---

## SOC-013: [P2] Interim detection while F-013 is open: T1190 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-013 |
| RACI | R: SOC | A: MGMT | C: IT-INFRA, GRC-DPO | I: SOC, NETWORK |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Pasos a aplicar

1. SOC: WAF/application log rule for SQL error strings and injection payload signatures on this endpoint.
2. Map the rule to ATT&CK T1190 and tag alerts with F-013.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190 | Mitigations: M1048, M1050, M1016 | D3FEND: D3-ACH | WSTG: WSTG-v42-INPV-05, WSTG-v42-INPV-12 | CWE: CWE-89

<details><summary>Evidencia de la prueba</summary>

```
ZAP plugin 40018, risk 3: https://suppliers.novarefino.example/catalog/search?q=valve | evidence: q || Burp high/certain: /catalog/search [q parameter]
```
</details>


---

## SOC-014: [P2] Interim detection while F-014 is open: T1133, T1021.001, T1110 on Admin jump host

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-014 |
| RACI | R: SOC | A: MGMT | C: IAM, IT-INFRA | I: SOC |

**Contexto:** Admin jump host | jump01.novarefino.example:3389 | Critical CVSS v4 9.2 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internet, technical_impact=total, asset_criticality=3/5)

**Impacto de negocio:** Admin jump host supports 'IT administration' (criticality 3/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could reach internal systems directly from an untrusted network.

### Pasos a aplicar

1. SOC: alert on successful logons to this service from non-VPN source ranges and on password-spray patterns.
2. Map the rule to ATT&CK T1133, T1021.001, T1110 and tag alerts with F-014.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1133, T1021.001, T1110 | Mitigations: M1035, M1032, M1030 | D3FEND: D3-ITF, D3-MFA, D3-NI | WSTG: WSTG-v42-CONF-01 | CWE: CWE-284

<details><summary>Evidencia de la prueba</summary>

```
nmap: 3389/tcp open, service 'ms-wbt-server Microsoft Terminal Services'
```
</details>


---

## SOC-015: [P2] Interim detection while F-015 is open: T1530, T1552.001 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-015 |
| RACI | R: SOC | A: MGMT | C: GRC-DPO | I: SOC, NETWORK, APPSEC-DEV |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 8.7 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Impacto de negocio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, confidential or personal data could be read by unauthorised parties, with regulatory exposure (GDPR).

### Pasos a aplicar

1. SOC: review access logs for the exposure window; alert on future public ACL changes.
2. Map the rule to ATT&CK T1530, T1552.001 and tag alerts with F-015.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1530, T1552.001 | Mitigations: M1041, M1022 | D3FEND: D3-FE, D3-UAP | WSTG: WSTG-v42-CONF-04, WSTG-v42-CONF-11 | CWE: CWE-538

<details><summary>Evidencia de la prueba</summary>

```
/.git/config returned 200 with remote URL and branch names
```
</details>


---

## SOC-016: [P2] Interim detection while F-016 is open: T1110, T1078 on Domain controller

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-016 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Domain controller | dc01.corp.novarefino.example | High CVSS v4 8.8 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could log in as a legitimate user and bypass most other controls.

### Pasos a aplicar

1. SOC: password-spray and impossible-travel analytics on the IdP logs.
2. Map the rule to ATT&CK T1110, T1078 and tag alerts with F-016.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1110, T1078 | Mitigations: M1032, M1036, M1027 | D3FEND: D3-MFA, D3-AL, D3-SPP | WSTG: WSTG-v42-ATHN-03, WSTG-v42-ATHN-07 | CWE: CWE-521, CWE-308

<details><summary>Evidencia de la prueba</summary>

```
Default Domain Policy: min length 7, no lockout; Kerberoasting cracked 3 of 12 service account hashes in under 2 h
```
</details>


---

## SOC-017: [P2] Interim detection while F-017 is open: T1190, T1210 on ERP database

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-017 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.7 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-017.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104

<details><summary>Evidencia de la prueba</summary>

```
Nessus plugin 73756: Installed version: 13.0.5026.0 (SQL Server 2016 SP2). Mainstream and extended support status should be checked against vendor lifecycle.
```
</details>


---

## SOC-018: [P2] Interim detection while F-018 is open: T1190, T1213 on ERP database

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-018 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. SOC: alert on database logins from hosts outside the application tier.
2. Map the rule to ATT&CK T1190, T1213 and tag alerts with F-018.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidencia de la prueba</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>


---

## SOC-019: [P2] Interim detection while F-019 is open: T1190, T1213 on ERP database

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-019 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Contexto:** ERP database | erp-db01.corp.novarefino.example:5432 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Impacto de negocio:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Pasos a aplicar

1. SOC: alert on database logins from hosts outside the application tier.
2. Map the rule to ATT&CK T1190, T1213 and tag alerts with F-019.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidencia de la prueba</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>


---

## SOC-020: [P2] Interim detection while F-020 is open: T1190, T1213 on Supplier portal

| Campo | Valor |
|---|---|
| Tipo | detection |
| Prioridad | **P2** |
| Fecha límite | **2026-11-04** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-020 |
| RACI | R: SOC | A: MGMT | C: IAM, GRC-DPO | I: SOC, NETWORK |

**Contexto:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 7.1 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Impacto de negocio:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Pasos a aplicar

1. SOC: alert on a single session enumerating many object IDs in a short window.
2. Map the rule to ATT&CK T1190, T1213 and tag alerts with F-020.
3. Keep the rule active until the fix ticket is verified closed.

### Criterio de cierre (verificación)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1213 | Mitigations: M1026, M1048 | D3FEND: D3-UAP | WSTG: WSTG-v42-ATHZ-02, WSTG-v42-ATHZ-04 | CWE: CWE-639

<details><summary>Evidencia de la prueba</summary>

```
GET /api/v2/suppliers/1043/bank as supplier 2210 returned IBAN of supplier 1043 (HTTP 200)
```
</details>


---

## SOC-021: [P3] Attack activity not detected or not logged on SIEM / SOC tooling (siem)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P3** |
| Fecha límite | **2026-12-17** |
| Departamento | Security Operations Center (SOC) |
| Hallazgo | F-027 |
| RACI | R: SOC | A: MGMT | C: IT-INFRA | I: - |

**Contexto:** SIEM / SOC tooling | siem | Medium CVSS v4 6.3 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=4/5, category floor P3)

**Impacto de negocio:** SIEM / SOC tooling supports 'Security monitoring' (criticality 4/5, production, zone IT; data: confidential). If exploited, an intrusion could progress without being noticed, increasing dwell time and damage.

### Pasos a aplicar

1. Onboard the missing log source (host, firewall, application) to the SIEM with parsing validated.
2. Create or tune the detection for the ATT&CK techniques used during the test, using the ATT&CK v20 detection strategies as a starting point.
3. Add the scenario to the purple-team regression list.

### Criterio de cierre (verificación)

- Replay the test activity (atomic test) and confirm an alert is raised and triaged within the SOC SLA.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1046, T1110 | Mitigations: M1047 | D3FEND: D3-NTA, D3-UBA, D3-PM | CWE: CWE-778

<details><summary>Evidencia de la prueba</summary>

```
Full nmap sweep and 600 spraying attempts over 2 days; no ticket raised by SOC
```
</details>

