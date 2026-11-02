# Security Operations Center (SOC)

NovaRefino Demo Corp (fictitious) | 2026-11-09 | 11 Tickets

Lead: Lucia Ferrer (fictitious) <soc@novarefino.example>

---

## SOC-001: [P1] Interim detection while F-002 is open: T1190, T1210 on Citrix gateway

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-002 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC, NETWORK |

**Context:** Citrix gateway | portal.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99999 | ACT (exploitation=active, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Business impact:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-002.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-4966

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/a:citrix:netscaler_gateway:13.1: |     	CVE-2023-4966	9.4	https://vulners.com/cve/CVE-2023-4966	*EXPLOIT*
```
</details>


---

## SOC-002: [P1] Interim detection while F-003 is open: T1190, T1210 on Engineering workstation (DCS/PLC programming)

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-003 |
| RACI | R: SOC | A: MGMT | C: IT-INFRA, APPSEC-DEV | I: SOC |

**Context:** Engineering workstation (DCS/PLC programming) | ews01.ot.novarefino.example:3389 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99999 | ACT (exploitation=active, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Business impact:** Engineering workstation (DCS/PLC programming) supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-003.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2019-0708

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_7: |     	CVE-2019-0708	9.8	https://vulners.com/cve/CVE-2019-0708	*EXPLOIT*
```
</details>


---

## SOC-003: [P1] Interim detection while F-005 is open: T1190, T1210 on Domain controller

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-005 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC, IAM |

**Context:** Domain controller | dc01.corp.novarefino.example:445 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99389 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Business impact:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-005.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2020-1472

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_server_2016: |     	CVE-2020-1472	10.0	https://vulners.com/cve/CVE-2020-1472	*EXPLOIT*
```
</details>


---

## SOC-004: [P1] Interim detection while F-006 is open: T1190, T1210 on Message broker

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-006 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Context:** Message broker | mq01.corp.novarefino.example:61616 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Business impact:** Message broker supports 'ERP to MES integration' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-006.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2023-46604

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/a:apache:activemq:5.17.5: |     	CVE-2023-46604	10.0	https://vulners.com/cve/CVE-2023-46604	*EXPLOIT*
```
</details>


---

## SOC-005: [P1] Interim detection while F-007 is open: T1190, T1210 on Maintenance planning app

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-007 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Context:** Maintenance planning app | maint-app.corp.novarefino.example:8080 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99999 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=4/5)

**Business impact:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-007.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-44228

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/a:apache:log4j:2.14.1: |     	CVE-2021-44228	10.0	https://vulners.com/cve/CVE-2021-44228	*EXPLOIT*
```
</details>


---

## SOC-006: [P1] Interim detection while F-008 is open: T1190, T1210 on Intranet web server

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P1** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-008 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV | I: SOC |

**Context:** Intranet web server | intranet.corp.novarefino.example:80 | Critical CVSS v4 9.3 | KEV: yes | EPSS: 0.99992 | ACT (exploitation=active, exposure=internal, technical_impact=total, asset_criticality=2/5)

**Business impact:** Intranet web server supports 'Employee intranet' (criticality 2/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Steps to apply

1. Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.
2. Map the rule to ATT&CK T1190, T1210 and tag alerts with F-008.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2021-41773, CVE-2021-42013, CVE-2023-25690, CVE-2022-22720

<details><summary>Evidence from the test</summary>

```
nmap NSE vulners: cpe:/a:apache:http_server:2.4.49: |     	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773	*EXPLOIT* |     	CVE-2021-42013	9.8	https://vulners.com/cve/CVE-2021-42013	*EXPLOIT* |     	CVE-2022-22720	9.8	https://vulners.com/cve/CVE-2022-22720 |     	CVE-2023-25690	9.8	https://vulners.com/cve/CVE-2023-25690
```
</details>


---

## SOC-007: [P2] Interim detection while F-009 is open: T0883, T0886, T1692 on PLC crude distillation unit

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P2** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-009 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Context:** PLC crude distillation unit | plc-cdu-01.ot.novarefino.example:502 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Business impact:** PLC crude distillation unit supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Steps to apply

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-009.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidence from the test</summary>

```
nmap: 502/tcp open, service 'modbus Modbus TCP'
```
</details>


---

## SOC-008: [P2] Interim detection while F-010 is open: T0883, T0886, T1692 on PLC utilities (steam/cooling water)

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P2** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-010 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Context:** PLC utilities (steam/cooling water) | plc-utl-02.ot.novarefino.example:102 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Business impact:** PLC utilities (steam/cooling water) supports 'Utilities' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Steps to apply

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-010.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidence from the test</summary>

```
nmap: 102/tcp open, service 'iso-tsap Siemens S7 PLC'
```
</details>


---

## SOC-009: [P2] Interim detection while F-012 is open: T0883, T0886, T1692 on OPC UA historian gateway

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P2** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-012 |
| RACI | R: SOC | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Context:** OPC UA historian gateway | opc-hist01.ot.novarefino.example:4840 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=4/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Business impact:** OPC UA historian gateway supports 'Process data to IT (historian)' (criticality 4/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Steps to apply

1. SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.
2. Map the rule to ATT&CK T0883, T0886, T1692 and tag alerts with F-012.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidence from the test</summary>

```
nmap: 4840/tcp open, service 'opcua-tcp OPC UA Server'
```
</details>


---

## SOC-010: [P2] Interim detection while F-018 is open: T1190, T1213 on ERP database

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P2** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-018 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Context:** ERP database | erp-db01.corp.novarefino.example:1433 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Steps to apply

1. SOC: alert on database logins from hosts outside the application tier.
2. Map the rule to ATT&CK T1190, T1213 and tag alerts with F-018.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidence from the test</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>


---

## SOC-011: [P2] Interim detection while F-019 is open: T1190, T1213 on ERP database

| Field | Value |
|---|---|
| Type | detection |
| Priority | **P2** |
| Due date | **2026-11-11** |
| Department | Security Operations Center (SOC) |
| Finding | F-019 |
| RACI | R: SOC | A: MGMT | C: APPSEC-DEV, NETWORK, GRC-DPO | I: SOC |

**Context:** ERP database | erp-db01.corp.novarefino.example:5432 | High CVSS v4 8.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.

### Steps to apply

1. SOC: alert on database logins from hosts outside the application tier.
2. Map the rule to ATT&CK T1190, T1213 and tag alerts with F-019.
3. Keep the rule active until the fix ticket is verified closed.

### Definition of done (verification)

- Trigger a safe simulation of the technique and confirm the alert reaches the SOC queue.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1213 | Mitigations: M1035, M1030, M1026 | D3FEND: D3-NI, D3-ITF, D3-UAP | WSTG: WSTG-v42-CONF-01 | CWE: CWE-668

<details><summary>Evidence from the test</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>

