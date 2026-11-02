# Security Remediation Package: NovaRefino Demo Corp (fictitious)

**Report date:** 2026-11-09  
**Scope:** Network rescan after first P1 fixes (nmap only)  
**Classification:** CONFIDENTIAL. Share per department on a need-to-know basis.

---

## 1. Executive summary

16 findings across 13 assets were consolidated from 1 sources. 6 need action within 3 days (P1) and 5 within the next SLA window (P2).

6 findings involve vulnerabilities on the CISA KEV list (exploited in the wild). 4 findings affect the OT / plant zone and are routed to OT Engineering under Management of Change.

Work is distributed to 6 departments as 30 tickets. The largest fix workload sits with IT Infrastructure & Operations (IT-INFRA, 10 fix tickets); the SOC also receives interim detection tickets for every open P1/P2.

Retest vs baseline: 3 fixed and verified, 16 still open, 0 new, 12 not retested in this run (they remain open).

| P1 | P2 | P3 | P4 | KEV | OT | Tickets |
|---|---|---|---|---|---|---|
| 6 | 5 | 3 | 2 | 6 | 4 | 30 |

### What management needs to decide this week

1. Approve the owners and due dates in section 3 (ticket `MGMT-001`).
2. Free capacity for every P1 item: the target is containment within 72 hours.
3. Formally accept, with a named owner and an expiry date, any risk that will not be fixed inside its SLA.

## 2. Prioritised findings

Priority is **P1 (ACT)**, **P2 (ATTEND)**, **P3 (TRACK\*)** or **P4 (TRACK)**. It comes from an SSVC-inspired decision that weighs exploitation evidence (CISA KEV, FIRST EPSS, public exploit), exposure (internet / OT / internal), technical impact (CVSS v4.0) and the asset's business criticality.

| ID | Priority | Severity | CVSS v4 | KEV | EPSS | Finding | Asset | Responsible | Due | ATT&CK |
|---|---|---|---|---|---|---|---|---|---|---|
| F-002 | **P1** | Critical | 9.3 | Y | 1.00 | Citrix NetScaler Gateway 13.1-48.47: CVE-2023-4966 | Citrix gateway | IT-INFRA | 2026-11-12 | T1190, T1210 |
| F-003 | **P1** | Critical | 9.3 | Y | 1.00 | Microsoft Terminal Services: CVE-2019-0708 | Engineering workstation (DCS/PLC… | OT-ENG | 2026-11-12 | T1190, T1210 |
| F-005 | **P1** | Critical | 9.3 | Y | 0.99 | Microsoft Windows Server 2016: CVE-2020-1472 | Domain controller | IT-INFRA | 2026-11-12 | T1190, T1210 |
| F-006 | **P1** | Critical | 9.3 | Y | 1.00 | ActiveMQ OpenWire transport 5.17.5: CVE-2023-46604 | Message broker | IT-INFRA | 2026-11-12 | T1190, T1210 |
| F-007 | **P1** | Critical | 9.3 | Y | 1.00 | Apache Tomcat 9.0.31: CVE-2021-44228 | Maintenance planning app | IT-INFRA | 2026-11-12 | T1190, T1210 |
| F-008 | **P1** | Critical | 9.3 | Y | 1.00 | Apache httpd 2.4.49: CVE-2021-41773 +3 more | Intranet web server | IT-INFRA | 2026-11-12 | T1190, T1210 |
| F-009 | **P2** | Critical | 9.3 | - | - | Modbus/TCP exposed on 502/tcp | PLC crude distillation unit | OT-ENG | 2026-12-09 | T0883, T0886, T1692 |
| F-010 | **P2** | Critical | 9.3 | - | - | Siemens S7comm exposed on 102/tcp | PLC utilities (steam/cooling water) | OT-ENG | 2026-12-09 | T0883, T0886, T1692 |
| F-012 | **P2** | Critical | 9.3 | - | - | OPC UA exposed on 4840/tcp | OPC UA historian gateway | OT-ENG | 2026-12-09 | T0883, T0886, T1692 |
| F-018 | **P2** | High | 8.3 | - | - | Database/cache exposed on 1433/tcp | ERP database | IT-INFRA | 2026-11-23 | T1190, T1213 |
| F-019 | **P2** | High | 8.3 | - | - | Database/cache exposed on 5432/tcp | ERP database | IT-INFRA | 2026-11-23 | T1190, T1213 |
| F-021 | **P3** | Critical | 9.3 | - | 1.00 | OpenSSH 8.9p1: CVE-2024-6387 +1 more | Maintenance planning app | IT-INFRA | 2026-12-24 | T1190, T1210 |
| F-022 | **P3** | Critical | 9.2 | - | - | VNC exposed on 5900/tcp | 10.10.9.99 (not in inventory) | NETWORK | 2026-12-24 | T1133, T1021.001, T1110 |
| F-024 | **P3** | Medium | 6.9 | - | - | SNMP exposed on 161/udp (unauthenticated read) | Core switch | NETWORK | 2026-12-24 | T1046, T1078.001 |
| F-030 | **P4** | High | 7.1 | - | - | FTP exposed on 21/tcp | Control room printer | IT-INFRA | 2027-02-07 | T1040, T1557 |
| F-031 | **P4** | High | 7.1 | - | - | Telnet exposed on 23/tcp | Control room printer | IT-INFRA | 2027-02-07 | T1040, T1557 |

## 3. Work distribution by department

Every finding has exactly one Accountable role and at least one Responsible department. While a P1/P2 fix is pending, the SOC receives a parallel detection ticket.

| Department | Tickets | P1 | P2 | P3 | P4 | Next due |
|---|---|---|---|---|---|---|
| Management / CISO office (MGMT) | 1 | 1 | 0 | 0 | 0 | 2026-11-11 |
| IT Infrastructure & Operations (IT-INFRA) | 10 | 5 | 2 | 1 | 2 | 2026-11-12 |
| Network & Perimeter (NETWORK) | 2 | 0 | 0 | 2 | 0 | 2026-12-24 |
| Security Operations Center (SOC) | 11 | 6 | 5 | 0 | 0 | 2026-11-11 |
| OT / Plant Engineering & Automation (OT-ENG) | 4 | 1 | 3 | 0 | 0 | 2026-11-12 |
| Legal, Compliance & Data Protection Officer (GRC-DPO) | 2 | 0 | 2 | 0 | 0 | 2026-11-23 |

Ticket files: `tickets/<DEPT>.md` (human readable), `tickets/<DEPT>.csv` and `.json`; consolidated `jira_import.csv`, `servicenow_import.json` and `defectdojo_generic.json`.

## 4. Operational security indicator

| Visibility (hosts with findings) | Access (exposed services) | Trust (services accepting unauthenticated or implicit-trust interaction) | Porosity V+A+T |
|---|---|---|---|
| 13 | 16 | 8 | **37** |

_Simplified indicator inspired by OSSTMM 3 operational-security metrics (visibility, access, trust). It is not an OSSTMM rav calculation; use it to track the trend between retests._

## 5. Finding details and fix steps

### F-002 [P1 / ACT] Citrix NetScaler Gateway 13.1-48.47: CVE-2023-4966

- **Asset:** Citrix gateway (portal.novarefino.example:443)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2023-4966 | EPSS 0.99999 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internet; technical_impact=total; asset_criticality=4/5), risk score 100/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2023-4966
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC, NETWORK | SLA 3 d, Due 2026-11-12

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/a:citrix:netscaler_gateway:13.1: |     	CVE-2023-4966	9.4	https://vulners.com/cve/CVE-2023-4966	*EXPLOIT*
```
</details>

### F-003 [P1 / ACT] Microsoft Terminal Services: CVE-2019-0708

- **Asset:** Engineering workstation (DCS/PLC programming) (ews01.ot.novarefino.example:3389)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2019-0708 | EPSS 0.99999 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=ot; technical_impact=total; asset_criticality=5/5), risk score 100/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset sits in the plant control (OT) zone, a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** Engineering workstation (DCS/PLC programming) supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2019-0708
- **RACI:** R OT-ENG | A MGMT | C IT-INFRA, APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-12
- > Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.
- > OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_7: |     	CVE-2019-0708	9.8	https://vulners.com/cve/CVE-2019-0708	*EXPLOIT*
```
</details>

### F-005 [P1 / ACT] Microsoft Windows Server 2016: CVE-2020-1472

- **Asset:** Domain controller (dc01.corp.novarefino.example:445)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2020-1472 | EPSS 0.99389 (pctl 0.999)
- **Decision:** ACT (exploitation=active; exposure=internal; technical_impact=total; asset_criticality=5/5), risk score 95.7/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2020-1472
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC, IAM | SLA 3 d, Due 2026-11-12

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_server_2016: |     	CVE-2020-1472	10.0	https://vulners.com/cve/CVE-2020-1472	*EXPLOIT*
```
</details>

### F-006 [P1 / ACT] ActiveMQ OpenWire transport 5.17.5: CVE-2023-46604

- **Asset:** Message broker (mq01.corp.novarefino.example:61616)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2023-46604 | EPSS 0.99992 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internal; technical_impact=total; asset_criticality=4/5), risk score 93.8/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Message broker supports 'ERP to MES integration' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2023-46604
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-12

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/a:apache:activemq:5.17.5: |     	CVE-2023-46604	10.0	https://vulners.com/cve/CVE-2023-46604	*EXPLOIT*
```
</details>

### F-007 [P1 / ACT] Apache Tomcat 9.0.31: CVE-2021-44228

- **Asset:** Maintenance planning app (maint-app.corp.novarefino.example:8080)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2021-44228 | EPSS 0.99999 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internal; technical_impact=total; asset_criticality=4/5), risk score 93.8/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2021-44228
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-12

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/a:apache:log4j:2.14.1: |     	CVE-2021-44228	10.0	https://vulners.com/cve/CVE-2021-44228	*EXPLOIT*
```
</details>

### F-008 [P1 / ACT] Apache httpd 2.4.49: CVE-2021-41773 +3 more

- **Asset:** Intranet web server (intranet.corp.novarefino.example:80)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2021-41773, CVE-2021-42013 | EPSS 0.99992 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internal; technical_impact=total; asset_criticality=2/5), risk score 89.8/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 2/5 (CVSS v4 9.3).
- **Business impact:** Intranet web server supports 'Employee intranet' (criticality 2/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2021-41773, CVE-2021-42013, CVE-2023-25690, CVE-2022-22720
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-12

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/a:apache:http_server:2.4.49: |     	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773	*EXPLOIT* |     	CVE-2021-42013	9.8	https://vulners.com/cve/CVE-2021-42013	*EXPLOIT* |     	CVE-2022-22720	9.8	https://vulners.com/cve/CVE-2022-22720 |     	CVE-2023-25690	9.8	https://vulners.com/cve/CVE-2023-25690
```
</details>

### F-009 [P2 / ATTEND] Modbus/TCP exposed on 502/tcp

- **Asset:** PLC crude distillation unit (plc-cdu-01.ot.novarefino.example:502)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=ot; technical_impact=total; asset_criticality=5/5), risk score 75.8/100
- **Why:** P2 because the asset sits in the plant control (OT) zone, a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** PLC crude distillation unit supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.
- **References:** ATT&CK T0883, T0886, T1692; mitigations M0930, M0937, M0807; D3FEND D3-NI, D3-ITF, D3-NTA; CWE 306
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-09
- > Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.
- > OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Fix steps**

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

**Verification / retest**

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

**Interim detection:** SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.

<details><summary>Evidence</summary>

```
nmap: 502/tcp open, service 'modbus Modbus TCP'
```
</details>

### F-010 [P2 / ATTEND] Siemens S7comm exposed on 102/tcp

- **Asset:** PLC utilities (steam/cooling water) (plc-utl-02.ot.novarefino.example:102)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=ot; technical_impact=total; asset_criticality=5/5), risk score 75.8/100
- **Why:** P2 because the asset sits in the plant control (OT) zone, a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** PLC utilities (steam/cooling water) supports 'Utilities' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.
- **References:** ATT&CK T0883, T0886, T1692; mitigations M0930, M0937, M0807; D3FEND D3-NI, D3-ITF, D3-NTA; CWE 306
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-09
- > Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.
- > OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Fix steps**

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

**Verification / retest**

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

**Interim detection:** SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.

<details><summary>Evidence</summary>

```
nmap: 102/tcp open, service 'iso-tsap Siemens S7 PLC'
```
</details>

### F-012 [P2 / ATTEND] OPC UA exposed on 4840/tcp

- **Asset:** OPC UA historian gateway (opc-hist01.ot.novarefino.example:4840)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=ot; technical_impact=total; asset_criticality=4/5), risk score 73.8/100
- **Why:** P2 because the asset sits in the plant control (OT) zone, a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** OPC UA historian gateway supports 'Process data to IT (historian)' (criticality 4/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.
- **References:** ATT&CK T0883, T0886, T1692; mitigations M0930, M0937, M0807; D3FEND D3-NI, D3-ITF, D3-NTA; CWE 306
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-09
- > Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.
- > OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Fix steps**

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

**Verification / retest**

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

**Interim detection:** SOC + OT-ENG: passive OT network monitoring rule for any IT-sourced Modbus/S7/DNP3/EtherNet-IP session, and for write/program-download function codes.

<details><summary>Evidence</summary>

```
nmap: 4840/tcp open, service 'opcua-tcp OPC UA Server'
```
</details>

### F-018 [P2 / ATTEND] Database/cache exposed on 1433/tcp

- **Asset:** ERP database (erp-db01.corp.novarefino.example:1433)
- **Severity:** High | CVSS v4 8.3 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=5/5), risk score 59.8/100
- **Why:** P2 because the asset is internal (not internet-facing) and its business criticality is 5/5 (CVSS v4 8.3).
- **Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1190, T1213; mitigations M1035, M1030, M1026; D3FEND D3-NI, D3-ITF, D3-UAP; WSTG WSTG-v42-CONF-01; CWE 668
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV, NETWORK, GRC-DPO | I SOC | SLA 14 d, Due 2026-11-23

**Fix steps**

1. Bind the service to the application subnet only and add a host firewall rule allowing just the app servers.
2. Require authentication and TLS for every client connection; remove anonymous or default accounts.
3. Move the database into a dedicated data tier segment if it currently shares the user VLAN.

**Verification / retest**

- From a user-VLAN host, nmap -p <db port> <host> must report filtered.
- Unauthenticated connection attempt must be refused.

**Interim detection:** SOC: alert on database logins from hosts outside the application tier.

<details><summary>Evidence</summary>

```
nmap: 1433/tcp open, service 'ms-sql-s Microsoft SQL Server 2016 13.00.5026'
```
</details>

### F-019 [P2 / ATTEND] Database/cache exposed on 5432/tcp

- **Asset:** ERP database (erp-db01.corp.novarefino.example:5432)
- **Severity:** High | CVSS v4 8.3 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=5/5), risk score 59.8/100
- **Why:** P2 because the asset is internal (not internet-facing) and its business criticality is 5/5 (CVSS v4 8.3).
- **Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1190, T1213; mitigations M1035, M1030, M1026; D3FEND D3-NI, D3-ITF, D3-UAP; WSTG WSTG-v42-CONF-01; CWE 668
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV, NETWORK, GRC-DPO | I SOC | SLA 14 d, Due 2026-11-23

**Fix steps**

1. Bind the service to the application subnet only and add a host firewall rule allowing just the app servers.
2. Require authentication and TLS for every client connection; remove anonymous or default accounts.
3. Move the database into a dedicated data tier segment if it currently shares the user VLAN.

**Verification / retest**

- From a user-VLAN host, nmap -p <db port> <host> must report filtered.
- Unauthenticated connection attempt must be refused.

**Interim detection:** SOC: alert on database logins from hosts outside the application tier.

<details><summary>Evidence</summary>

```
nmap: 5432/tcp open, service 'postgresql PostgreSQL DB 12.3'
```
</details>

### F-021 [P3 / TRACK*] OpenSSH 8.9p1: CVE-2024-6387 +1 more

- **Asset:** Maintenance planning app (maint-app.corp.novarefino.example:22)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS 0.99506 (pctl 0.999)
- **Decision:** TRACK* (exploitation=poc; exposure=internal; technical_impact=total; asset_criticality=4/5), risk score 78.7/100
- **Why:** P3 because EPSS gives a 100% probability of exploitation activity in the next 30 days, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Maintenance planning app supports 'Plant maintenance work orders' (criticality 4/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2024-6387, CVE-2023-48795
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 45 d, Due 2026-12-24

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
nmap NSE vulners: cpe:/a:openbsd:openssh:8.9p1: |     	CVE-2024-6387	8.1	https://vulners.com/cve/CVE-2024-6387 |     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
```
</details>

### F-022 [P3 / TRACK*] VNC exposed on 5900/tcp

- **Asset:** 10.10.9.99 (not in inventory) (10.10.9.99:5900)
- **Severity:** Critical | CVSS v4 9.2 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internal; technical_impact=total; asset_criticality=3/5), risk score 61.2/100
- **Why:** P3 because the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 3/5 (CVSS v4 9.2).
- **Business impact:** 10.10.9.99 (not in inventory) supports 'unknown' (criticality 3/5, unknown, zone IT; data: unknown). If exploited, an attacker could reach internal systems directly from an untrusted network.
- **References:** ATT&CK T1133, T1021.001, T1110; mitigations M1035, M1032, M1030; D3FEND D3-ITF, D3-MFA, D3-NI; WSTG WSTG-v42-CONF-01; CWE 284
- **RACI:** R NETWORK | A MGMT | C IAM, IT-INFRA | I SOC | SLA 45 d, Due 2026-12-24
- > Asset not found in inventory: IT-INFRA must register it in the CMDB (unknown assets are a finding by themselves).

**Fix steps**

1. Remove the direct exposure: close the port on the perimeter firewall / security group for any source outside the admin allowlist.
2. Publish remote administration only through the corporate VPN or a zero-trust access broker with MFA.
3. Enforce Network Level Authentication (RDP) or key-only authentication (SSH) and disable password logins for privileged accounts.
4. Record the rule change with ticket ID in the firewall change log.

**Verification / retest**

- From an external vantage point, nmap -Pn -p <port> <public IP> must report filtered/closed.
- Confirm the service is still reachable through the VPN / broker path for authorised admins.

**Interim detection:** SOC: alert on successful logons to this service from non-VPN source ranges and on password-spray patterns.

<details><summary>Evidence</summary>

```
nmap: 5900/tcp open, service 'vnc VNC protocol 3.8'
```
</details>

### F-024 [P3 / TRACK*] SNMP exposed on 161/udp (unauthenticated read)

- **Asset:** Core switch (core-sw01.corp.novarefino.example:161)
- **Severity:** Medium | CVSS v4 6.9 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=5/5), risk score 51.4/100
- **Why:** P3 because the asset is internal (not internet-facing) and its business criticality is 5/5 (CVSS v4 6.9).
- **Business impact:** Core switch supports 'Campus network' (criticality 5/5, production, zone IT; data: internal). If exploited, an attacker could reach internal systems directly from an untrusted network.
- **References:** ATT&CK T1046, T1078.001; mitigations M1042, M1027; D3FEND D3-SPP, D3-ACH; CWE 798
- **RACI:** R NETWORK | A MGMT | C IT-INFRA | I SOC | SLA 45 d, Due 2026-12-24

**Fix steps**

1. Migrate the device to SNMPv3 with authPriv (SHA-2 + AES).
2. If v2c must stay temporarily, set a long random read-only community and an ACL that allows only the NMS address.
3. Disable SNMP write access entirely.

**Verification / retest**

- nmap -sU -p161 --script snmp-info <host> with 'public' must fail.
- NMS still polls the device over SNMPv3.

**Interim detection:** SOC: alert on SNMP requests from sources other than the NMS.

<details><summary>Evidence</summary>

```
nmap: 161/udp open, service 'snmp SNMPv1 server; public' | snmp-info: enterprise: ciscoSystems
  engineIDFormat: unknown
  community: public (read)
```
</details>

### F-030 [P4 / TRACK] FTP exposed on 21/tcp

- **Asset:** Control room printer (prn-ctrlroom.corp.novarefino.example:21)
- **Severity:** High | CVSS v4 7.1 (`CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=1/5), risk score 44.6/100
- **Why:** P4 because the asset is internal (not internet-facing) and its business criticality is 1/5 (CVSS v4 7.1).
- **Business impact:** Control room printer supports 'Shift reports printing' (criticality 1/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1040, T1557; mitigations M1041, M1042; D3FEND D3-ET, D3-MENCR; WSTG WSTG-v42-CRYP-03; CWE 319
- **RACI:** R IT-INFRA | A MGMT | C NETWORK | I SOC | SLA 90 d, Due 2027-02-07

**Fix steps**

1. Replace Telnet with SSH and FTP with SFTP/FTPS; disable the cleartext daemon after migration.
2. Rotate every credential that was ever used over the cleartext protocol.
3. Block the cleartext port at the host firewall so it cannot be re-enabled silently.

**Verification / retest**

- nmap -p 21,23 <host> must report closed/filtered.
- Confirm that the replacement encrypted service accepts logins with rotated credentials.

**Interim detection:** SOC: network sensor rule for any new Telnet/FTP session on the segment.

<details><summary>Evidence</summary>

```
nmap: 21/tcp open, service 'ftp vsftpd 3.0.3'
```
</details>

### F-031 [P4 / TRACK] Telnet exposed on 23/tcp

- **Asset:** Control room printer (prn-ctrlroom.corp.novarefino.example:23)
- **Severity:** High | CVSS v4 7.1 (`CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=1/5), risk score 44.6/100
- **Why:** P4 because the asset is internal (not internet-facing) and its business criticality is 1/5 (CVSS v4 7.1).
- **Business impact:** Control room printer supports 'Shift reports printing' (criticality 1/5, production, zone IT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1040, T1557; mitigations M1041, M1042; D3FEND D3-ET, D3-MENCR; WSTG WSTG-v42-CRYP-03; CWE 319
- **RACI:** R IT-INFRA | A MGMT | C NETWORK | I SOC | SLA 90 d, Due 2027-02-07

**Fix steps**

1. Replace Telnet with SSH and FTP with SFTP/FTPS; disable the cleartext daemon after migration.
2. Rotate every credential that was ever used over the cleartext protocol.
3. Block the cleartext port at the host firewall so it cannot be re-enabled silently.

**Verification / retest**

- nmap -p 21,23 <host> must report closed/filtered.
- Confirm that the replacement encrypted service accepts logins with rotated credentials.

**Interim detection:** SOC: network sensor rule for any new Telnet/FTP session on the segment.

<details><summary>Evidence</summary>

```
nmap: 23/tcp open, service 'telnet Busybox telnetd'
```
</details>


## 6. Retest plan

| Finding | Owner | Retest command / check | When |
|---|---|---|---|
| F-002 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-003 | OT-ENG | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-005 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-006 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-007 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-008 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-12 |
| F-009 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-09 |
| F-010 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-09 |
| F-012 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-09 |
| F-018 | IT-INFRA | From a user-VLAN host, nmap -p <db port> <host> must report filtered. | after fix, before 2026-11-23 |
| F-019 | IT-INFRA | From a user-VLAN host, nmap -p <db port> <host> must report filtered. | after fix, before 2026-11-23 |
| F-021 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-12-24 |
| F-022 | NETWORK | From an external vantage point, nmap -Pn -p <port> <public IP> must report filtered/closed. | after fix, before 2026-12-24 |
| F-024 | NETWORK | nmap -sU -p161 --script snmp-info <host> with 'public' must fail. | after fix, before 2026-12-24 |
| F-030 | IT-INFRA | nmap -p 21,23 <host> must report closed/filtered. | after fix, before 2027-02-07 |
| F-031 | IT-INFRA | nmap -p 21,23 <host> must report closed/filtered. | after fix, before 2027-02-07 |

## 7. Retest delta

| Status | Count |
|---|---|
| Fixed and verified by rescan | 3 |
| Still open | 16 |
| New | 0 |
| Not retested (tool or host not in this run, stays open) | 12 |

- FIXED: F-001 Palo Alto GlobalProtect PAN-OS 10.2.9: CVE-2024-3400 on vpn.novarefino.example
- FIXED: F-004 SMBv1 / MS17-010: CVE-2017-0143 on fs01.corp.novarefino.example
- FIXED: F-014 RDP exposed on 3389/tcp on jump01.novarefino.example
- NOT RETESTED: F-011 HMI web interface accepts vendor default password on hmi-cdu-01.ot.novarefino.example (source: manual)
- NOT RETESTED: F-013 SQL Injection on suppliers.novarefino.example (source: burp, zap)
- NOT RETESTED: F-015 Git metadata exposed on web root on suppliers.novarefino.example (source: burp)
- NOT RETESTED: F-016 No MFA and weak password policy for domain accounts on dc01.corp.novarefino.example (source: manual)
- NOT RETESTED: F-017 Microsoft SQL Server Unsupported Version Detection (remote check) on erp-db01.corp.novarefino.example (source: nessus)
- NOT RETESTED: F-020 IDOR: supplier bank details readable by changing supplierId on suppliers.novarefino.example (source: burp)
- NOT RETESTED: F-023 Admin console reachable from the internet on suppliers.novarefino.example (source: burp)
- NOT RETESTED: F-025 Phishing simulation: 18% click rate and 7% credential submission on users (source: phishing-sim)
- NOT RETESTED: F-026 Cross Site Scripting (Reflected) on suppliers.novarefino.example (source: zap)
- NOT RETESTED: F-027 Port scans and password spraying generated no SOC alert on siem (source: manual)
- NOT RETESTED: F-028 Missing web security headers / insecure cookie attributes (2 issues) on suppliers.novarefino.example (source: burp, zap)
- NOT RETESTED: F-029 TLS Version 1.0 Protocol Detection on portal.novarefino.example (source: nessus)
- STILL OPEN: F-002 Citrix NetScaler Gateway 13.1-48.47: CVE-2023-4966 on portal.novarefino.example (due 2026-11-12)
- STILL OPEN: F-003 Microsoft Terminal Services: CVE-2019-0708 on ews01.ot.novarefino.example (due 2026-11-12)
- STILL OPEN: F-005 Microsoft Windows Server 2016: CVE-2020-1472 on dc01.corp.novarefino.example (due 2026-11-12)
- STILL OPEN: F-006 ActiveMQ OpenWire transport 5.17.5: CVE-2023-46604 on mq01.corp.novarefino.example (due 2026-11-12)
- STILL OPEN: F-007 Apache Tomcat 9.0.31: CVE-2021-44228 on maint-app.corp.novarefino.example (due 2026-11-12)
- STILL OPEN: F-008 Apache httpd 2.4.49: CVE-2021-41773 +3 more on intranet.corp.novarefino.example (due 2026-11-12)
- STILL OPEN: F-009 Modbus/TCP exposed on 502/tcp on plc-cdu-01.ot.novarefino.example (due 2026-12-09)
- STILL OPEN: F-010 Siemens S7comm exposed on 102/tcp on plc-utl-02.ot.novarefino.example (due 2026-12-09)
- STILL OPEN: F-012 OPC UA exposed on 4840/tcp on opc-hist01.ot.novarefino.example (due 2026-12-09)
- STILL OPEN: F-018 Database/cache exposed on 1433/tcp on erp-db01.corp.novarefino.example (due 2026-11-23)
- STILL OPEN: F-019 Database/cache exposed on 5432/tcp on erp-db01.corp.novarefino.example (due 2026-11-23)
- STILL OPEN: F-021 OpenSSH 8.9p1: CVE-2024-6387 +1 more on maint-app.corp.novarefino.example (due 2026-12-24)
- STILL OPEN: F-022 VNC exposed on 5900/tcp on 10.10.9.99 (due 2026-12-24)
- STILL OPEN: F-024 SNMP exposed on 161/udp (unauthenticated read) on core-sw01.corp.novarefino.example (due 2026-12-24)
- STILL OPEN: F-030 FTP exposed on 21/tcp on prn-ctrlroom.corp.novarefino.example (due 2027-02-07)
- STILL OPEN: F-031 Telnet exposed on 23/tcp on prn-ctrlroom.corp.novarefino.example (due 2027-02-07)


## 8. Method and sources

PTES phases as process spine (pre-engagement to reporting); NIST SP 800-115 for planning, rules of engagement and reporting structure; OWASP WSTG v4.2 test IDs for web findings; MITRE ATT&CK v20 technique and mitigation IDs plus MITRE D3FEND 1.6.0 countermeasures for mapping; OSSTMM-inspired visibility/access/trust indicator for trend. Prioritisation: CVSS v4.0 base score, CISA KEV, FIRST EPSS and an SSVC-inspired decision tree (ACT / ATTEND / TRACK* / TRACK) adjusted by asset criticality and exposure.

Sources parsed: nmap. KEV catalog version: 2026.10.30. EPSS scores loaded: 16 (date 2026-11-02).

Identifiers cited: MITRE ATT&CK® and MITRE D3FEND™ (© The MITRE Corporation), OWASP WSTG test IDs, CWE, CVE, CISA KEV, FIRST EPSS and CVSS v4.0. All explanatory wording in this report is original. See NOTICE.md in the skill repository.
