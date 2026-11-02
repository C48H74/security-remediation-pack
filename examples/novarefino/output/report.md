# Security Remediation Package: NovaRefino Demo Corp (fictitious)

**Report date:** 2026-11-02  
**Scope:** External perimeter 203.0.113.0/24, corporate 10.10.0.0/16, OT 10.20.0.0/24 (read-only), supplier portal  
**Classification:** CONFIDENTIAL. Share per department on a need-to-know basis.

---

## 1. Executive summary

31 findings across 21 assets were consolidated from 6 sources. 8 need action within 3 days (P1) and 12 within the next SLA window (P2).

8 findings involve vulnerabilities on the CISA KEV list (exploited in the wild). 5 findings affect the OT / plant zone and are routed to OT Engineering under Management of Change.

Work is distributed to 9 departments as 59 tickets. The largest fix workload sits with IT Infrastructure & Operations (IT-INFRA, 15 fix tickets); the SOC also receives interim detection tickets for every open P1/P2.

| P1 | P2 | P3 | P4 | KEV | OT | Tickets |
|---|---|---|---|---|---|---|
| 8 | 12 | 8 | 3 | 8 | 5 | 59 |

### What management needs to decide this week

1. Approve the owners and due dates in section 3 (ticket `MGMT-001`).
2. Free capacity for every P1 item: the target is containment within 72 hours.
3. Formally accept, with a named owner and an expiry date, any risk that will not be fixed inside its SLA.

## 2. Prioritised findings

Priority is **P1 (ACT)**, **P2 (ATTEND)**, **P3 (TRACK\*)** or **P4 (TRACK)**. It comes from an SSVC-inspired decision that weighs exploitation evidence (CISA KEV, FIRST EPSS, public exploit), exposure (internet / OT / internal), technical impact (CVSS v4.0) and the asset's business criticality.

| ID | Priority | Severity | CVSS v4 | KEV | EPSS | Finding | Asset | Responsible | Due | ATT&CK |
|---|---|---|---|---|---|---|---|---|---|---|
| F-001 | **P1** | Critical | 9.3 | Y | 1.00 | Palo Alto GlobalProtect PAN-OS 10.2.9: CVE-2024-3400 | Perimeter firewall / VPN | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-002 | **P1** | Critical | 9.3 | Y | 1.00 | Citrix NetScaler Gateway 13.1-48.47: CVE-2023-4966 | Citrix gateway | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-003 | **P1** | Critical | 9.3 | Y | 1.00 | Microsoft Terminal Services: CVE-2019-0708 | Engineering workstation (DCS/PLC… | OT-ENG | 2026-11-05 | T1190, T1210 |
| F-004 | **P1** | Critical | 10.0 | Y | 0.99 | SMBv1 / MS17-010: CVE-2017-0143 | HR file server | IT-INFRA | 2026-11-05 | T1210, T1021.002 |
| F-005 | **P1** | Critical | 9.3 | Y | 0.99 | Microsoft Windows Server 2016: CVE-2020-1472 | Domain controller | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-006 | **P1** | Critical | 9.3 | Y | 1.00 | ActiveMQ OpenWire transport 5.17.5: CVE-2023-46604 | Message broker | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-007 | **P1** | Critical | 9.3 | Y | 1.00 | Apache Tomcat 9.0.31: CVE-2021-44228 | Maintenance planning app | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-008 | **P1** | Critical | 9.3 | Y | 1.00 | Apache httpd 2.4.49: CVE-2021-41773 +3 more | Intranet web server | IT-INFRA | 2026-11-05 | T1190, T1210 |
| F-009 | **P2** | Critical | 9.3 | - | - | Modbus/TCP exposed on 502/tcp | PLC crude distillation unit | OT-ENG | 2026-12-02 | T0883, T0886, T1692 |
| F-010 | **P2** | Critical | 9.3 | - | - | Siemens S7comm exposed on 102/tcp | PLC utilities (steam/cooling water) | OT-ENG | 2026-12-02 | T0883, T0886, T1692 |
| F-011 | **P2** | Critical | 9.3 | - | - | HMI web interface accepts vendor default password | HMI crude distillation unit | OT-ENG | 2026-12-02 | T1078.001 |
| F-012 | **P2** | Critical | 9.3 | - | - | OPC UA exposed on 4840/tcp | OPC UA historian gateway | OT-ENG | 2026-12-02 | T0883, T0886, T1692 |
| F-013 | **P2** | Critical | 9.3 | - | - | SQL Injection | Supplier portal | APPSEC-DEV | 2026-11-16 | T1190 |
| F-014 | **P2** | Critical | 9.2 | - | - | RDP exposed on 3389/tcp | Admin jump host | NETWORK | 2026-11-16 | T1133, T1021.001, T1110 |
| F-015 | **P2** | High | 8.7 | - | - | Git metadata exposed on web root | Supplier portal | IT-INFRA | 2026-11-16 | T1530, T1552.001 |
| F-016 | **P2** | High | 8.8 | - | - | No MFA and weak password policy for domain accounts | Domain controller | IAM | 2026-11-16 | T1110, T1078 |
| F-017 | **P2** | High | 8.7 | - | - | Microsoft SQL Server Unsupported Version Detection (remote check) | ERP database | IT-INFRA | 2026-11-16 | T1190, T1210 |
| F-018 | **P2** | High | 8.3 | - | - | Database/cache exposed on 1433/tcp | ERP database | IT-INFRA | 2026-11-16 | T1190, T1213 |
| F-019 | **P2** | High | 8.3 | - | - | Database/cache exposed on 5432/tcp | ERP database | IT-INFRA | 2026-11-16 | T1190, T1213 |
| F-020 | **P2** | High | 7.1 | - | - | IDOR: supplier bank details readable by changing supplierId | Supplier portal | APPSEC-DEV | 2026-11-16 | T1190, T1213 |
| F-021 | **P3** | Critical | 9.3 | - | 1.00 | OpenSSH 8.9p1: CVE-2024-6387 +1 more | Maintenance planning app | IT-INFRA | 2026-12-17 | T1190, T1210 |
| F-022 | **P3** | Critical | 9.2 | - | - | VNC exposed on 5900/tcp | 10.10.9.99 (not in inventory) | NETWORK | 2026-12-17 | T1133, T1021.001, T1110 |
| F-023 | **P3** | Medium | 6.9 | - | - | Admin console reachable from the internet | Supplier portal | APPSEC-DEV | 2026-12-17 | T1190, T1078 |
| F-024 | **P3** | Medium | 6.9 | - | - | SNMP exposed on 161/udp (unauthenticated read) | Core switch | NETWORK | 2026-12-17 | T1046, T1078.001 |
| F-025 | **P3** | High | 7.0 | - | - | Phishing simulation: 18% click rate and 7% credential submission | Workforce | HR-AWARENESS | 2026-12-17 | T1566 |
| F-026 | **P3** | Medium | 5.3 | - | - | Cross Site Scripting (Reflected) | Supplier portal | APPSEC-DEV | 2026-12-17 | T1185, T1059.007 |
| F-027 | **P3** | Medium | 6.3 | - | - | Port scans and password spraying generated no SOC alert | SIEM / SOC tooling | SOC | 2026-12-17 | T1046, T1110 |
| F-028 | **P3** | Low | 2.3 | - | - | Missing web security headers / insecure cookie attributes (2 issues) | Supplier portal | APPSEC-DEV | 2026-12-17 | T1185 |
| F-029 | **P4** | Medium | 6.3 | - | - | TLS Version 1.0 Protocol Detection | Citrix gateway | IT-INFRA | 2027-01-31 | T1557 |
| F-030 | **P4** | High | 7.1 | - | - | FTP exposed on 21/tcp | Control room printer | IT-INFRA | 2027-01-31 | T1040, T1557 |
| F-031 | **P4** | High | 7.1 | - | - | Telnet exposed on 23/tcp | Control room printer | IT-INFRA | 2027-01-31 | T1040, T1557 |

## 3. Work distribution by department

Every finding has exactly one Accountable role and at least one Responsible department. While a P1/P2 fix is pending, the SOC receives a parallel detection ticket.

| Department | Tickets | P1 | P2 | P3 | P4 | Next due |
|---|---|---|---|---|---|---|
| Management / CISO office (MGMT) | 1 | 1 | 0 | 0 | 0 | 2026-11-04 |
| IT Infrastructure & Operations (IT-INFRA) | 15 | 7 | 4 | 1 | 3 | 2026-11-05 |
| Network & Perimeter (NETWORK) | 3 | 0 | 1 | 2 | 0 | 2026-11-16 |
| Application Security & Development (APPSEC-DEV) | 5 | 0 | 2 | 3 | 0 | 2026-11-16 |
| Security Operations Center (SOC) | 21 | 8 | 12 | 1 | 0 | 2026-11-04 |
| Identity & Access Management (IAM) | 1 | 0 | 1 | 0 | 0 | 2026-11-16 |
| OT / Plant Engineering & Automation (OT-ENG) | 5 | 1 | 4 | 0 | 0 | 2026-11-05 |
| Legal, Compliance & Data Protection Officer (GRC-DPO) | 7 | 1 | 6 | 0 | 0 | 2026-11-05 |
| HR & Security Awareness (HR-AWARENESS) | 1 | 0 | 0 | 1 | 0 | 2026-12-17 |

Ticket files: `tickets/<DEPT>.md` (human readable), `tickets/<DEPT>.csv` and `.json`; consolidated `jira_import.csv`, `servicenow_import.json` and `defectdojo_generic.json`.

## 4. Operational security indicator

| Visibility (hosts with findings) | Access (exposed services) | Trust (services accepting unauthenticated or implicit-trust interaction) | Porosity V+A+T |
|---|---|---|---|
| 21 | 22 | 10 | **53** |

_Simplified indicator inspired by OSSTMM 3 operational-security metrics (visibility, access, trust). It is not an OSSTMM rav calculation; use it to track the trend between retests._

## 5. Finding details and fix steps

### F-001 [P1 / ACT] Palo Alto GlobalProtect PAN-OS 10.2.9: CVE-2024-3400

- **Asset:** Perimeter firewall / VPN (vpn.novarefino.example:443)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2024-3400 | EPSS 0.99999 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internet; technical_impact=total; asset_criticality=5/5), risk score 100/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** Perimeter firewall / VPN supports 'Remote access for staff and contractors' (criticality 5/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2024-3400
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC, NETWORK | SLA 3 d, Due 2026-11-05

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
nmap NSE vulners: cpe:/o:paloaltonetworks:pan-os:10.2.9: |     	CVE-2024-3400	10.0	https://vulners.com/cve/CVE-2024-3400	*EXPLOIT*
```
</details>

### F-002 [P1 / ACT] Citrix NetScaler Gateway 13.1-48.47: CVE-2023-4966

- **Asset:** Citrix gateway (portal.novarefino.example:443)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2023-4966 | EPSS 0.99999 (pctl 1.0)
- **Decision:** ACT (exploitation=active; exposure=internet; technical_impact=total; asset_criticality=4/5), risk score 100/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104; CVE CVE-2023-4966
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC, NETWORK | SLA 3 d, Due 2026-11-05

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
- **RACI:** R OT-ENG | A MGMT | C IT-INFRA, APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-05
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

### F-004 [P1 / ACT] SMBv1 / MS17-010: CVE-2017-0143

- **Asset:** HR file server (fs01.corp.novarefino.example:445)
- **Severity:** Critical | CVSS v4 10.0 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`, category default (assessor must confirm))
- **KEV / EPSS:** KEV CVE-2017-0144, CVE-2017-0143, CVE-2017-0145 | EPSS 0.9923 (pctl 0.999)
- **Decision:** ACT (exploitation=active; exposure=internal; technical_impact=total; asset_criticality=4/5), risk score 97.9/100
- **Why:** P1 because it is on the CISA KEV list, so attackers are already exploiting it in ransomware campaigns, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 10.0).
- **Business impact:** HR file server supports 'HR records and payroll exports' (criticality 4/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).
- **References:** ATT&CK T1210, T1021.002; mitigations M1042, M1051, M1037; D3FEND D3-SU, D3-ACH, D3-ITF; CWE 477; CVE CVE-2017-0144, CVE-2017-0143, CVE-2017-0145
- **RACI:** R IT-INFRA | A MGMT | C NETWORK, GRC-DPO | I SOC | SLA 3 d, Due 2026-11-05

**Fix steps**

1. Disable SMBv1 on the server and clients (Windows feature removal or GPO) after checking that no legacy device still depends on it.
2. Scanner guidance: Apply the vendor security update for SMB server and disable SMBv1.
3. Install the cumulative security update that covers the listed CVEs.
4. Restrict TCP 445 to the subnets that need file services; never expose it to the internet or to the OT zone.

**Verification / retest**

- nmap -p445 --script smb-protocols <host> must not list SMBv1 (NT LM 0.12).
- nmap -p445 --script smb-vuln-ms17-010 <host> must report not vulnerable.

**Interim detection:** SOC: alert on SMBv1 negotiation and on lateral SMB connections between workstations.

<details><summary>Evidence</summary>

```
nmap NSE smb-vuln-ms17-010: VULNERABLE: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) |     State: VULNERABLE |     IDs:  CVE:CVE-2017-0143 || Nessus plugin 97833: The remote host is affected by the SMBv1 remote code execution vulnerabilities.
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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC, IAM | SLA 3 d, Due 2026-11-05

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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-05

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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-05

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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 3 d, Due 2026-11-05

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
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-02
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
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-02
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

### F-011 [P2 / ATTEND] HMI web interface accepts vendor default password

- **Asset:** HMI crude distillation unit (hmi-cdu-01.ot.novarefino.example:80 http://10.20.0.40/)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=poc; exposure=ot; technical_impact=total; asset_criticality=5/5), risk score 75.8/100
- **Why:** P2 because the tester or the scanner confirmed it can be exploited, the asset sits in the plant control (OT) zone, a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 9.3).
- **Business impact:** HMI crude distillation unit supports 'Operator console' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could log in as a legitimate user and bypass most other controls.
- **References:** ATT&CK T1078.001; mitigations M1027, M1026; D3FEND D3-CH, D3-SPP; WSTG WSTG-v42-ATHN-02; CWE 1392
- **RACI:** R OT-ENG | A MGMT | C IAM, IT-INFRA | I SOC | SLA 30 d, Due 2026-12-02
- > Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.
- > OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Fix steps**

1. Change the default credential immediately to a unique secret stored in the corporate vault (PAM).
2. Disable or rename the vendor account if the product allows it.
3. Add a 'no default credentials' gate to the build/commissioning checklist for new devices.

**Verification / retest**

- Login with the vendor default must fail.
- Vault entry exists and rotation policy is attached.

**Interim detection:** SOC: alert on any successful login with a known vendor account name.

<details><summary>Evidence</summary>

```
Login with vendor default account succeeded (read-only test, no values changed)
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
- **RACI:** R OT-ENG | A MGMT | C NETWORK, SOC | I GRC-DPO | SLA 30 d, Due 2026-12-02
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

### F-013 [P2 / ATTEND] SQL Injection

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/catalog/search?q=valve)
- **Severity:** Critical | CVSS v4 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=poc; exposure=internet; technical_impact=total; asset_criticality=4/5), risk score 71.8/100
- **Why:** P2 because the tester or the scanner confirmed it can be exploited, the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 9.3).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.
- **References:** ATT&CK T1190; mitigations M1048, M1050, M1016; D3FEND D3-ACH; WSTG WSTG-v42-INPV-05, WSTG-v42-INPV-12; CWE 89
- **RACI:** R APPSEC-DEV | A MGMT | C IT-INFRA, GRC-DPO | I SOC, NETWORK | SLA 14 d, Due 2026-11-16

**Fix steps**

1. Replace string-built queries/commands with parameterised queries or safe APIs in the affected endpoint and in every endpoint that reuses the same data-access helper.
2. Add server-side input validation (allowlist of type, length, format).
3. Run the database account with least privilege (no DDL, no file or OS access).
4. Add a regression test reproducing the payload to the CI pipeline and a SAST rule for the pattern.

**Verification / retest**

- Re-run the original proof of concept request; the response must not change behaviour or leak data.
- DAST (ZAP active scan) on the endpoint reports no injection alert; CI regression test passes.

**Interim detection:** SOC: WAF/application log rule for SQL error strings and injection payload signatures on this endpoint.

<details><summary>Evidence</summary>

```
ZAP plugin 40018, risk 3: https://suppliers.novarefino.example/catalog/search?q=valve | evidence: q || Burp high/certain: /catalog/search [q parameter]
```
</details>

### F-014 [P2 / ATTEND] RDP exposed on 3389/tcp

- **Asset:** Admin jump host (jump01.novarefino.example:3389)
- **Severity:** Critical | CVSS v4 9.2 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=internet; technical_impact=total; asset_criticality=3/5), risk score 69.2/100
- **Why:** P2 because the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 3/5 (CVSS v4 9.2).
- **Business impact:** Admin jump host supports 'IT administration' (criticality 3/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could reach internal systems directly from an untrusted network.
- **References:** ATT&CK T1133, T1021.001, T1110; mitigations M1035, M1032, M1030; D3FEND D3-ITF, D3-MFA, D3-NI; WSTG WSTG-v42-CONF-01; CWE 284
- **RACI:** R NETWORK | A MGMT | C IAM, IT-INFRA | I SOC | SLA 14 d, Due 2026-11-16

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
nmap: 3389/tcp open, service 'ms-wbt-server Microsoft Terminal Services'
```
</details>

### F-015 [P2 / ATTEND] Git metadata exposed on web root

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/.git/config)
- **Severity:** High | CVSS v4 8.7 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=poc; exposure=internet; technical_impact=total; asset_criticality=4/5), risk score 68.2/100
- **Why:** P2 because the tester or the scanner confirmed it can be exploited, the asset is reachable from the internet, a successful attack means full compromise of the system and its business criticality is 4/5 (CVSS v4 8.7).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, confidential or personal data could be read by unauthorised parties, with regulatory exposure (GDPR).
- **References:** ATT&CK T1530, T1552.001; mitigations M1041, M1022; D3FEND D3-FE, D3-UAP; WSTG WSTG-v42-CONF-04, WSTG-v42-CONF-11; CWE 538
- **RACI:** R IT-INFRA | A MGMT | C GRC-DPO | I SOC, NETWORK, APPSEC-DEV | SLA 14 d, Due 2026-11-16

**Fix steps**

1. Remove public access to the storage/backup location immediately and keep a copy of access logs as evidence.
2. Rotate any secrets found inside the exposed files.
3. DPO assesses whether personal data was accessed and whether a GDPR Art. 33 notification (72 hours) is required.
4. Enable encryption at rest and a policy that blocks public buckets/shares by default.

**Verification / retest**

- Anonymous request to the object/share URL returns 403.
- Cloud posture scan shows the 'block public access' control enabled.

**Interim detection:** SOC: review access logs for the exposure window; alert on future public ACL changes.

<details><summary>Evidence</summary>

```
/.git/config returned 200 with remote URL and branch names
```
</details>

### F-016 [P2 / ATTEND] No MFA and weak password policy for domain accounts

- **Asset:** Domain controller (dc01.corp.novarefino.example)
- **Severity:** High | CVSS v4 8.8 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=poc; exposure=internal; technical_impact=total; asset_criticality=5/5), risk score 62.8/100
- **Why:** P2 because the tester or the scanner confirmed it can be exploited, the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 8.8).
- **Business impact:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could log in as a legitimate user and bypass most other controls.
- **References:** ATT&CK T1110, T1078; mitigations M1032, M1036, M1027; D3FEND D3-MFA, D3-AL, D3-SPP; WSTG WSTG-v42-ATHN-03, WSTG-v42-ATHN-07; CWE 521, 308
- **RACI:** R IAM | A MGMT | C APPSEC-DEV | I SOC | SLA 14 d, Due 2026-11-16

**Fix steps**

1. Put the application behind the corporate IdP (SSO) and enforce phishing-resistant MFA for all users, mandatory for admins.
2. Configure progressive delays or temporary lockout after repeated failures, plus breached-password screening.
3. Align password length and rotation rules with the corporate identity policy (length over complexity).

**Verification / retest**

- Ten failed logins in a row trigger delay/lockout and a SIEM event.
- Login without the second factor is refused for the test account.

**Interim detection:** SOC: password-spray and impossible-travel analytics on the IdP logs.

<details><summary>Evidence</summary>

```
Default Domain Policy: min length 7, no lockout; Kerberoasting cracked 3 of 12 service account hashes in under 2 h
```
</details>

### F-017 [P2 / ATTEND] Microsoft SQL Server Unsupported Version Detection (remote check)

- **Asset:** ERP database (erp-db01.corp.novarefino.example:1433)
- **Severity:** High | CVSS v4 8.7 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, tool/tester)
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=none; exposure=internal; technical_impact=total; asset_criticality=5/5), risk score 62.2/100
- **Why:** P2 because the asset is internal (not internet-facing), a successful attack means full compromise of the system and its business criticality is 5/5 (CVSS v4 8.7).
- **Business impact:** ERP database supports 'Finance and procurement' (criticality 5/5, production, zone IT; data: personal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1190, T1210; mitigations M1051, M1016; D3FEND D3-SU; WSTG WSTG-v42-CONF-02; CWE 1104
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV, GRC-DPO | I SOC | SLA 14 d, Due 2026-11-16

**Fix steps**

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Scanner guidance: Upgrade to a supported version of SQL Server.
3. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
4. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
5. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

**Verification / retest**

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

**Interim detection:** Alert on exploitation patterns for the listed CVEs at the edge (WAF/IDS) and on unexpected child processes of the service.

<details><summary>Evidence</summary>

```
Nessus plugin 73756: Installed version: 13.0.5026.0 (SQL Server 2016 SP2). Mainstream and extended support status should be checked against vendor lifecycle.
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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV, NETWORK, GRC-DPO | I SOC | SLA 14 d, Due 2026-11-16

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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV, NETWORK, GRC-DPO | I SOC | SLA 14 d, Due 2026-11-16

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

### F-020 [P2 / ATTEND] IDOR: supplier bank details readable by changing supplierId

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/api/v2/suppliers/1043/bank)
- **Severity:** High | CVSS v4 7.1 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** ATTEND (exploitation=poc; exposure=internet; technical_impact=partial; asset_criticality=4/5), risk score 58.6/100
- **Why:** P2 because the tester or the scanner confirmed it can be exploited, the asset is reachable from the internet and its business criticality is 4/5 (CVSS v4 7.1).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.
- **References:** ATT&CK T1190, T1213; mitigations M1026, M1048; D3FEND D3-UAP; WSTG WSTG-v42-ATHZ-02, WSTG-v42-ATHZ-04; CWE 639
- **RACI:** R APPSEC-DEV | A MGMT | C IAM, GRC-DPO | I SOC, NETWORK | SLA 14 d, Due 2026-11-16

**Fix steps**

1. Enforce an object-level authorization check on the server for every request that takes an object identifier (owner or tenant match).
2. Centralise the check in a policy middleware instead of per-controller code.
3. Use non-sequential identifiers as defence in depth (never as the only control).
4. Add negative authorization tests (user A cannot read user B) to CI.

**Verification / retest**

- Repeat the request with a second low-privilege account; the API must return 403/404.
- Automated authorization test suite passes.

**Interim detection:** SOC: alert on a single session enumerating many object IDs in a short window.

<details><summary>Evidence</summary>

```
GET /api/v2/suppliers/1043/bank as supplier 2210 returned IBAN of supplier 1043 (HTTP 200)
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
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I SOC | SLA 45 d, Due 2026-12-17

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
- **RACI:** R NETWORK | A MGMT | C IAM, IT-INFRA | I SOC | SLA 45 d, Due 2026-12-17
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

### F-023 [P3 / TRACK*] Admin console reachable from the internet

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/admin/)
- **Severity:** Medium | CVSS v4 6.9 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internet; technical_impact=partial; asset_criticality=4/5), risk score 57.4/100
- **Why:** P3 because the asset is reachable from the internet and its business criticality is 4/5 (CVSS v4 6.9).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.
- **References:** ATT&CK T1190, T1078; mitigations M1035, M1032; D3FEND D3-ITF, D3-MFA; WSTG WSTG-v42-CONF-05; CWE 284
- **RACI:** R APPSEC-DEV | A MGMT | C NETWORK, IAM, GRC-DPO | I SOC | SLA 45 d, Due 2026-12-17

**Fix steps**

1. Move the admin path to an internal-only listener or restrict it by source IP at the reverse proxy.
2. Require SSO + MFA for the admin role.
3. Remove sample/installer pages left by the vendor.

**Verification / retest**

- External request to the admin path returns 403/404.
- Admin access works from the admin network with MFA.

**Interim detection:** SOC: alert on admin path access from external IPs.

<details><summary>Evidence</summary>

```
/admin/ login page served to anonymous internet users; no IP allow-list
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
- **RACI:** R NETWORK | A MGMT | C IT-INFRA | I SOC | SLA 45 d, Due 2026-12-17

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

### F-025 [P3 / TRACK*] Phishing simulation: 18% click rate and 7% credential submission

- **Asset:** Workforce (users)
- **Severity:** High | CVSS v4 7.0 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=4/5), risk score 50.0/100
- **Why:** P3 because the asset is internal (not internet-facing) and its business criticality is 4/5 (CVSS v4 7.0).
- **Business impact:** Workforce supports 'All business processes' (criticality 4/5, production, zone IT; data: personal). If exploited, attackers could obtain credentials or code execution through users.
- **References:** ATT&CK T1566; mitigations M1017, M1054; D3FEND D3-DNSDL
- **RACI:** R HR-AWARENESS | A MGMT | C SOC, GRC-DPO | I - | SLA 45 d, Due 2026-12-17

**Fix steps**

1. Run short, role-based awareness sessions for the affected teams within 30 days (no blame, focus on reporting).
2. Deploy a one-click 'report phishing' button and publish the reporting channel.
3. Enforce MFA so a captured password alone is not enough.
4. Schedule a follow-up simulation in 90 days to measure improvement.

**Verification / retest**

- Follow-up simulation click rate below the agreed target; report rate above target.

**Interim detection:** SOC: triage queue for user-reported phishing with SLA.

<details><summary>Evidence</summary>

```
Campaign Q3: 412 recipients, 74 clicks, 29 credential submissions, 6 reports to SOC
```
</details>

### F-026 [P3 / TRACK*] Cross Site Scripting (Reflected)

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/onboarding/step2?company=)
- **Severity:** Medium | CVSS v4 5.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=poc; exposure=internet; technical_impact=partial; asset_criticality=4/5), risk score 47.8/100
- **Why:** P3 because the tester or the scanner confirmed it can be exploited, the asset is reachable from the internet and its business criticality is 4/5 (CVSS v4 5.3).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.
- **References:** ATT&CK T1185, T1059.007; mitigations M1021, M1048; D3FEND D3-ACH; WSTG WSTG-v42-CLNT-01, WSTG-v42-INPV-01, WSTG-v42-INPV-02; CWE 79
- **RACI:** R APPSEC-DEV | A MGMT | C GRC-DPO | I SOC, NETWORK | SLA 45 d, Due 2026-12-17

**Fix steps**

1. Apply context-aware output encoding in the template layer for the affected parameter (HTML, attribute, JS, URL contexts).
2. Enable the framework's auto-escaping and remove any raw/unsafe rendering helpers in the affected view.
3. Deploy a restrictive Content-Security-Policy (no unsafe-inline) as defence in depth.
4. Set HttpOnly on session cookies so injected script cannot read them.

**Verification / retest**

- Replay the payload; it must render as inert text.
- ZAP passive + active scan shows no XSS alert for the endpoint.

**Interim detection:** SOC: CSP violation reports forwarded to SIEM; alert on spikes.

<details><summary>Evidence</summary>

```
ZAP plugin 40012, risk 3: https://suppliers.novarefino.example/onboarding/step2?company= | evidence: <scrIpt>alert(1);</scRipt>
```
</details>

### F-027 [P3 / TRACK*] Port scans and password spraying generated no SOC alert

- **Asset:** SIEM / SOC tooling (siem)
- **Severity:** Medium | CVSS v4 6.3 (`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internal; technical_impact=partial; asset_criticality=4/5; category floor P3), risk score 45.8/100
- **Why:** P3 because the asset is internal (not internet-facing) and its business criticality is 4/5 (CVSS v4 6.3). Raised to P3 by policy: this category never ranks lower.
- **Business impact:** SIEM / SOC tooling supports 'Security monitoring' (criticality 4/5, production, zone IT; data: confidential). If exploited, an intrusion could progress without being noticed, increasing dwell time and damage.
- **References:** ATT&CK T1046, T1110; mitigations M1047; D3FEND D3-NTA, D3-UBA, D3-PM; CWE 778
- **RACI:** R SOC | A MGMT | C IT-INFRA | I - | SLA 45 d, Due 2026-12-17

**Fix steps**

1. Onboard the missing log source (host, firewall, application) to the SIEM with parsing validated.
2. Create or tune the detection for the ATT&CK techniques used during the test, using the ATT&CK v20 detection strategies as a starting point.
3. Add the scenario to the purple-team regression list.

**Verification / retest**

- Replay the test activity (atomic test) and confirm an alert is raised and triaged within the SOC SLA.

**Interim detection:** This ticket IS the detection work.

<details><summary>Evidence</summary>

```
Full nmap sweep and 600 spraying attempts over 2 days; no ticket raised by SOC
```
</details>

### F-028 [P3 / TRACK*] Missing web security headers / insecure cookie attributes (2 issues)

- **Asset:** Supplier portal (suppliers.novarefino.example:443 https://suppliers.novarefino.example/)
- **Severity:** Low | CVSS v4 2.3 (`CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK* (exploitation=none; exposure=internet; technical_impact=partial; asset_criticality=4/5), risk score 29.8/100
- **Why:** P3 because the asset is reachable from the internet and its business criticality is 4/5 (CVSS v4 2.3).
- **Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.
- **References:** ATT&CK T1185; mitigations M1021; D3FEND D3-ACH; WSTG WSTG-v42-CLNT-09, WSTG-v42-CONF-07, WSTG-v42-SESS-02; CWE 693
- **RACI:** R APPSEC-DEV | A MGMT | C IT-INFRA, GRC-DPO | I NETWORK | SLA 45 d, Due 2026-12-17

**Fix steps**

1. Add Strict-Transport-Security (max-age >= 1 year), Content-Security-Policy, X-Content-Type-Options and frame-ancestors at the reverse proxy for all virtual hosts.
2. Set Secure, HttpOnly and SameSite on session cookies in the framework configuration.
3. Keep the header set in a shared proxy snippet under version control.

**Verification / retest**

- curl -sI https://<host> shows the headers; ZAP passive scan shows no header alerts.
- Browser dev tools show the cookie flags.

**Interim detection:** Track through configuration compliance; no SOC rule needed.

<details><summary>Evidence</summary>

```
ZAP plugin 10038, risk 2: https://suppliers.novarefino.example/; https://suppliers.novarefino.example/onboarding/ || ZAP plugin 10010, risk 1: https://suppliers.novarefino.example/login | evidence: Set-Cookie: SESSIONID || Burp low/firm: /login [SESSIONID cookie]
```
</details>

### F-029 [P4 / TRACK] TLS Version 1.0 Protocol Detection

- **Asset:** Citrix gateway (portal.novarefino.example:443)
- **Severity:** Medium | CVSS v4 6.3 (`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`, category default (assessor must confirm))
- **KEV / EPSS:** not in KEV | EPSS n/a
- **Decision:** TRACK (exploitation=none; exposure=internet; technical_impact=partial; asset_criticality=4/5), risk score 53.8/100
- **Why:** P4 because the asset is reachable from the internet and its business criticality is 4/5 (CVSS v4 6.3).
- **Business impact:** Citrix gateway supports 'Remote apps for engineering' (criticality 4/5, production, zone DMZ, internet-facing; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware.
- **References:** ATT&CK T1557; mitigations M1041; D3FEND D3-ET, D3-CA; WSTG WSTG-v42-CRYP-01; CWE 326
- **RACI:** R IT-INFRA | A MGMT | C APPSEC-DEV | I NETWORK | SLA 90 d, Due 2027-01-31

**Fix steps**

1. Disable SSLv3, TLS 1.0 and TLS 1.1; keep TLS 1.2 with AEAD ciphers and TLS 1.3.
2. Scanner guidance: Enable TLS 1.2 or 1.3 only.
3. Replace self-signed or expiring certificates with certificates from the corporate or public CA and automate renewal.
4. Apply the change through a shared hardening baseline (Ansible/GPO) so every web front end gets it.

**Verification / retest**

- nmap --script ssl-enum-ciphers -p443 <host> must show no TLS 1.0/1.1 and grade A ciphers only.
- testssl.sh <host> shows no high or critical items.

**Interim detection:** Low detection value; track through configuration compliance scanning.

<details><summary>Evidence</summary>

```
Nessus plugin 104743: TLSv1.0 is enabled and the server supports at least one cipher.
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
- **RACI:** R IT-INFRA | A MGMT | C NETWORK | I SOC | SLA 90 d, Due 2027-01-31

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
- **RACI:** R IT-INFRA | A MGMT | C NETWORK | I SOC | SLA 90 d, Due 2027-01-31

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
| F-001 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-002 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-003 | OT-ENG | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-004 | IT-INFRA | nmap -p445 --script smb-protocols <host> must not list SMBv1 (NT LM 0.12). | after fix, before 2026-11-05 |
| F-005 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-006 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-007 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-008 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-05 |
| F-009 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-02 |
| F-010 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-02 |
| F-011 | OT-ENG | Login with the vendor default must fail. | after fix, before 2026-12-02 |
| F-012 | OT-ENG | Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production. | after fix, before 2026-12-02 |
| F-013 | APPSEC-DEV | Re-run the original proof of concept request; the response must not change behaviour or leak data. | after fix, before 2026-11-16 |
| F-014 | NETWORK | From an external vantage point, nmap -Pn -p <port> <public IP> must report filtered/closed. | after fix, before 2026-11-16 |
| F-015 | IT-INFRA | Anonymous request to the object/share URL returns 403. | after fix, before 2026-11-16 |
| F-016 | IAM | Ten failed logins in a row trigger delay/lockout and a SIEM event. | after fix, before 2026-11-16 |
| F-017 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-11-16 |
| F-018 | IT-INFRA | From a user-VLAN host, nmap -p <db port> <host> must report filtered. | after fix, before 2026-11-16 |
| F-019 | IT-INFRA | From a user-VLAN host, nmap -p <db port> <host> must report filtered. | after fix, before 2026-11-16 |
| F-020 | APPSEC-DEV | Repeat the request with a second low-privilege account; the API must return 403/404. | after fix, before 2026-11-16 |
| F-021 | IT-INFRA | Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version. | after fix, before 2026-12-17 |
| F-022 | NETWORK | From an external vantage point, nmap -Pn -p <port> <public IP> must report filtered/closed. | after fix, before 2026-12-17 |
| F-023 | APPSEC-DEV | External request to the admin path returns 403/404. | after fix, before 2026-12-17 |
| F-024 | NETWORK | nmap -sU -p161 --script snmp-info <host> with 'public' must fail. | after fix, before 2026-12-17 |
| F-025 | HR-AWARENESS | Follow-up simulation click rate below the agreed target; report rate above target. | after fix, before 2026-12-17 |
| F-026 | APPSEC-DEV | Replay the payload; it must render as inert text. | after fix, before 2026-12-17 |
| F-027 | SOC | Replay the test activity (atomic test) and confirm an alert is raised and triaged within the SOC SLA. | after fix, before 2026-12-17 |
| F-028 | APPSEC-DEV | curl -sI https://<host> shows the headers; ZAP passive scan shows no header alerts. | after fix, before 2026-12-17 |
| F-029 | IT-INFRA | nmap --script ssl-enum-ciphers -p443 <host> must show no TLS 1.0/1.1 and grade A ciphers only. | after fix, before 2027-01-31 |
| F-030 | IT-INFRA | nmap -p 21,23 <host> must report closed/filtered. | after fix, before 2027-01-31 |
| F-031 | IT-INFRA | nmap -p 21,23 <host> must report closed/filtered. | after fix, before 2027-01-31 |

## 7. Retest delta

_No baseline supplied. Run again with `--baseline <previous findings.json>` after fixes._

## 8. Method and sources

PTES phases as process spine (pre-engagement to reporting); NIST SP 800-115 for planning, rules of engagement and reporting structure; OWASP WSTG v4.2 test IDs for web findings; MITRE ATT&CK v20 technique and mitigation IDs plus MITRE D3FEND 1.6.0 countermeasures for mapping; OSSTMM-inspired visibility/access/trust indicator for trend. Prioritisation: CVSS v4.0 base score, CISA KEV, FIRST EPSS and an SSVC-inspired decision tree (ACT / ATTEND / TRACK* / TRACK) adjusted by asset criticality and exposure.

Sources parsed: burp, manual, nessus, nmap, phishing-sim, zap. KEV catalog version: 2026.10.30. EPSS scores loaded: 16 (date 2026-11-02).

Identifiers cited: MITRE ATT&CK® and MITRE D3FEND™ (© The MITRE Corporation), OWASP WSTG test IDs, CWE, CVE, CISA KEV, FIRST EPSS and CVSS v4.0. All explanatory wording in this report is original. See NOTICE.md in the skill repository.
