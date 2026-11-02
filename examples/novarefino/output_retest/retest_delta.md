# Retest delta 2026-11-09

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

