# Network & Perimeter (NETWORK)

NovaRefino Demo Corp (fictitious) | 2026-11-09 | 2 Tickets

Lead: Ana Ribeiro (fictitious) <network@novarefino.example>

---

## NETWORK-001: [P3] Remote administration service reachable from untrusted networks on 10.10.9.99 (not in inventory) (10.10.9.99:5900)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-24** |
| Department | Network & Perimeter (NETWORK) |
| Finding | F-022 |
| RACI | R: NETWORK | A: MGMT | C: IAM, IT-INFRA | I: SOC |

**Context:** 10.10.9.99 (not in inventory) | 10.10.9.99:5900 | Critical CVSS v4 9.2 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internal, technical_impact=total, asset_criticality=3/5)

> Asset not found in inventory: IT-INFRA must register it in the CMDB (unknown assets are a finding by themselves).

**Business impact:** 10.10.9.99 (not in inventory) supports 'unknown' (criticality 3/5, unknown, zone IT; data: unknown). If exploited, an attacker could reach internal systems directly from an untrusted network.

### Steps to apply

1. Remove the direct exposure: close the port on the perimeter firewall / security group for any source outside the admin allowlist.
2. Publish remote administration only through the corporate VPN or a zero-trust access broker with MFA.
3. Enforce Network Level Authentication (RDP) or key-only authentication (SSH) and disable password logins for privileged accounts.
4. Record the rule change with ticket ID in the firewall change log.

### Definition of done (verification)

- From an external vantage point, nmap -Pn -p <port> <public IP> must report filtered/closed.
- Confirm the service is still reachable through the VPN / broker path for authorised admins.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1133, T1021.001, T1110 | Mitigations: M1035, M1032, M1030 | D3FEND: D3-ITF, D3-MFA, D3-NI | WSTG: WSTG-v42-CONF-01 | CWE: CWE-284

<details><summary>Evidence from the test</summary>

```
nmap: 5900/tcp open, service 'vnc VNC protocol 3.8'
```
</details>


---

## NETWORK-002: [P3] SNMP v1/v2c with default or guessable community string on Core switch (core-sw01.corp.novarefino.example:161)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-24** |
| Department | Network & Perimeter (NETWORK) |
| Finding | F-024 |
| RACI | R: NETWORK | A: MGMT | C: IT-INFRA | I: SOC |

**Context:** Core switch | core-sw01.corp.novarefino.example:161 | Medium CVSS v4 6.9 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=5/5)

**Business impact:** Core switch supports 'Campus network' (criticality 5/5, production, zone IT; data: internal). If exploited, an attacker could reach internal systems directly from an untrusted network.

### Steps to apply

1. Migrate the device to SNMPv3 with authPriv (SHA-2 + AES).
2. If v2c must stay temporarily, set a long random read-only community and an ACL that allows only the NMS address.
3. Disable SNMP write access entirely.

### Definition of done (verification)

- nmap -sU -p161 --script snmp-info <host> with 'public' must fail.
- NMS still polls the device over SNMPv3.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1046, T1078.001 | Mitigations: M1042, M1027 | D3FEND: D3-SPP, D3-ACH | CWE: CWE-798

<details><summary>Evidence from the test</summary>

```
nmap: 161/udp open, service 'snmp SNMPv1 server; public' | snmp-info: enterprise: ciscoSystems
  engineIDFormat: unknown
  community: public (read)
```
</details>

