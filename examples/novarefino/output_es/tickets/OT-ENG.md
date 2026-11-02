# OT / Plant Engineering & Automation (OT-ENG)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 5 Tickets

Lead: Ramon Vidal (fictitious) <ot-eng@novarefino.example>

---

## OT-ENG-001: [P1] Outdated software with known vulnerabilities on Engineering workstation (DCS/PLC programming) (ews01.ot.novarefino.example:3389)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P1** |
| Fecha límite | **2026-11-05** |
| Departamento | OT / Plant Engineering & Automation (OT-ENG) |
| Hallazgo | F-003 |
| RACI | R: OT-ENG | A: MGMT | C: IT-INFRA, APPSEC-DEV | I: SOC |

**Contexto:** Engineering workstation (DCS/PLC programming) | ews01.ot.novarefino.example:3389 | Critical CVSS v4 9.3 | KEV: sí | EPSS: 0.99999 | ACT (exploitation=active, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** Engineering workstation (DCS/PLC programming) supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could take control of the server and use it as a foothold for lateral movement or ransomware. CVE used by ransomware campaigns (KEV).

### Pasos a aplicar

1. Confirm the exact installed version and the vendor advisory for every CVE listed.
2. Apply the vendor fixed release (or the supported LTS branch) through the normal change process; emergency change if the CVE is in CISA KEV.
3. If patching must wait, apply the vendor workaround or put the service behind an allowlist / WAF virtual patch and document the compensating control with an expiry date.
4. Add the component to the software inventory (SBOM / CMDB) so the next advisory is matched automatically.

### Criterio de cierre (verificación)

- Re-run the version detection scan (nmap -sV --script vulners) and confirm the banner or package reports the fixed version.
- Re-run the original exploit check (non-destructive) and confirm it fails.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1190, T1210 | Mitigations: M1051, M1016 | D3FEND: D3-SU | WSTG: WSTG-v42-CONF-02 | CWE: CWE-1104 | CVE: CVE-2019-0708

<details><summary>Evidencia de la prueba</summary>

```
nmap NSE vulners: cpe:/o:microsoft:windows_7: |     	CVE-2019-0708	9.8	https://vulners.com/cve/CVE-2019-0708	*EXPLOIT*
```
</details>


---

## OT-ENG-002: [P2] Industrial control protocol reachable from outside the OT zone on PLC crude distillation unit (plc-cdu-01.ot.novarefino.example:502)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-12-02** |
| Departamento | OT / Plant Engineering & Automation (OT-ENG) |
| Hallazgo | F-009 |
| RACI | R: OT-ENG | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** PLC crude distillation unit | plc-cdu-01.ot.novarefino.example:502 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** PLC crude distillation unit supports 'Crude distillation unit control' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

### Criterio de cierre (verificación)

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 502/tcp open, service 'modbus Modbus TCP'
```
</details>


---

## OT-ENG-003: [P2] Industrial control protocol reachable from outside the OT zone on PLC utilities (steam/cooling water) (plc-utl-02.ot.novarefino.example:102)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-12-02** |
| Departamento | OT / Plant Engineering & Automation (OT-ENG) |
| Hallazgo | F-010 |
| RACI | R: OT-ENG | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** PLC utilities (steam/cooling water) | plc-utl-02.ot.novarefino.example:102 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** PLC utilities (steam/cooling water) supports 'Utilities' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

### Criterio de cierre (verificación)

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 102/tcp open, service 'iso-tsap Siemens S7 PLC'
```
</details>


---

## OT-ENG-004: [P2] Default or vendor credentials accepted on HMI crude distillation unit (hmi-cdu-01.ot.novarefino.example:80)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-12-02** |
| Departamento | OT / Plant Engineering & Automation (OT-ENG) |
| Hallazgo | F-011 |
| RACI | R: OT-ENG | A: MGMT | C: IAM, IT-INFRA | I: SOC |

**Contexto:** HMI crude distillation unit | hmi-cdu-01.ot.novarefino.example:80 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=ot, technical_impact=total, asset_criticality=5/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** HMI crude distillation unit supports 'Operator console' (criticality 5/5, production, zone OT; data: internal). If exploited, an attacker could log in as a legitimate user and bypass most other controls.

### Pasos a aplicar

1. Change the default credential immediately to a unique secret stored in the corporate vault (PAM).
2. Disable or rename the vendor account if the product allows it.
3. Add a 'no default credentials' gate to the build/commissioning checklist for new devices.

### Criterio de cierre (verificación)

- Login with the vendor default must fail.
- Vault entry exists and rotation policy is attached.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1078.001 | Mitigations: M1027, M1026 | D3FEND: D3-CH, D3-SPP | WSTG: WSTG-v42-ATHN-02 | CWE: CWE-1392

<details><summary>Evidencia de la prueba</summary>

```
Login with vendor default account succeeded (read-only test, no values changed)
```
</details>


---

## OT-ENG-005: [P2] Industrial control protocol reachable from outside the OT zone on OPC UA historian gateway (opc-hist01.ot.novarefino.example:4840)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-12-02** |
| Departamento | OT / Plant Engineering & Automation (OT-ENG) |
| Hallazgo | F-012 |
| RACI | R: OT-ENG | A: MGMT | C: NETWORK, SOC | I: GRC-DPO |

**Contexto:** OPC UA historian gateway | opc-hist01.ot.novarefino.example:4840 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=none, exposure=ot, technical_impact=total, asset_criticality=4/5)

> Requires Management of Change (MOC) and process-safety sign-off before any change on live equipment.

> OT rule: contain within 72 h with compensating controls (block the conduit at the IT/OT firewall, disable remote access, increase monitoring); apply the permanent fix in the next approved maintenance window or turnaround.

**Impacto de negocio:** OPC UA historian gateway supports 'Process data to IT (historian)' (criticality 4/5, production, zone OT; data: internal). If exploited, an attacker could read or change process values or controller logic, with possible safety, environmental and production-loss consequences.

### Pasos a aplicar

1. Do NOT scan aggressively or patch live controllers: open a Management of Change (MOC) with Process Safety before any intervention.
2. Contain first: add a deny rule at the IT/OT boundary (conduit) so the protocol is only reachable from the engineering workstations and historian in the OT DMZ (zones and conduits model, IEC 62443 style).
3. Enable the controller's write-protection / run-mode key or protocol allowlist where the vendor supports it.
4. Plan the permanent fix (firmware, segmentation redesign) for the next scheduled turnaround and record it in the plant maintenance system.

### Criterio de cierre (verificación)

- Passive check: from the corporate IT VLAN, a single TCP connect test (nc -zv <ip> <port>) must fail; no active protocol scanning on production.
- OT-ENG confirms with the asset owner that HMI/historian communication is unaffected (sign-off in MOC).

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T0883, T0886, T1692 | Mitigations: M0930, M0937, M0807 | D3FEND: D3-NI, D3-ITF, D3-NTA | CWE: CWE-306

<details><summary>Evidencia de la prueba</summary>

```
nmap: 4840/tcp open, service 'opcua-tcp OPC UA Server'
```
</details>

