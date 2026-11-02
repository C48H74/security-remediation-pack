# Identity & Access Management (IAM)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 1 Tickets

Lead: Pedro Lima (fictitious) <iam@novarefino.example>

---

## IAM-001: [P2] Weak authentication controls (no lockout / no MFA / weak policy) on Domain controller (dc01.corp.novarefino.example)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P2** |
| Fecha límite | **2026-11-16** |
| Departamento | Identity & Access Management (IAM) |
| Hallazgo | F-016 |
| RACI | R: IAM | A: MGMT | C: APPSEC-DEV | I: SOC |

**Contexto:** Domain controller | dc01.corp.novarefino.example | High CVSS v4 8.8 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internal, technical_impact=total, asset_criticality=5/5)

**Impacto de negocio:** Domain controller supports 'Identity for all corporate users' (criticality 5/5, production, zone IT; data: confidential). If exploited, an attacker could log in as a legitimate user and bypass most other controls.

### Pasos a aplicar

1. Put the application behind the corporate IdP (SSO) and enforce phishing-resistant MFA for all users, mandatory for admins.
2. Configure progressive delays or temporary lockout after repeated failures, plus breached-password screening.
3. Align password length and rotation rules with the corporate identity policy (length over complexity).

### Criterio de cierre (verificación)

- Ten failed logins in a row trigger delay/lockout and a SIEM event.
- Login without the second factor is refused for the test account.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1110, T1078 | Mitigations: M1032, M1036, M1027 | D3FEND: D3-MFA, D3-AL, D3-SPP | WSTG: WSTG-v42-ATHN-03, WSTG-v42-ATHN-07 | CWE: CWE-521, CWE-308

<details><summary>Evidencia de la prueba</summary>

```
Default Domain Policy: min length 7, no lockout; Kerberoasting cracked 3 of 12 service account hashes in under 2 h
```
</details>

