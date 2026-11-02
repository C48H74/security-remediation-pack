# HR & Security Awareness (HR-AWARENESS)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 1 Tickets

Lead: Beatriz Costa (fictitious) <awareness@novarefino.example>

---

## HR-AWARENESS-001: [P3] Users susceptible to phishing / social engineering on Workforce (users)

| Campo | Valor |
|---|---|
| Tipo | fix |
| Prioridad | **P3** |
| Fecha límite | **2026-12-17** |
| Departamento | HR & Security Awareness (HR-AWARENESS) |
| Hallazgo | F-025 |
| RACI | R: HR-AWARENESS | A: MGMT | C: SOC, GRC-DPO | I: - |

**Contexto:** Workforce | users | High CVSS v4 7.0 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=4/5)

**Impacto de negocio:** Workforce supports 'All business processes' (criticality 4/5, production, zone IT; data: personal). If exploited, attackers could obtain credentials or code execution through users.

### Pasos a aplicar

1. Run short, role-based awareness sessions for the affected teams within 30 days (no blame, focus on reporting).
2. Deploy a one-click 'report phishing' button and publish the reporting channel.
3. Enforce MFA so a captured password alone is not enough.
4. Schedule a follow-up simulation in 90 days to measure improvement.

### Criterio de cierre (verificación)

- Follow-up simulation click rate below the agreed target; report rate above target.

- Adjunta la evidencia de la comprobación a este ticket y pásalo a *Listo para retest*. El auditor lo cierra tras el reescaneo.

**Referencias:** ATT&CK v20: T1566 | Mitigations: M1017, M1054 | D3FEND: D3-DNSDL

<details><summary>Evidencia de la prueba</summary>

```
Campaign Q3: 412 recipients, 74 clicks, 29 credential submissions, 6 reports to SOC
```
</details>

