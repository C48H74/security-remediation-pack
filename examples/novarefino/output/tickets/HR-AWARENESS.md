# HR & Security Awareness (HR-AWARENESS)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 1 Tickets

Lead: Beatriz Costa (fictitious) <awareness@novarefino.example>

---

## HR-AWARENESS-001: [P3] Users susceptible to phishing / social engineering on Workforce (users)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-17** |
| Department | HR & Security Awareness (HR-AWARENESS) |
| Finding | F-025 |
| RACI | R: HR-AWARENESS | A: MGMT | C: SOC, GRC-DPO | I: - |

**Context:** Workforce | users | High CVSS v4 7.0 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internal, technical_impact=partial, asset_criticality=4/5)

**Business impact:** Workforce supports 'All business processes' (criticality 4/5, production, zone IT; data: personal). If exploited, attackers could obtain credentials or code execution through users.

### Steps to apply

1. Run short, role-based awareness sessions for the affected teams within 30 days (no blame, focus on reporting).
2. Deploy a one-click 'report phishing' button and publish the reporting channel.
3. Enforce MFA so a captured password alone is not enough.
4. Schedule a follow-up simulation in 90 days to measure improvement.

### Definition of done (verification)

- Follow-up simulation click rate below the agreed target; report rate above target.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1566 | Mitigations: M1017, M1054 | D3FEND: D3-DNSDL

<details><summary>Evidence from the test</summary>

```
Campaign Q3: 412 recipients, 74 clicks, 29 credential submissions, 6 reports to SOC
```
</details>

