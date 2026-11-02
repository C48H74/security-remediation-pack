# Application Security & Development (APPSEC-DEV)

NovaRefino Demo Corp (fictitious) | 2026-11-02 | 5 Tickets

Lead: Marc Soler (fictitious) <appsec@novarefino.example>

---

## APPSEC-DEV-001: [P2] Injection in web application (SQL / OS command) on Supplier portal (suppliers.novarefino.example:443)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P2** |
| Due date | **2026-11-16** |
| Department | Application Security & Development (APPSEC-DEV) |
| Finding | F-013 |
| RACI | R: APPSEC-DEV | A: MGMT | C: IT-INFRA, GRC-DPO | I: SOC, NETWORK |

**Context:** Supplier portal | suppliers.novarefino.example:443 | Critical CVSS v4 9.3 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=total, asset_criticality=4/5)

**Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Steps to apply

1. Replace string-built queries/commands with parameterised queries or safe APIs in the affected endpoint and in every endpoint that reuses the same data-access helper.
2. Add server-side input validation (allowlist of type, length, format).
3. Run the database account with least privilege (no DDL, no file or OS access).
4. Add a regression test reproducing the payload to the CI pipeline and a SAST rule for the pattern.

### Definition of done (verification)

- Re-run the original proof of concept request; the response must not change behaviour or leak data.
- DAST (ZAP active scan) on the endpoint reports no injection alert; CI regression test passes.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190 | Mitigations: M1048, M1050, M1016 | D3FEND: D3-ACH | WSTG: WSTG-v42-INPV-05, WSTG-v42-INPV-12 | CWE: CWE-89

<details><summary>Evidence from the test</summary>

```
ZAP plugin 40018, risk 3: https://suppliers.novarefino.example/catalog/search?q=valve | evidence: q || Burp high/certain: /catalog/search [q parameter]
```
</details>


---

## APPSEC-DEV-002: [P2] Broken access control (IDOR / BOLA) on Supplier portal (suppliers.novarefino.example:443)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P2** |
| Due date | **2026-11-16** |
| Department | Application Security & Development (APPSEC-DEV) |
| Finding | F-020 |
| RACI | R: APPSEC-DEV | A: MGMT | C: IAM, GRC-DPO | I: SOC, NETWORK |

**Context:** Supplier portal | suppliers.novarefino.example:443 | High CVSS v4 7.1 | KEV: no | EPSS: n/a | ATTEND (exploitation=poc, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Steps to apply

1. Enforce an object-level authorization check on the server for every request that takes an object identifier (owner or tenant match).
2. Centralise the check in a policy middleware instead of per-controller code.
3. Use non-sequential identifiers as defence in depth (never as the only control).
4. Add negative authorization tests (user A cannot read user B) to CI.

### Definition of done (verification)

- Repeat the request with a second low-privilege account; the API must return 403/404.
- Automated authorization test suite passes.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1213 | Mitigations: M1026, M1048 | D3FEND: D3-UAP | WSTG: WSTG-v42-ATHZ-02, WSTG-v42-ATHZ-04 | CWE: CWE-639

<details><summary>Evidence from the test</summary>

```
GET /api/v2/suppliers/1043/bank as supplier 2210 returned IBAN of supplier 1043 (HTTP 200)
```
</details>


---

## APPSEC-DEV-003: [P3] Administrative interface exposed to users or internet on Supplier portal (suppliers.novarefino.example:443)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-17** |
| Department | Application Security & Development (APPSEC-DEV) |
| Finding | F-023 |
| RACI | R: APPSEC-DEV | A: MGMT | C: NETWORK, IAM, GRC-DPO | I: SOC |

**Context:** Supplier portal | suppliers.novarefino.example:443 | Medium CVSS v4 6.9 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Steps to apply

1. Move the admin path to an internal-only listener or restrict it by source IP at the reverse proxy.
2. Require SSO + MFA for the admin role.
3. Remove sample/installer pages left by the vendor.

### Definition of done (verification)

- External request to the admin path returns 403/404.
- Admin access works from the admin network with MFA.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1190, T1078 | Mitigations: M1035, M1032 | D3FEND: D3-ITF, D3-MFA | WSTG: WSTG-v42-CONF-05 | CWE: CWE-284

<details><summary>Evidence from the test</summary>

```
/admin/ login page served to anonymous internet users; no IP allow-list
```
</details>


---

## APPSEC-DEV-004: [P3] Cross-site scripting (reflected or stored) on Supplier portal (suppliers.novarefino.example:443)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-17** |
| Department | Application Security & Development (APPSEC-DEV) |
| Finding | F-026 |
| RACI | R: APPSEC-DEV | A: MGMT | C: GRC-DPO | I: SOC, NETWORK |

**Context:** Supplier portal | suppliers.novarefino.example:443 | Medium CVSS v4 5.3 | KEV: no | EPSS: n/a | TRACK* (exploitation=poc, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Steps to apply

1. Apply context-aware output encoding in the template layer for the affected parameter (HTML, attribute, JS, URL contexts).
2. Enable the framework's auto-escaping and remove any raw/unsafe rendering helpers in the affected view.
3. Deploy a restrictive Content-Security-Policy (no unsafe-inline) as defence in depth.
4. Set HttpOnly on session cookies so injected script cannot read them.

### Definition of done (verification)

- Replay the payload; it must render as inert text.
- ZAP passive + active scan shows no XSS alert for the endpoint.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1185, T1059.007 | Mitigations: M1021, M1048 | D3FEND: D3-ACH | WSTG: WSTG-v42-CLNT-01, WSTG-v42-INPV-01, WSTG-v42-INPV-02 | CWE: CWE-79

<details><summary>Evidence from the test</summary>

```
ZAP plugin 40012, risk 3: https://suppliers.novarefino.example/onboarding/step2?company= | evidence: <scrIpt>alert(1);</scRipt>
```
</details>


---

## APPSEC-DEV-005: [P3] Missing web security headers / insecure cookie attributes on Supplier portal (suppliers.novarefino.example:443)

| Field | Value |
|---|---|
| Type | fix |
| Priority | **P3** |
| Due date | **2026-12-17** |
| Department | Application Security & Development (APPSEC-DEV) |
| Finding | F-028 |
| RACI | R: APPSEC-DEV | A: MGMT | C: IT-INFRA, GRC-DPO | I: NETWORK |

**Context:** Supplier portal | suppliers.novarefino.example:443 | Low CVSS v4 2.3 | KEV: no | EPSS: n/a | TRACK* (exploitation=none, exposure=internet, technical_impact=partial, asset_criticality=4/5)

**Business impact:** Supplier portal supports 'Procurement and supplier onboarding' (criticality 4/5, production, zone DMZ, internet-facing; data: personal). If exploited, an attacker could read or modify application data and act as other users.

### Steps to apply

1. Add Strict-Transport-Security (max-age >= 1 year), Content-Security-Policy, X-Content-Type-Options and frame-ancestors at the reverse proxy for all virtual hosts.
2. Set Secure, HttpOnly and SameSite on session cookies in the framework configuration.
3. Keep the header set in a shared proxy snippet under version control.

### Definition of done (verification)

- curl -sI https://<host> shows the headers; ZAP passive scan shows no header alerts.
- Browser dev tools show the cookie flags.

- Attach evidence of the check to this ticket, then move it to *Ready for retest*. The assessor closes it after the rescan.

**References:** ATT&CK v20: T1185 | Mitigations: M1021 | D3FEND: D3-ACH | WSTG: WSTG-v42-CLNT-09, WSTG-v42-CONF-07, WSTG-v42-SESS-02 | CWE: CWE-693

<details><summary>Evidence from the test</summary>

```
ZAP plugin 10038, risk 2: https://suppliers.novarefino.example/; https://suppliers.novarefino.example/onboarding/ || ZAP plugin 10010, risk 1: https://suppliers.novarefino.example/login | evidence: Set-Cookie: SESSIONID || Burp low/firm: /login [SESSIONID cookie]
```
</details>

