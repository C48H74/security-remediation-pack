# Reuse survey: build, borrow or integrate?

Before writing code I surveyed GitHub (repository search, 2026-11-02) for projects that already turn findings into routed remediation work. The skill is meant to be usable commercially, so **every license was checked**.

- **GPL and AGPL code is never copied** into this MIT-licensed repo.
- **LGPL** is used only as an optional import.

## Top candidates

| Project | Stars (approx.) | License | What it does | Verdict |
|---|---|---|---|---|
| [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | 5.1k | BSD-3-Clause | Vulnerability management, 200+ parsers | **Integrate**: we export its Generic Findings JSON so teams can import the package directly |
| [mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) | 2.5k | Apache-2.0 | ATT&CK matrix viewer | **Integrate**: we write layer files (format 4.5) for Enterprise and ICS |
| [center-for-threat-informed-defense/mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer) | 0.1k | Apache-2.0 | CVE/KEV → ATT&CK and control mappings | **Reuse data (optional)**: a good source to enrich CVE → technique mapping later |
| [mitre/cti](https://github.com/mitre/cti) and attack-stix-data | 2.2k | ATT&CK Terms of Use (royalty-free, attribution) | ATT&CK STIX data | **Reuse IDs** with attribution (see NOTICE.md). The data is used only for validation and is not shipped |
| [OWASP/wstg](https://github.com/OWASP/wstg) | 10.2k | CC-BY-SA-4.0 | Web testing guide and checklist | **IDs only**: test identifiers are cited and no text is copied, so ShareAlike does not reach our code |
| [GhostManager/Ghostwriter](https://github.com/GhostManager/Ghostwriter) | 2k | BSD-3-Clause | Pentest reporting platform | Complementary: a strong report writer, with no department routing or SLA logic |
| [pwndoc/pwndoc](https://github.com/pwndoc/pwndoc) | 2.9k | MIT | Pentest report generator | Complementary: same gap (no RACI or tickets) |
| [infobyte/faraday](https://github.com/infobyte/faraday) | 6.8k | **GPL-3.0** | Collaborative vuln management | **Do not copy code**. Interoperate through files only |
| [Syslifters/sysreptor](https://github.com/Syslifters/sysreptor) | 2.6k | Custom, not OSI-approved | Pentest reporting | **Commercial caution**: read the license before any embedding |
| [dradis/dradis-ce](https://github.com/dradis/dradis-ce) | 0.8k | **GPL-2.0** | Reporting and collaboration | **Do not copy code** |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | 16k | MIT | LLM agent that helps run tests | Different job (testing, not remediation routing) |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 35k | Apache-2.0 | 800+ agent skills with security guidance | Complementary: guidance skills, none route fixes to departments |
| [RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss) | 0.1k | **LGPL-3.0** | CVSS v2/v3/v4 calculator | **Optional import only** (`pip install cvss`), never vendored |

Also checked:

- Avoid: nessus-file-reader (GPL-3.0), YetAnotherPentestParser (AGPL).
- No SPDX license declared, so not used: python-libnmap.
- Data or ideas only: nuclei-templates (MIT), CERTCC/SSVC (decision-tree concept), cisagov KEV data (public feed).

## Decision

No surveyed project combines all of these:

- a RACI split across nine departments,
- IT and OT SLAs,
- separate fix and detection tickets,
- DPO compliance tickets,
- a retest delta that refuses to call untested items fixed.

So the core is a small, **standard-library-only** Python script, with integration at the edges:

- DefectDojo, ATT&CK Navigator, Jira CSV and ServiceNow JSON as exports,
- ATT&CK, D3FEND, WSTG, KEV and EPSS as credited reference data.

This keeps the license clean (MIT) and the install trivial.
