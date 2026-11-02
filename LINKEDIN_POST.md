# LinkedIn post (English)

A pentest report with 31 findings is not a plan. It is homework nobody signed up for.

After 15 years of programming as a hobby, I decided to put those skills to work building new tools that change the way we handle cybersecurity.

The first thing I wanted to fix was the handover. The test ends, a PDF lands in someone's inbox, and then the questions start. Who fixes this? By when? Does the SOC watch it until then? Does the DPO need to know?

So I built the piece I kept looking for and could not find.

It's an open-source AI agent skill. You give it nmap, Nessus, ZAP or Burp output, plus your asset list. It gives you back one report for management and one ticket queue per department.

Every finding gets:
• a priority from CVSS v4, CISA KEV and EPSS
• one plain sentence explaining that priority
• an owner from a RACI matrix and a due date
• MITRE ATT&CK and D3FEND mapping for the SOC
• fix steps and the exact check that proves it was fixed

Plant systems follow plant rules: contain in 72 hours, then the permanent fix goes through Management of Change. Nobody patches a PLC live.

The retest is honest too. A finding only counts as fixed when it was tested again, not because it went missing from a smaller scan.

I tested it on a fictitious refinery: 31 findings became 59 tickets across 9 teams, with exports for Jira, ServiceNow and DefectDojo. The docs come in English, Spanish and Portuguese.

Before writing any code I compared the six frameworks from the Cisco NetAcad Ethical Hacker course. PTES, NIST SP 800-115, OWASP WSTG and ATT&CK all made it in. None of them says what to fix first or who owns it, and that gap is what this project tries to close.

Code, demo and the full framework comparison:
{{GITHUB_URL}}

If you work in a SOC or run pentests, I'd like to know what breaks when you try it.

#cybersecurity #pentesting #OTsecurity #MITREATTACK #opensource

---

## Repository

- **Repo name:** `security-remediation-pack`
- **One-line description:** Open-source AI agent skill that turns pentest and scanner output into prioritized, owned remediation tickets for every department (CVSS v4, KEV, EPSS, ATT&CK, OT/ICS).
- **Topics:** `cybersecurity`, `pentesting`, `vulnerability-management`, `remediation`, `mitre-attack`, `d3fend`, `owasp`, `cvss`, `epss`, `cisa-kev`, `ot-security`, `ics-security`, `soc`, `ai-agents`, `agent-skills`, `python`

## Images to attach (in this order)

1. `assets/how_it_works.png`
2. `assets/diagram.png`
3. `assets/roadmap.png`
