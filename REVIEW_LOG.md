# Review loop log

Each round followed the same cycle:

1. Draft.
2. Run on the NovaRefino sample (`examples/novarefino/run_example.sh`).
3. Score with `scripts/selftest.py`, plus a manual read of the report as a CISO, a department lead and an OT engineer.
4. Fix, then log the changes here.

The rubric grew with each round, because each critique pass turned up failure modes that had not been tested before.

**Sample:** a fictitious refinery operator. Inputs:

- nmap, with an external, a corporate and an OT zone,
- Nessus,
- OWASP ZAP,
- Burp (from round 3),
- 7 manual findings,
- a 19-asset inventory and 9 departments.

## Round 1: first end-to-end draft

- **Ran:** 31 findings, 59 tickets, 9 departments. **Rubric (13 rules):** 552/562 checks passed.
- **Failures and critique:**
  1. R13: 10 titles were longer than 80 characters (raw nmap CPE strings).
  2. All web misconfigurations merged under the CSP title, so the cookie issue was invisible.
  3. Reflected XSS on an internet-facing portal with personal data ranked P4.
  4. The executive summary called the SOC "the biggest load" only because it gets a detection ticket for every P1/P2. That misleads management.
  5. There was no plain-language reason per finding, so a manager could not challenge a priority.
  6. OT findings had a 30-day SLA but no guidance on what to do in the first 72 h.
- **Changes:**
  - Added `short_title()` (product, version and top CVE, "+N more").
  - Merged findings now use the catalog title plus an issue count.
  - Internet-facing assets with personal data are bumped from TRACK to TRACK\*.
  - The workload sentence now counts **fix** tickets only.
  - Added `explain()`, which writes the "Why" line.
  - Added an OT containment note: contain within 72 h, then the permanent fix via MOC.

## Round 2: priorities and readability

- **Ran:** 562/562 passed. P1×8 (all KEV), P2×12, P3×7, P4×4. OT findings route to OT-ENG with an MOC note.
- **Critique (manual read):**
  1. A merged title was cut mid-word ("...insecure cookie a").
  2. OpenSSH listed its lower-risk CVE first. The title should lead with the one that matters (regreSSHion, CVE-2024-6387).
  3. "No SOC alert on port scans and password spraying" ranked P4. A blind SOC turns every other P3 into a P1, so P4 is too low.
  4. The HMI default-password finding depended on asset criticality to get its rank. Default credentials should never fall below P2.
- **Changes:**
  - Added word-boundary `clip()`.
  - CVEs are sorted with KEV first, then EPSS descending, and the title is rebuilt from that order.
  - Added a per-category `min_priority` floor (logging gap P3, default credentials P2), recorded in the decision reasons.

## Round 3: retest honesty, cross-tool input, edge cases

- **New rubric rules (27 in total):**
  - R14: every finding has a "Why" line that starts with its priority.
  - R15: KEV findings must be P1 or P2.
  - R16: CVE findings must have KEV/EPSS enrichment. This is a WARN, not a FAIL, when no catalog was loaded.
  - R17: findings are sorted by priority.
  - R18: no ticket is due after its finding's SLA.
  - R13 now also rejects titles cut mid-word.
- **Tests run:**
  - full run,
  - retest with `--baseline`,
  - `--lang es` and `--lang pt-BR`,
  - a minimal run with nmap only (no assets, no org, no KEV/EPSS),
  - catalog identifier validation.
- **Critique and changes:**
  1. **Retest lied.** In a rescan with only nmap, every ZAP, Burp, manual and Nessus finding showed as *fixed*, because it was absent from the new run. Re-running with stale files did the opposite: they all showed as *still open*.
     - Fix: every parser records which (tool, host) pairs it covered.
     - A baseline finding counts as **fixed** only if one of its tools re-tested its host. Otherwise it is **not retested (stays open)**.
     - The example jump01 host now shows up in the rescan with RDP closed, so the fix is provable.
  2. **IDs changed between runs** (F-001 became a different finding after the fix), which breaks ticket references.
     - Fix: IDs are reused by fingerprint from the baseline, and new findings continue the numbering.
  3. **Silent degradation.** A run without KEV/EPSS produced plausible-looking priorities with no warning.
     - Fix: the script prints warnings, and the self-test reports the WARN.
  4. **Burp was promised but not parsed.**
     - Fix: added a `--burp` parser (issue type ID plus name keywords).
     - The sample Burp file repeats ZAP's SQL injection on purpose. Result: one finding with sources `burp, zap`, not two.
  5. Asset names in the priority table were cut mid-word ("(DCS/PLC"), so the table now uses `clip()`.
  6. The "Why" line said "P1 because ... the asset is internal only", which reads as a reason *not* to act.
     - Fix: it now says "internal (not internet-facing)" and adds "a successful attack means full compromise of the system" when CVSS v4 ≥ 8.5. Category floors are explained ("Raised to P2 by policy").
  7. Templates were translated to ES and PT-BR. Catalog fix text stays in English by design (one source of truth for technical steps).
- **Results:**

  | Run | Checks passed | Findings | Tickets |
  |---|---|---|---|
  | Main | 669/669 | 31 | 59 |
  | Retest | 354/354 | 16 | 30 |
  | ES | 669/669 | 31 | 59 |
  | PT-BR | 669/669 | 31 | 59 |
  | Minimal (nmap only) | 308/308, plus 1 expected WARN | 18 | 18 |

  - Retest delta: 3 fixed and verified (VPN CVE-2024-3400, fs01 SMBv1, jump01 RDP), 16 still open, 0 new, 12 not retested.
  - `verify_ids.py`: 129/129 ATT&CK v20, D3FEND 1.6.0 and WSTG identifiers valid.

## Round 4: docs, images and the LinkedIn post

- **Scope:** the three README files, the three images, the LinkedIn post, and a full re-run of everything.
- **Checks run:**
  - Each PNG was rendered at 2x (3200 px wide) and opened to look for overlapping, clipped or wrapped text and empty space.
  - Every number in the images and READMEs was compared with `output/` (findings, tickets per department and priority, due dates, retest delta).
  - Every relative link in README.md, README.es.md, README.pt-BR.md and the three SKILL.md files was checked to exist.
  - The LinkedIn post was searched for em and en dashes and a list of filler words. It was also checked for length (about 2,000 characters, under the LinkedIn limit).
  - `run_example.sh`, `verify_ids.py` and the minimal nmap-only run were run again.
- **Critique and changes:**
  1. how_it_works: the P4 SLA line in the "Decide" card wrapped onto two lines, and the cards had a large empty area at the bottom. Fix: monospace no-wrap SLA list, cards sized to content, canvas height cut from 1200 to 1140.
  2. roadmap: the legend squares rendered white because a generic rule overrode the priority colours. Fix: more specific selectors. The canvas was trimmed to remove the blank space under the footer.
  3. diagram, title claim: the first draft said "four owned tickets", but F-004 creates three (fix for IT-INFRA, detection for SOC, compliance for GRC-DPO). MGMT is accountable without a ticket of its own for this finding. Fix: the title now says three, and MGMT is shown as "Accountable · signs off".
  4. diagram, wrong input name: it showed `org.yaml`, but the script takes a departments CSV. Fix: `org_departments.csv`. "Pentest notes" became "Notes (agent → CSV)", because notes are converted to the findings CSV by the agent and not parsed directly.
  5. diagram, wrong footer claim: it said "no network calls at run time", but `--online` fetches KEV and EPSS. Fix: "offline with KEV/EPSS snapshots, or --online".
  6. diagram, wrapping: the department labels and the router text wrapped badly. Fix: shorter labels and no-wrap.
  7. The READMEs promise only what the code does. The weekdays in the intro were checked against the due dates: Nov 4, 2026 is a Wednesday and Nov 5 is a Thursday.
  8. Housekeeping: removed an unused `measure.js` and `__pycache__`, and added `.gitignore`.
- **Results:**
  - Main: 669/669. Retest: 354/354. ES: 669/669. PT-BR: 669/669. Minimal: 308/308, with the expected KEV/EPSS warnings.
  - `verify_ids.py`: 129/129.
  - No broken links.
  - The LinkedIn post has 0 em or en dashes and 0 hits from the filler-word list.
