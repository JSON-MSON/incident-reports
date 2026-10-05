# CSF 2.0 Mapping

Rev 3 is explicit that only three of the six CSF 2.0 Functions constitute incident response itself: "the preparation activities of Govern, Identify, and Protect are not part of the incident response itself. Rather, they are much broader cybersecurity risk management activities that also support incident response." Rev 3 organizes incident response around Detect, Respond, and Recover. This document maps each report section to the CSF 2.0 Subcategories that describe its outcome.

The CSF Functions are not sequential phases: CSF 2.0 says they should be addressed concurrently and depicts them as a wheel, not a pipeline. A report section therefore maps to a Function by the *outcome it produces*, not by where it falls in the document, which is why several sections map to more than one Subcategory.

---

## Section mapping

Both reports share this structure, section for section; incident-02 adds a Section 8, mapped below under its section-specific additions.

| Report section | CSF 2.0 Subcategory | Why |
|---|---|---|
| 1. Executive Summary | — | A summary of what follows, not a distinct CSF activity. RC.RP-06's after-action report is met by the report as a whole and cited at the Recover section, not here. |
| 2. Detect | **DE.AE-02**, **DE.AE-03**, **DE.AE-07** | Contains Indicators of Compromise (analysis of potentially adverse events; correlation of information from multiple sources) and MITRE ATT&CK Mapping (Rev 3 R1: integrate contextual information into adverse event analysis to characterize threat actors, their methods, and indicators of compromise) |
| 3. Respond — Incident Management | **RS.MA-02**, **RS.MA-03**, **RS.MA-04**, **DE.AE-08**, **RS.CO-02** | Contains Timeline of Events (sequence reconstruction, itself **RS.AN-03** — presented here for narrative continuity with the triage it informs), Triage & Severity Assessment (triage/validation with severity estimation; categorization and prioritization; declaring an incident when adverse events meet defined criteria), and Escalation Decision (escalation/elevation as needed; notifying stakeholders once an incident is analyzed and prioritized) |
| 4. Respond — Incident Analysis | **RS.AN-03** | Contains Root Cause Analysis — Rev 3 R3: analyze the incident to find the underlying or systemic root causes |
| 5. Respond — Mitigation | **RS.MI-01**, **RS.MI-02** | Contains Containment & Remediation Actions — incidents are contained; incidents are eradicated |
| 6. Recover | **RC.RP-06** | Rev 3 R1: prepare an after-action report documenting the incident, the response and recovery actions taken, and lessons learned. States why RC.RP-01 through RC.RP-05 don't apply to either incident. |
| 7. Improvement | **ID.IM-03** | Contains Lessons Learned / Recommendations — Rev 3 N3: improvements are often identified when creating follow-up reports for incidents or holding lessons-learned meetings |

### Section-specific additions

**incident-01** — Section 5 (Respond — Mitigation) also maps to **RS.AN-06** (actions performed during an investigation are recorded). A follow-up query was run and documented rather than trusting the delete commands' own success output; the Security log records the removal and deletion, and the query's reply survives as terminal output pasted at the time.

**incident-02** — Section 5 (Respond — Mitigation) also maps to **RS.AN-07** (incident data and metadata are collected, and their integrity and provenance are preserved) and **RS.AN-08** (an incident's magnitude is estimated and validated). The FIM alert preserved the complete pre-truncation content of the destroyed file, and establishing that only the live on-disk copy was lost is a magnitude determination.

**incident-02** — Section 8 (Detection Engineering Notes) maps to **DE.CM** and **DE.CM-09** (computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events). Rev 3's R4 for DE.CM-09 specifically covers monitoring for signs of tampering.

---

## Coverage and its limits

Mapping the reports against Rev 3 makes the shape of this portfolio's incident work visible, including where it is thin.

**Well covered — Detect and Respond.** Both reports engage the full Respond Function: management, analysis, communication, and mitigation. Detection differs between the two. `incident-02`'s detection was real and pre-built: the File Integrity Monitoring coverage of `auth.log`, which Wazuh's built-in integrity rule 550 alerts on, was configured and debugged until it produced a genuine, dashboard-visible alert (Section 8). `incident-01`'s was not; its Lessons Learned section states that "no alerting currently exists for Event IDs 4720/4732 on this endpoint. Both events were only found through manual, retrospective log review — a real detection gap." One shows engineered detection; the other shows a real gap found and documented. Both are legitimate SOC skills, but not the same skill, and claiming both reports show pre-built detection would contradict `incident-01` itself.

**Barely covered — Recover.** Neither report performs recovery. `incident-01` removed the offending account; `incident-02` declined to restore the truncated file, since the SIEM-preserved diff already served as the authoritative record. Recover therefore appears only through **RC.RP-06**, satisfied by each report's Recover section, which states that recovery wasn't required. Subcategories RC.RP-01 through RC.RP-05 — recovery plan execution, prioritization of recovery actions, verification of backup integrity, establishing post-incident operational norms, and confirmation of normal operating status — have no corresponding work in either report.

This is a scope limitation of single-host lab exercises, not an oversight in the reports. Recovery outcomes assume restoration of affected systems and services, which these incidents did not require. The closest related work sits outside `incident-reports`: the Samba DC backup and restore exercise in [`iam-ad-lab`](https://github.com/JSON-MSON/iam-ad-lab), which verifies the restored domain against a pre-failure snapshot and maps to **RC.RP-05** (the integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed). It does not cover **RC.RP-03**, which calls for checking restoration assets for indicators of compromise before use — the archive there was confirmed readable, not screened.

**Not covered here — Govern, Identify, Protect.** Rev 3 places these outside incident response itself, describing them as broader cybersecurity risk management activities that support it. They are represented elsewhere in this portfolio rather than in these reports.
