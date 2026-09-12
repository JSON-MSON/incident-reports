# CSF 2.0 Mapping

Both incident reports in this repository are structured on the four-phase lifecycle from NIST SP 800-61 Rev 2, *Computer Security Incident Handling Guide*. NIST withdrew that publication on April 3, 2025 and superseded it with [SP 800-61 Rev 3](https://doi.org/10.6028/NIST.SP.800-61r3), *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, which retires the four-phase model and organizes incident response around the six CSF 2.0 Functions instead.

The reports are kept in their original structure. This document maps each report section to the specific CSF 2.0 Subcategories that describe its outcome, so the work stays readable against the current standard without rewriting reports that already reflect how the incidents were actually handled.

Rev 3 provides its own crosswalk from the retired model (Table 1):

| Rev 2 phase | CSF 2.0 Functions |
|---|---|
| Preparation | Govern, Identify (all Categories), Protect |
| Detection & Analysis | Detect, Identify (Improvement) |
| Containment, Eradication & Recovery | Respond, Recover, Identify (Improvement) |
| Post-Incident Activity | Identify (Improvement) |

One structural point from Rev 3 matters for reading the table below. The CSF Functions are not sequential phases — CSF 2.0 states they should be addressed concurrently, and depicts them as a wheel rather than a pipeline. A report section therefore maps to a Function because of the *outcome it produces*, not because of where it falls in the document. Several sections map to more than one Subcategory for that reason.

---

## Section mapping

| Report section | CSF 2.0 Subcategory | Why |
|---|---|---|
| 1. Executive Summary | **RC.RP-06** | Rev 3 R1: prepare an after-action report documenting the incident, the response and recovery actions taken, and lessons learned |
| 2. Timeline of Events | **RS.AN-03** | Rev 3 R1: determine the sequence of events that occurred during the incident and which assets and resources were involved in each |
| 3. Indicators of Compromise | **DE.AE-02**, **DE.AE-03** | Analysis of potentially adverse events to understand associated activity; correlation of information from multiple sources |
| 4. MITRE ATT&CK Mapping | **DE.AE-07** | Rev 3 R1: integrate contextual information into adverse event analysis to characterize threat actors, their methods, and indicators of compromise |
| 5. Triage & Severity Assessment | **RS.MA-02**, **RS.MA-03**, **DE.AE-08** | Triage and validation with severity estimation; categorization and prioritization; declaring an incident when adverse events meet defined criteria |
| 6. Escalation Decision | **RS.MA-04**, **RS.CO-02** | Escalation and elevation as needed; notifying stakeholders once an incident is analyzed and prioritized |
| 7. Containment & Remediation | **RS.MI-01**, **RS.MI-02** | Incidents are contained; incidents are eradicated |
| 8. Root Cause Analysis | **RS.AN-03** | Rev 3 R3: analyze the incident to find the underlying or systemic root causes |
| 9. Lessons Learned | **ID.IM-03** | Rev 3 N3: improvements are often identified when creating follow-up reports for incidents or holding lessons-learned meetings |

### Section-specific additions

**incident-01** — Section 7 also maps to **RS.AN-06** (actions performed during an investigation are recorded). The containment commands were independently verified with a follow-up query rather than trusted from their own success output, and that verification is recorded in the report.

**incident-02** — Section 7 also maps to **RS.AN-07** (incident data and metadata are collected, and their integrity and provenance are preserved) and **RS.AN-08** (an incident's magnitude is estimated and validated). The FIM alert preserved the complete pre-truncation content of the destroyed file, and establishing that only the live on-disk copy was lost is a magnitude determination.

**incident-02** — Section 10 maps to **DE.CM** and **DE.CM-09** (computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events). Rev 3's R4 for DE.CM-09 specifically covers monitoring for signs of tampering.

---

## Coverage and its limits

Mapping the reports against Rev 3 makes the shape of this portfolio's incident work visible, including where it is thin.

**Well covered — Detect and Respond.** Both reports engage the full Respond Function: management, analysis, communication, and mitigation. Detection coverage is real rather than assumed, with detection rules built, validated, and confirmed against live activity before either incident was written.

**Barely covered — Recover.** Neither report performs recovery. incident-01 deleted the offending account; incident-02 explicitly declined to restore the truncated file, since the on-disk copy could not be returned to its exact prior state and the SIEM-preserved diff already served as the authoritative record. Recover therefore appears only through **RC.RP-06**, the after-action report itself. Subcategories RC.RP-01 through RC.RP-05 — recovery plan execution, prioritization of recovery actions, verification of backup integrity, and confirmation of normal operating status — have no corresponding work in either report.

This is a scope limitation of single-host lab exercises, not an oversight in the reports. Recovery outcomes assume restoration of affected systems and services, which these incidents did not require. The closest related work in this portfolio sits outside `incident-reports` entirely: the domain controller backup and restore exercise in [`iam-ad-lab`](https://github.com/JSON-MSON/iam-ad-lab), which verifies the restored domain against a pre-failure snapshot and maps to **RC.RP-05** (the integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed). It does not cover **RC.RP-03**, which calls for checking restoration assets for indicators of compromise before use — the archive there was confirmed readable, not screened.

**Not covered here — Govern, Identify, Protect.** Rev 3 places these outside incident response itself, describing them as broader cybersecurity risk management activities that support it. They are represented elsewhere in this portfolio rather than in these reports.

---

## Note on citation

Where the reports themselves cite SP 800-61, that citation refers to Rev 2 and is historical. Rev 2 is withdrawn and should not be treated as current guidance. Rev 3 is the current publication and is the basis for every mapping in this document.
