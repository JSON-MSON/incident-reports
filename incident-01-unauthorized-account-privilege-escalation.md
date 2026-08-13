# Incident Report: Unauthorized Local Account Creation and Privilege Escalation

**Report ID:** INC-2026-08-12-01
**Classification:** Internal — Lab Exercise
**Framework:** NIST SP 800-61 (Computer Security Incident Handling Guide)
**Severity:** High
**Status:** Escalated — Pending L2 Investigation

---

## 1. Executive Summary

On August 12, 2026, a local Windows account (`svc_update`) was created on a domain-joined endpoint (`DESKTOP-QLHBOB7`) and immediately added to the local `Administrators` group, granting it full administrative control of the machine. Both actions were attributed to the machine's own known local administrator account (`codemane`) — but attribution to a legitimate account does not confirm legitimate intent, since a compromised administrator session would produce identical evidence. Out-of-band verification with the account owner did not confirm the actions were authorized. Given confirmed privilege escalation, an unverified actor, and no supporting change record, this incident is assessed as High severity and escalated to SOC Tier 2 for deeper investigation rather than closed at Tier 1.

## 2. Timeline of Events

All times local (EDT), sourced directly from Windows Security Event Log entries — not estimated.

| Time | Event | Source |
|---|---|---|
| 11:38:06 AM | Local account `svc_update` created | Event ID 4720 |
| 11:38:06 AM | `svc_update` added to default `Users` group (automatic, on creation) | Event ID 4732 |
| 11:38:12 AM | `svc_update` added to `Administrators` group | Event ID 4732 |

The six-second gap between account creation and the `Administrators` addition reflects two separate, deliberate command executions rather than a single automated action — consistent with an operator (human or scripted) manually escalating a freshly created account, not a bulk provisioning process. Both `Administrators` group events (`TargetSid S-1-5-32-544`) and `Users` group events (`TargetSid S-1-5-32-545`) were confirmed directly via full Event Detail review, not inferred from the summary list.

## 3. Indicators of Compromise

| Indicator | Value |
|---|---|
| Account name | `svc_update` |
| Account SID | `S-1-5-21-4040229294-2445324513-3451548623-1006` |
| Host | `DESKTOP-QLHBOB7` |
| Subject account (creator) | `codemane` |
| Subject SID | `S-1-5-21-4040229294-2445324513-3451548623-1001` |
| Target group | `Administrators` (Builtin, SID `S-1-5-32-544`) |
| Password | Set at time of creation; deliberately chosen, not left blank or randomly generated |

The account name itself is a soft indicator worth noting: `svc_update` follows a legitimate-looking service-account naming convention, the kind of name designed to blend into normal administrative activity rather than draw attention — a real, common tradecraft pattern for persistence accounts, not proof of malicious intent on its own.

## 4. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Create Account: Local Account | T1136.001 | Persistence |
| Account Manipulation | T1098 | Persistence |

## 5. Triage & Severity Assessment

**Severity: High.** This assessment rests on completed, verified impact — not a suspicious attempt. Both the account creation and the privilege escalation were independently confirmed via `net user`/`net localgroup` output, not assumed from command success alone. A newly created account with local administrative rights, on a domain-joined machine, represents genuine and immediate elevated access.

**Initial (Tier 1) validation performed before escalation:**
- Reviewed the full Event Detail (Subject field) for both 4720 and 4732 — not just the summary list — to identify the specific account responsible for each action.
- Confirmed the responsible account (`codemane`) is not the local Windows built-in `Administrator` account, but a genuine standing local admin identity.
- Attempted out-of-band verification with the account owner to confirm intent.

**Why this was not closed at Tier 1 despite identifying a known account:** attribution to a legitimate credential is not the same as confirmation of legitimate intent. A compromised administrator session is, if anything, a more severe finding than an unknown external identity performing the same action, since it implies an attacker already holds a functioning foothold with real administrative credentials rather than needing to obtain one. Verification with the account owner did not confirm the actions were intentional or authorized.

## 6. Escalation Decision

**Escalated to SOC Tier 2.** Justification: privilege escalation is confirmed and completed (not attempted), the responsible account's legitimacy could not be verified through available Tier 1 means, and no change record or ticket exists to explain the action. Tier 2 is needed to pursue investigation beyond Tier 1's scope — session and login history review for the `codemane` account around the time of the incident, checking for concurrent or preceding suspicious authentication activity, and determining whether the account's credentials show any sign of compromise.

## 7. Containment & Remediation Actions

Executed and independently verified — not just trusted from the removal commands' own success output:

```powershell
net localgroup Administrators svc_update /delete
net user svc_update /delete
```

Confirmed via a follow-up query:
```powershell
net user svc_update
```
Result: `The user name could not be found.` — genuine confirmation the account no longer exists, not an assumption based on the delete commands reporting success.

In a live environment, these containment actions would typically be held until Tier 2 authorizes them, to preserve the account and its activity for forensic review — removing it immediately can destroy evidence Tier 2 would otherwise need. Documenting that trade-off here rather than skipping it, even though this exercise executed containment immediately.

## 8. Root Cause Analysis

**Unresolved.** This is an honest limitation of the current evidence, not a gap to be papered over: without confirmed intent from the account owner or session-level forensic data (outside this exercise's scope), the actual root cause cannot be conclusively determined. Two possibilities remain open:

1. **Legitimate but undocumented administrative action** — a real but unrecorded change, reflecting a change-management gap rather than a security incident.
2. **Compromised administrative session** — an attacker operating through the `codemane` account's existing privileges, using account creation as a persistence mechanism.

The report deliberately does not force a conclusion between these; a real Tier 2 investigation exists specifically to resolve exactly this kind of ambiguity, and asserting a false certainty here would misrepresent what the available evidence actually supports.

## 9. Lessons Learned / Recommendations

- **No alerting currently exists for Event IDs 4720/4732 on this endpoint.** Both events were only found through manual, retrospective log review — a real detection gap. A future addition to this lab's SIEM coverage: a Wazuh rule correlating 4720 followed by 4732 (Administrators) for the same `TargetUserName` within a short window, surfacing this exact pattern automatically rather than requiring manual discovery.
- **No change-management record exists for local administrative actions on this endpoint.** Even in a home-lab context, this highlights a real, common organizational gap: without a change ticket to check against, Tier 1 has no fast way to distinguish authorized administrative work from malicious activity performed with valid credentials.

## Appendix: Raw Evidence

- `screenshots/event-4720-list.png` — Security log filtered for Event ID 4720, confirming a single account-creation event at the incident timestamp
- `screenshots/event-4720-account-created.png` — Event 4720 full detail view (Subject, Target, timestamps)
- `screenshots/event-4732-list.png` — Security log filtered for Event ID 4732, showing both group-membership events (`11:38:06 AM` and `11:38:12 AM`) at the top of the list
- `screenshots/event-4732-group-membership-added.png` — Event 4732 full detail view (`Administrators` group addition)
- `screenshots/event-4732-users-group-added.png` — Event 4732 full detail view (`Users` group addition, automatic on account creation)
