# Security model

## Assets and trust boundaries

The protected assets are server sending reputation, customer mailbox availability, queued mail, cPanel account boundaries, and incident evidence. Mail logs and webhook responses are untrusted input. The daemon is unprivileged; the sudo transition into `dweb-mail-abuse-helper` is the primary trust boundary.

## Required properties

- An unauthenticated failure burst must never suspend a mailbox by itself.
- A mailbox identity must be syntactically validated and verified against its resolved cPanel owner before any action.
- No log-derived value may become shell syntax or select an executable path.
- Containment must affect only the detected mailbox and queue entries with its exact envelope sender.
- A failed or partial action must never be recorded as successful.
- Audit mode must have no mailbox or queue side effects.
- Frozen mail must not be thawed automatically during release.

## Principal threats and controls

| Threat | Control |
|---|---|
| Stolen SMTP credential sends distributed spam | Rolling recipient/source-IP correlation and provider rejection correlation |
| Attacker deliberately fails authentication to disable a victim | Authentication failures produce warnings only |
| Crafted mailbox or log value injects a command | Conservative identity validation, fixed executable paths, argument arrays, no shell |
| Cross-account cPanel action | Domain owner resolution followed by UAPI mailbox ownership verification |
| Duplicate readers repeat containment | Atomic active-incident record and cooldown |
| Log rotation loses or replays events | Durable byte offset, file identity, size check, and prefix hash |
| Notification outage blocks response | Local incident persistence and journal logging; webhook is secondary |
| Compromised daemon abuses root | Sudo permits only the validation helper; the daemon has no general root command |

The daemon's systemd unit cannot use `NoNewPrivileges` or `RestrictSUIDSGID`: cPanel's sendmail wrapper and the restricted sudo helper both rely on controlled set-ID transitions. The privilege boundary is therefore enforced by the dedicated service UID, exact sudo command, helper input validation, fixed executable paths, and cPanel ownership verification.

## Deliberate limitations

This release does not scan WordPress, endpoints, or message content and does not determine how a credential was stolen. It contains observed mail abuse and preserves enough metadata for an administrator to investigate. It also does not replace provider feedback loops, DNS authentication, outbound content filtering, or host intrusion detection.
