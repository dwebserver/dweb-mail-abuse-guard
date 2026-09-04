# Architecture

The product deliberately separates observation from privilege.

```text
Exim/Dovecot logs
       |
       v
unprivileged daemon -> parser -> rolling policy engine -> BoltDB incident record
                                                      |
                                      audit: notify only
                                      enforce: sudo exact helper
                                                      |
                                                      v
                           cPanel UAPI + doveadm + exact-sender queue freeze
```

The daemon runs as `dweb-mail-abuse-guard` with read access to Exim's log through the `mail` group. Its durable cursor survives restarts and detects truncation or rotation using the file identity, size, and a prefix hash.

Status and release operations use a local Unix socket with mode `0660`; they do not open the database from a second process. The daemon remains the only database owner, and membership in the socket's group controls access to the local API.

The helper is intentionally small. It accepts only `contain` and `release`, validates a conservative mailbox syntax and a generated incident identifier, resolves the domain's cPanel owner, verifies the mailbox belongs to that account, and then runs fixed absolute commands with argument arrays. It cannot execute arbitrary shell text.

## Detection rules

Policy uses rolling five-minute, ten-minute, and one-hour windows. A containment decision requires one of these signals:

- the hard ten-minute recipient ceiling is reached;
- a five-minute recipient burst occurs across the configured number of source IPs;
- a provider abuse rejection is correlated to an authenticated Exim message during abnormal volume.

High authentication-failure volume creates a warning, not containment. That prevents an unauthenticated attacker from disabling somebody else's mailbox.

Warnings and containment decisions are explainable and retain the exact counters that fired. A warning does not suppress a later containment escalation.

## Failure behavior

Events are persisted before evaluation. Incidents are created atomically and deduplicated per mailbox during the cooldown. A failed privileged action is recorded as `failed`, logged, and never reported as successful. Notification failure does not undo containment or stop log processing.

The optional Exim ACL is independent of the watchdog. It remains effective if the daemon is unavailable, while the watchdog supplies correlation, containment, incident history, and notification.
