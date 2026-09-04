# Configuration

The YAML decoder rejects unknown fields. Paths must be absolute and durations use Go notation such as `500ms`, `10m`, or `24h`.

## Operating mode

`mode: audit` records incidents and sends notifications without changing mailboxes. Keep a new installation in audit mode long enough to cover normal peaks. Change to `enforce` only after replay and live observations show acceptable thresholds.

## Profiles

Each mailbox uses `default_profile` unless it appears in `accounts`. Recipient counts are counts observed on authenticated Exim acceptance records; source IPs are distinct authenticated client addresses.

The standard example warns at 50 recipients in five minutes and contains at 200 recipients in ten minutes. It can contain earlier at five recipients if at least five source IPs were observed during the preceding hour, a pattern that catches distributed credential abuse without treating a single roaming device as proof of compromise. A correlated provider rejection requires at least 20 recent recipients.

Use a separate `high_volume` profile for known applications. Do not raise the global profile to accommodate one sender.

## Sources

`start_at_end: true` prevents a first start from treating historical mail as live. The stored cursor takes precedence on later starts. Add a Dovecot source only when its log is readable by the service account:

```yaml
- kind: dovecot
  path: /var/log/maillog
  start_at_end: true
```

If log rotation recreates that file without the required access, update the platform's logrotate policy rather than making it world-readable.

## Notifications

Put one HTTPS webhook URL in a root-managed file and set `webhook_url_file` to its absolute path. The URL is never logged or passed as a process argument. The webhook receives the incident JSON. Empty configuration disables external notifications; incidents still appear in the journal and state database.

## Validation

```sh
dweb-mail-abuse-guard validate-config --config /etc/dweb-mail-abuse-guard/config.yml
```

Restart the service after a valid change. There is no implicit live reload.
