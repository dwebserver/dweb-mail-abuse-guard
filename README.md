# dweb-mail-abuse-guard

`dweb-mail-abuse-guard` detects compromised mailboxes on cPanel/Exim servers and can contain them before a spam run damages the server's reputation.

It combines two controls:

- a watchdog that correlates authenticated submissions, source-IP changes, authentication failures, and provider abuse rejections;
- an optional Exim RCPT-time rate limit that stops an extreme burst synchronously.

The watchdog starts in **audit mode**. In enforcement mode it suspends login and outgoing delivery for the affected mailbox, terminates active Dovecot sessions, and freezes queued messages from that exact sender. It never changes passwords, deletes mail, or releases frozen messages automatically.

## Supported platform

The first production adapter targets cPanel with Exim and Dovecot on systemd-based Linux distributions. The detection engine is platform-neutral; additional adapters can be added without changing policy evaluation.

## Quick start

Build and test with Go 1.27 or later:

```sh
go test -race ./...
go build -o dist/dweb-mail-abuse-guard ./cmd/dweb-mail-abuse-guard
go build -o dist/dweb-mail-abuse-guardctl ./cmd/dweb-mail-abuse-guardctl
go build -o dist/dweb-mail-abuse-helper ./cmd/dweb-mail-abuse-helper
sudo ./packaging/install.sh
```

The installer preserves an existing configuration and always uses the supplied audit-mode example for a new install.

```sh
systemctl status dweb-mail-abuse-guard
journalctl -u dweb-mail-abuse-guard -f
dweb-mail-abuse-guardctl status
```

Before deployment, replay a historical log to check the thresholds against real traffic:

```sh
dweb-mail-abuse-guard replay \
  --config /etc/dweb-mail-abuse-guard/config.yml \
  --kind exim \
  --path /var/log/exim_mainlog
```

Read [Configuration](docs/configuration.md), [Operations](docs/operations.md), [Architecture](docs/architecture.md), and the [Security model](docs/security-model.md) before enabling enforcement. The optional Exim safety net is documented in [Exim rate limiting](docs/exim-rate-limit.md).

## Privacy and safety

The state database contains timestamps, mailbox identities, source IPs, Exim message IDs, envelope senders, counts, and incident decisions. It does not store passwords, message bodies, subjects, or recipient addresses. Command execution never passes through a shell, and every identity crossing the privilege boundary is validated again by the helper.

## License

Apache License 2.0. See [LICENSE](LICENSE).
