# Operations

## Rollout

1. Install with `mode: audit`.
2. Replay representative historical logs, including known busy periods and at least one abuse incident.
3. Observe live incidents for several days and assign explicit profiles to legitimate high-volume accounts.
4. Test containment on a dedicated mailbox.
5. Change to `mode: enforce`, validate, and restart.
6. Calibrate the optional Exim ACL in `warn` form before enabling its `deny` form.

## Incident response

When containment fires:

1. Confirm the incident in `journalctl -u dweb-mail-abuse-guard` and `dweb-mail-abuse-guardctl status`.
2. Contact the mailbox owner through a trusted channel.
3. Reset the mailbox password and revoke or rotate credentials stored in mail clients and applications.
4. Inspect the originating devices and the associated website or application for compromise.
5. Review frozen Exim queue entries. Remove confirmed spam manually; do not thaw it blindly.
6. Release the mailbox only after the credentials and source system are clean:

```sh
sudo dweb-mail-abuse-guardctl release --incident INCIDENT_ID
```

Release restores cPanel login and outgoing delivery. It intentionally leaves queue entries frozen for operator review.

## Useful commands

```sh
systemctl status dweb-mail-abuse-guard
journalctl -u dweb-mail-abuse-guard --since today
dweb-mail-abuse-guardctl status
dweb-mail-abuse-guardctl report
```

The `report` command sends the same 24-hour health email used by the daily scheduler. Use it after installation or mail-routing changes to verify delivery immediately.

## Recovery

If the daemon stops, Exim continues to deliver normally unless the optional Exim ACL is installed. Fix the reported error and restart; durable cursors resume from the last committed complete line.

If a containment action partially fails, treat the mailbox as compromised and perform the cPanel suspension manually. The incident remains `failed` rather than claiming full containment.
