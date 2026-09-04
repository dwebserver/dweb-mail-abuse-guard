# Changelog

All notable changes are documented here. This project follows Semantic Versioning.

## 0.1.1 - 2026-09-04

- Added immediate incident email through the server's local mail transport.
- Added daily 24-hour service health reports and a manual report command.
- Added durable heartbeats, unclean-stop recovery alerts, and fatal service-error emails.

## 0.1.0 - 2026-09-04

- Initial cPanel/Exim/Dovecot detection and containment adapter.
- Audit and enforcement modes with rolling-window policy profiles.
- Durable log cursors, incident history, replay tooling, and optional HTTPS webhook notifications.
- Restricted privileged helper and optional Exim authenticated-recipient rate-limit template.
