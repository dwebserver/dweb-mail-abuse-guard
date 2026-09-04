#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "uninstall.sh must be run as root" >&2; exit 1; fi
systemctl disable --now dweb-mail-abuse-guard.service 2>/dev/null || true
rm -f /etc/systemd/system/dweb-mail-abuse-guard.service /etc/sudoers.d/dweb-mail-abuse-guard
rm -f /usr/local/sbin/dweb-mail-abuse-guard /usr/local/sbin/dweb-mail-abuse-guardctl /usr/local/libexec/dweb-mail-abuse-helper
systemctl daemon-reload
echo "Binaries and service files removed. Configuration and incident state were retained."
