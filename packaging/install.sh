#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh must be run as root" >&2
  exit 1
fi

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary_dir=${BINARY_DIR:-"${root_dir}/dist"}

for binary in dweb-mail-abuse-guard dweb-mail-abuse-guardctl dweb-mail-abuse-helper; do
  if [[ ! -f "${binary_dir}/${binary}" ]]; then
    echo "missing ${binary_dir}/${binary}; build the Linux binaries first" >&2
    exit 1
  fi
done
if [[ ! -r /var/log/exim_mainlog ]]; then
  echo "this installer currently expects a cPanel Exim host" >&2
  exit 1
fi
if ! getent group mail >/dev/null; then
  echo "required mail group does not exist" >&2
  exit 1
fi

if ! getent group dweb-mail-abuse-guard >/dev/null; then
  groupadd --system dweb-mail-abuse-guard
fi
if ! id dweb-mail-abuse-guard >/dev/null 2>&1; then
  useradd --system --gid dweb-mail-abuse-guard --groups mail --home-dir /var/lib/dweb-mail-abuse-guard --shell /sbin/nologin dweb-mail-abuse-guard
else
  usermod --append --groups mail dweb-mail-abuse-guard
fi

install -D -o root -g root -m 0755 "${binary_dir}/dweb-mail-abuse-guard" /usr/local/sbin/dweb-mail-abuse-guard
install -D -o root -g root -m 0755 "${binary_dir}/dweb-mail-abuse-guardctl" /usr/local/sbin/dweb-mail-abuse-guardctl
install -D -o root -g root -m 0755 "${binary_dir}/dweb-mail-abuse-helper" /usr/local/libexec/dweb-mail-abuse-helper
install -D -o root -g root -m 0440 "${root_dir}/packaging/dweb-mail-abuse-guard.sudoers" /etc/sudoers.d/dweb-mail-abuse-guard
visudo -cf /etc/sudoers.d/dweb-mail-abuse-guard >/dev/null
install -D -o root -g root -m 0644 "${root_dir}/packaging/dweb-mail-abuse-guard.service" /etc/systemd/system/dweb-mail-abuse-guard.service

install -d -o root -g dweb-mail-abuse-guard -m 0750 /etc/dweb-mail-abuse-guard
if [[ ! -e /etc/dweb-mail-abuse-guard/config.yml ]]; then
  install -o root -g dweb-mail-abuse-guard -m 0640 "${root_dir}/config/config.example.yml" /etc/dweb-mail-abuse-guard/config.yml
fi
install -d -o dweb-mail-abuse-guard -g dweb-mail-abuse-guard -m 0750 /var/lib/dweb-mail-abuse-guard

/usr/local/sbin/dweb-mail-abuse-guard validate-config --config /etc/dweb-mail-abuse-guard/config.yml
systemctl daemon-reload
systemctl enable dweb-mail-abuse-guard.service
systemctl restart dweb-mail-abuse-guard.service
echo "Installed in audit mode. Review docs/operations.md before enabling enforcement."
