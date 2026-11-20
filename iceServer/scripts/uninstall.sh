#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "Run with sudo: sudo ./scripts/uninstall.sh" >&2; exit 1; fi
systemctl disable --now overte-ice.service 2>/dev/null || true
rm -f /etc/systemd/system/overte-ice.service /usr/local/bin/overte-ice-server
systemctl daemon-reload
if [[ ${1:-} == "--purge" ]]; then rm -rf /etc/overte-ice /var/lib/overte-ice; echo "Service and configuration/data removed."; else echo "Service removed. Configuration and registry retained in /etc/overte-ice and /var/lib/overte-ice."; fi
