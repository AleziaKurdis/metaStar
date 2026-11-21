#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "Run with sudo: sudo ./scripts/install.sh" >&2; exit 1; fi
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then echo "This package currently contains Linux x86_64 only (detected: $ARCH)." >&2; exit 1; fi
if [[ ! -x "$(dirname "$0")/../bin/overte-ice-server" ]]; then echo "Missing precompiled binary in bin/. Extract the complete release ZIP first." >&2; exit 1; fi

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
if ! id overte-ice >/dev/null 2>&1; then useradd --system --home-dir /var/lib/overte-ice --create-home --shell /usr/sbin/nologin overte-ice; fi
install -d -o root -g overte-ice -m 0750 /etc/overte-ice
install -d -o overte-ice -g overte-ice -m 0750 /var/lib/overte-ice
install -o root -g root -m 0755 "$ROOT_DIR/bin/overte-ice-server" /usr/local/bin/overte-ice-server

if [[ ! -f /etc/overte-ice/config.json ]]; then
  read -r -p "Public IPv4 or IPv6 address for ICE HTTPS certificate: " PUBLIC_IP
  if [[ "$PUBLIC_IP" == *:* ]]; then
    if ! [[ "$PUBLIC_IP" =~ ^[0-9A-Fa-f:]+$ ]] || ! getent ahosts "$PUBLIC_IP" >/dev/null 2>&1; then echo "Invalid IPv6 address" >&2; exit 1; fi
    LISTEN_ADDRESS="::"
  else
    if ! [[ "$PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then echo "Invalid IPv4 address" >&2; exit 1; fi
    IFS=. read -r A B C D <<< "$PUBLIC_IP"
    for OCTET in "$A" "$B" "$C" "$D"; do if ((10#$OCTET > 255)); then echo "Invalid IPv4 address" >&2; exit 1; fi; done
    LISTEN_ADDRESS="0.0.0.0"
  fi
  TOKEN=$(openssl rand -hex 32)
  cat > /etc/overte-ice/config.json <<CONFIG
{
  "listen_address": "$LISTEN_ADDRESS",
  "port": 7337,
  "advertise_ip": "$PUBLIC_IP",
  "data_file": "/var/lib/overte-ice/registry.json",
  "tls_cert_file": "/var/lib/overte-ice/tls.crt",
  "tls_key_file": "/var/lib/overte-ice/tls.key",
  "read_timeout_seconds": 10,
  "write_timeout_seconds": 10,
  "enrollment_token": "$TOKEN"
}
CONFIG
  chmod 0640 /etc/overte-ice/config.json
  chown root:overte-ice /etc/overte-ice/config.json
  echo
  echo "Save the ICE enrollment secret securely (never commit to GitHub):"
  echo "$TOKEN"
  echo "Directory Servers use it once to enroll and receive individual credentials."

fi

install -o root -g root -m 0644 "$ROOT_DIR/systemd/overte-ice.service" /etc/systemd/system/overte-ice.service
systemctl daemon-reload
systemctl enable --now overte-ice.service

echo
echo "Overte ICE Server installed."
echo "Check status: sudo systemctl status overte-ice"
echo "View logs:    sudo journalctl -u overte-ice -f"
echo "Firewall (if UFW is active): sudo ufw allow 7337/tcp && sudo ufw allow 7337/udp"
echo "Router must forward BOTH TCP 7337 and UDP 7337 to this machine."
