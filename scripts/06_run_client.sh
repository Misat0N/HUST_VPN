#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[06_run_client] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/vpnclient"
CERT_DIR="$ROOT_DIR/cert"

SERVER_HOST="${SERVER_HOST:-vpnserver.com}"
SERVER_IP="${SERVER_IP:-10.0.2.8}"
PORT="${PORT:-4433}"

if [[ "$EUID" -ne 0 ]]; then
  log "must run as root"
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  log "vpnclient not found, build first (make)"
  exit 1
fi

if [[ -z "${VPN_USER:-}" || -z "${VPN_PASS:-}" ]]; then
  log "set VPN_USER and VPN_PASS"
  exit 1
fi

log "ensure HostU is running"
docker start HostU >/dev/null 2>&1 || true

log "copy client and CA to HostU"
docker exec HostU mkdir -p /opt/sslvpn

docker cp "$BIN" HostU:/opt/sslvpn/vpnclient

docker cp "$CERT_DIR/ca.crt" HostU:/opt/sslvpn/ca.crt

log "update /etc/hosts in HostU"
docker exec HostU sh -c "grep -v 'vpnserver.com' /etc/hosts > /tmp/hosts && echo \"$SERVER_IP vpnserver.com\" >> /tmp/hosts && cat /tmp/hosts > /etc/hosts"

MODE="${1:-}"
if [[ "$MODE" == "-d" ]]; then
  log "starting vpnclient in background"
  docker exec -d     -e VPN_USER="$VPN_USER" -e VPN_PASS="$VPN_PASS"     HostU /opt/sslvpn/vpnclient -s "$SERVER_HOST" -p "$PORT" -a /opt/sslvpn/ca.crt
else
  log "starting vpnclient in foreground"
  docker exec -it     -e VPN_USER="$VPN_USER" -e VPN_PASS="$VPN_PASS"     HostU /opt/sslvpn/vpnclient -s "$SERVER_HOST" -p "$PORT" -a /opt/sslvpn/ca.crt
fi
