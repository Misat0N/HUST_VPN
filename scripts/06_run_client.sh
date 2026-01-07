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
CLIENT_NAME="${CLIENT_NAME:-HostU}"
CLIENT_DIR="${CLIENT_DIR:-/opt/sslvpn}"

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
docker start "$CLIENT_NAME" >/dev/null 2>&1 || true

log "copy client and CA to HostU"
docker exec "$CLIENT_NAME" mkdir -p "$CLIENT_DIR"

docker cp "$BIN" "$CLIENT_NAME":"$CLIENT_DIR"/vpnclient

docker cp "$CERT_DIR/ca.crt" "$CLIENT_NAME":"$CLIENT_DIR"/ca.crt

log "update /etc/hosts in HostU"
docker exec "$CLIENT_NAME" sh -c "grep -v '$SERVER_HOST' /etc/hosts > /tmp/hosts && echo \"$SERVER_IP $SERVER_HOST\" >> /tmp/hosts && cat /tmp/hosts > /etc/hosts"

MODE="${1:-}"
if [[ "$MODE" == "-d" ]]; then
  log "starting vpnclient in background"
  docker exec -d "$CLIENT_NAME" env VPN_USER="$VPN_USER" VPN_PASS="$VPN_PASS" \
    "$CLIENT_DIR"/vpnclient -s "$SERVER_HOST" -p "$PORT" -a "$CLIENT_DIR"/ca.crt
else
  log "starting vpnclient in foreground"
  docker exec -it "$CLIENT_NAME" env VPN_USER="$VPN_USER" VPN_PASS="$VPN_PASS" \
    "$CLIENT_DIR"/vpnclient -s "$SERVER_HOST" -p "$PORT" -a "$CLIENT_DIR"/ca.crt
fi
