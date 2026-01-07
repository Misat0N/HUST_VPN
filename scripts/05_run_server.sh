#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[05_run_server] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/vpnserver"
LOG_DIR="$ROOT_DIR/logs"
RUN_DIR="$ROOT_DIR/run"
PIDFILE="$RUN_DIR/vpnserver.pid"
LOGFILE="$LOG_DIR/vpnserver.log"

LISTEN_IP="${LISTEN_IP:-10.0.2.8}"
PORT="${PORT:-4433}"
CERT="${CERT:-$ROOT_DIR/cert/server.crt}"
KEY="${KEY:-$ROOT_DIR/cert/server.key}"
CA="${CA:-$ROOT_DIR/cert/ca.crt}"
VPN_SUBNET="${VPN_SUBNET:-192.168.53.0/24}"
TUN_IP="${TUN_IP:-192.168.53.1/24}"
ROUTE_NET="${ROUTE_NET:-192.168.60.0/24}"
MTU="${MTU:-1400}"

if [[ "$EUID" -ne 0 ]]; then
  log "must run as root"
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  log "vpnserver not found, build first (make)"
  exit 1
fi

if [[ ! -c /dev/net/tun ]]; then
  log "/dev/net/tun not available"
  exit 1
fi

mkdir -p "$LOG_DIR" "$RUN_DIR"

if [[ -f "$PIDFILE" ]] && ps -p "$(cat "$PIDFILE")" >/dev/null 2>&1; then
  log "vpnserver already running (pid $(cat "$PIDFILE"))"
  exit 0
fi

if [[ "${1:-}" == "--foreground" ]]; then
  log "starting vpnserver in foreground"
  exec "$BIN" -l "$LISTEN_IP" -p "$PORT" -c "$CERT" -k "$KEY" -a "$CA"     -s "$VPN_SUBNET" -t "$TUN_IP" -r "$ROUTE_NET" -m "$MTU"
else
  log "starting vpnserver in background"
  nohup "$BIN" -l "$LISTEN_IP" -p "$PORT" -c "$CERT" -k "$KEY" -a "$CA"     -s "$VPN_SUBNET" -t "$TUN_IP" -r "$ROUTE_NET" -m "$MTU"     > "$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  log "pid $(cat "$PIDFILE"), log $LOGFILE"
fi
