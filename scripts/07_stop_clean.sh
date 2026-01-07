#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[07_stop_clean] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="$ROOT_DIR/run/vpnserver.pid"

log "stopping vpnserver"
if [[ -f "$PIDFILE" ]]; then
  PID="$(cat "$PIDFILE")"
  if ps -p "$PID" >/dev/null 2>&1; then
    kill "$PID" || true
  fi
  rm -f "$PIDFILE"
fi

log "stopping vpnclient in HostU"
docker exec HostU pkill vpnclient >/dev/null 2>&1 || true

log "cleaning tun0 on host and HostU"
ip link del tun0 >/dev/null 2>&1 || true
docker exec HostU ip link del tun0 >/dev/null 2>&1 || true

log "cleaning routes"
docker exec HostU ip route del 192.168.60.0/24 >/dev/null 2>&1 || true
docker exec HostV ip route del 192.168.53.0/24 via 192.168.60.1 >/dev/null 2>&1 || true

if [[ "${1:-}" == "--purge" ]]; then
  log "purge containers and networks"
  docker rm -f HostU HostV >/dev/null 2>&1 || true
  docker network rm extranet intranet >/dev/null 2>&1 || true
fi
