#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[09_recover] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STEP03="$ROOT_DIR/scripts/03_hostv_route_back.sh"
STEP05="$ROOT_DIR/scripts/05_run_server.sh"
STEP06="$ROOT_DIR/scripts/06_run_client.sh"

if [[ "$EUID" -ne 0 ]]; then
  log "must run as root"
  exit 1
fi

VPN_USER="${VPN_USER:-}"
VPN_PASS="${VPN_PASS:-}"

if [[ -z "$VPN_USER" ]]; then
  read -r -p "VPN username: " VPN_USER
fi

if [[ -z "$VPN_PASS" ]]; then
  read -r -s -p "VPN password: " VPN_PASS
  echo
fi

export VPN_USER VPN_PASS

log "re-apply HostV return route (03)"
"$STEP03"

log "restart vpnserver (05)"
"$STEP05"

log "restart vpnclient (06)"
"$STEP06"
