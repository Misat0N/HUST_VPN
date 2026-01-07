#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[03_hostv_route_back] $*"
}

log "add return route on HostV"
docker exec HostV ip route replace 192.168.53.0/24 via 192.168.60.1

docker exec HostV ip route
