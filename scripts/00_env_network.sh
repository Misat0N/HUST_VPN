#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[00_env_network] $*"
}

create_net() {
  local name="$1" subnet="$2" gateway="$3" bridge="$4"
  if docker network inspect "$name" >/dev/null 2>&1; then
    log "network $name already exists"
  else
    log "creating network $name"
    docker network create --driver bridge       --subnet "$subnet" --gateway "$gateway"       -o com.docker.network.bridge.name="$bridge" "$name"
  fi
}

create_net "extranet" "10.0.2.0/24" "10.0.2.8" "docker1"
create_net "intranet" "192.168.60.0/24" "192.168.60.1" "docker2"

log "docker networks:"
docker network ls

log "network details:"
docker network inspect extranet intranet | sed -n '1,80p'
