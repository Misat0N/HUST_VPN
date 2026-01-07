#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[02_start_containers] $*"
}

ensure_container() {
  local name="$1" net="$2" ip="$3"
  if docker inspect "$name" >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]]; then
      log "starting existing container $name"
      docker start "$name"
    else
      log "container $name already running"
    fi
  else
    log "creating container $name"
    docker run -d --name "$name" --privileged       --network "$net" --ip "$ip" seedubuntu       bash -c "sleep infinity"
  fi

  log "remove default route in $name"
  docker exec "$name" ip route del default >/dev/null 2>&1 || true
}

ensure_container "HostU" "extranet" "10.0.2.7"
ensure_container "HostV" "intranet" "192.168.60.101"

log "container IPs"
docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' HostU HostV

log "HostU routes"
docker exec HostU ip route

log "HostV routes"
docker exec HostV ip route
