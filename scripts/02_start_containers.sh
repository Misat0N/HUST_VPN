#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[02_start_containers] $*"
}

ensure_container() {
  local name="$1" net="$2" ip="$3"
  local net_flag="--network"
  local ip_flag="--ip"
  if ! docker run --help 2>/dev/null | grep -q -- "--network"; then
    net_flag="--net"
  fi
  if ! docker run --help 2>/dev/null | grep -q -- "--ip"; then
    log "docker run does not support --ip; please upgrade docker"
    exit 1
  fi
  if docker inspect "$name" >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]]; then
      log "starting existing container $name"
      docker start "$name"
    else
      log "container $name already running"
    fi
  else
    log "creating container $name"
    docker run -d --name "$name" --privileged       "$net_flag" "$net" "$ip_flag" "$ip" seedubuntu       bash -c "sleep infinity"
  fi

  log "remove default route in $name"
  docker exec "$name" ip route del default >/dev/null 2>&1 || true
}

ensure_container "HostU" "extranet" "10.0.2.7"
ensure_container "HostV" "intranet" "192.168.60.101"

if [[ -n "${EXTRA_HOSTU:-}" ]]; then
  log "extra HostU list: $EXTRA_HOSTU"
  for item in $EXTRA_HOSTU; do
    name="${item%%:*}"
    ip="${item##*:}"
    if [[ -z "$name" || -z "$ip" || "$name" == "$ip" ]]; then
      log "skip invalid extra entry: $item"
      continue
    fi
    ensure_container "$name" "extranet" "$ip"
  done
fi

log "container IPs"
docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' HostU HostV

log "HostU routes"
docker exec HostU ip route

log "HostV routes"
docker exec HostV ip route
