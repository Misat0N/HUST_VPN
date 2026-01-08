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
    local net_flag="--net"
    if docker run --help 2>/dev/null | grep -q -- "--network"; then
      net_flag="--network"
    fi
    log "creating container $name"
    docker run -d --name "$name" --privileged       "$net_flag" "$net" seedubuntu       bash -c "sleep infinity"
  fi

  if [[ -n "$ip" ]]; then
    log "set static IP $ip/24 on $name"
    if ! docker exec "$name" ip addr flush dev eth0 >/dev/null 2>&1; then
      log "failed to flush eth0 in $name"
    fi
    if ! docker exec "$name" ip addr add "${ip}/24" dev eth0 >/dev/null 2>&1; then
      log "failed to set static IP $ip/24 in $name"
    fi
  fi

  log "remove default route in $name"
  docker exec "$name" ip route del default >/dev/null 2>&1 || true
}

ensure_container "HostU" "extranet" "10.0.2.7"
ensure_container "HostU2" "extranet" "10.0.2.9"
ensure_container "HostU3" "extranet" "10.0.2.10"
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
get_ip() {
  local name="$1"
  docker exec "$name" sh -c "ip -4 -o addr show dev eth0 | sed -n 's/.* inet \\([^ ]*\\) .*/\\1/p'" 2>/dev/null | head -n1 || true
}
echo "HostU $(get_ip HostU)"
echo "HostU2 $(get_ip HostU2)"
echo "HostU3 $(get_ip HostU3)"
echo "HostV $(get_ip HostV)"

log "HostU routes"
docker exec HostU ip route

log "HostV routes"
docker exec HostV ip route
