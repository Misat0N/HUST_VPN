#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[01_gateway_forwarding] $*"
}

ACTION="${1:-start}"

if [[ "$ACTION" == "clean" || "$ACTION" == "stop" ]]; then
  log "removing iptables rules"
  iptables -D FORWARD -i docker1 -o docker2 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i docker2 -o docker1 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i docker1 -o docker2 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i docker2 -o docker1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  sysctl -w net.ipv4.ip_forward=0
  sysctl net.ipv4.ip_forward
  iptables -L FORWARD -n -v
  exit 0
fi

log "enable ip forwarding"
sysctl -w net.ipv4.ip_forward=1

log "configure iptables forwarding between docker1 and docker2"
iptables -C FORWARD -i docker1 -o docker2 -j ACCEPT 2>/dev/null ||   iptables -A FORWARD -i docker1 -o docker2 -j ACCEPT
iptables -C FORWARD -i docker2 -o docker1 -j ACCEPT 2>/dev/null ||   iptables -A FORWARD -i docker2 -o docker1 -j ACCEPT
iptables -C FORWARD -i docker1 -o docker2 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||   iptables -A FORWARD -i docker1 -o docker2 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -i docker2 -o docker1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||   iptables -A FORWARD -i docker2 -o docker1 -m state --state RELATED,ESTABLISHED -j ACCEPT

sysctl net.ipv4.ip_forward
iptables -L FORWARD -n -v
