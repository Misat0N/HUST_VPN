#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[08_capture] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAP_DIR="$ROOT_DIR/captures"

IFACE="docker1"
PORT=""
NET=""

while getopts ":i:p:n:" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    p) PORT="$OPTARG" ;;
    n) NET="$OPTARG" ;;
    *)
      echo "usage: $0 -i <iface> [-p port] [-n net]"
      exit 1
      ;;
  esac
done

mkdir -p "$CAP_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
FILE="$CAP_DIR/${IFACE}_${TS}.pcap"

FILTER=""
if [[ -n "$PORT" ]]; then
  FILTER="$FILTER port $PORT"
fi
if [[ -n "$NET" ]]; then
  FILTER="$FILTER net $NET"
fi

log "capturing on $IFACE to $FILE"
if [[ -n "$FILTER" ]]; then
  tcpdump -i "$IFACE" -w "$FILE" $FILTER
else
  tcpdump -i "$IFACE" -w "$FILE"
fi
