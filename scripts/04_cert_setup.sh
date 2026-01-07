#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[04_cert_setup] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/cert"

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/ca.key"
CA_CRT="$CERT_DIR/ca.crt"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CRT="$CERT_DIR/server.crt"
SERVER_EXT="$CERT_DIR/server.ext"
CA_SRL="$CERT_DIR/ca.srl"

if [[ "$FORCE" -eq 1 ]]; then
  log "force mode: removing existing certs"
  rm -f "$CA_KEY" "$CA_CRT" "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT" "$SERVER_EXT" "$CA_SRL"
fi

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
  log "generating CA"
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650     -subj "/CN=VPN Test CA" -out "$CA_CRT"
else
  log "CA already exists"
fi

if [[ ! -f "$SERVER_KEY" || ! -f "$SERVER_CRT" ]]; then
  log "generating server key and cert"
  openssl genrsa -out "$SERVER_KEY" 2048
  openssl req -new -key "$SERVER_KEY" -subj "/CN=vpnserver.com" -out "$SERVER_CSR"

  cat > "$SERVER_EXT" <<EOF
subjectAltName = DNS:vpnserver.com
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

  openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY"     -CAcreateserial -out "$SERVER_CRT" -days 365 -sha256 -extfile "$SERVER_EXT"
else
  log "server cert already exists"
fi

log "certs ready in $CERT_DIR"
