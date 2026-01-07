#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[11_add_user] $*"
}

if [[ "$EUID" -ne 0 ]]; then
  log "must run as root"
  exit 1
fi

NEW_USER="${NEW_USER:-}"
NEW_PASS="${NEW_PASS:-}"
ADD_SUDO="${ADD_SUDO:-no}"

if [[ -z "$NEW_USER" ]]; then
  read -r -p "New username: " NEW_USER
fi
if [[ -z "$NEW_USER" ]]; then
  log "username required"
  exit 1
fi

if id -u "$NEW_USER" >/dev/null 2>&1; then
  log "user $NEW_USER already exists"
else
  log "creating user $NEW_USER"
  useradd -m -s /bin/bash "$NEW_USER"
fi

if [[ -z "$NEW_PASS" ]]; then
  read -r -s -p "New password: " NEW_PASS
  echo
fi
if [[ -z "$NEW_PASS" ]]; then
  log "password required"
  exit 1
fi
if [[ "$NEW_PASS" == *:* ]]; then
  log "password cannot contain ':'"
  exit 1
fi

echo "$NEW_USER:$NEW_PASS" | chpasswd
log "password set for $NEW_USER"

if [[ "$ADD_SUDO" == "yes" ]]; then
  usermod -aG sudo "$NEW_USER"
  log "added $NEW_USER to sudo group"
fi
