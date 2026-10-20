#!/usr/bin/env bash
# Undo host_dns_enable.sh (same privileges: an active local session, or sudo).
set -euo pipefail

BR="br-$(docker network inspect -f '{{.Id}}' redamon_sc_lab | cut -c1-12)"
resolvectl revert "$BR"
echo "[*] Reverted DNS settings on $BR"
