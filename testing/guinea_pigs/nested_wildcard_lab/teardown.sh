#!/usr/bin/env bash
# Stop the nested-wildcard lab. The shared redamon_sc_lab network is left alone:
# it belongs to the supply_chain_target project, and removing it also drops the
# per-link DNS setting (host_dns_enable.sh). To remove it, after this script:
#   docker compose -f ../supply_chain_target/docker-compose.yml down
set -euo pipefail
cd "$(dirname "$0")"
docker compose down
echo "[*] Lab down. 192.88.99.0/24 may now route to the internet: no lab scans until setup.sh runs again."
