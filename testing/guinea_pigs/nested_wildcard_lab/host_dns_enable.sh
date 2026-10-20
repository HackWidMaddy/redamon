#!/usr/bin/env bash
# Route ONLY the two lab zones to the lab DNS, on the lab bridge link only.
# Run once per creation of the redamon_sc_lab network: the per-link setting is
# lost when the bridge is recreated. polkit lets the user of an active local
# session change per-link DNS, so no sudo is needed there; over SSH, use sudo.
#
# Recon and its scan containers use network_mode=host and resolve through the
# host's systemd-resolved stub (127.0.0.53); dnspython ignores /etc/hosts.
set -euo pipefail

BR="br-$(docker network inspect -f '{{.Id}}' redamon_sc_lab | cut -c1-12)"
# NetworkManager adopts Docker bridges as "connected (externally)" and can push
# its own (empty) DNS for the link to resolved, silently undoing the lines
# below. Runtime only: Docker owns this bridge, and NM forgets it on restart.
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$BR" managed no || true
fi
resolvectl dns "$BR" 192.88.99.53
resolvectl domain "$BR" '~nwlab.test' '~nwlab-two.test'
# Never the default route: every other name keeps using the normal resolvers.
resolvectl default-route "$BR" false
# The zones are unsigned and .test has no delegation, so DNSSEC validation on
# this link could only turn lab answers into failures.
resolvectl dnssec "$BR" no
resolvectl status "$BR"

if resolvectl query v1.api.nwlab.test 2>/dev/null | grep -q '192.88.99.60'; then
    echo "[+] OK: v1.api.nwlab.test resolves to 192.88.99.60 through the host resolver"
else
    echo "[!] FAILED: v1.api.nwlab.test does not resolve through the host resolver" >&2
    exit 1
fi
