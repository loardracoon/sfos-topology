#!/usr/bin/env bash
# Capture the ten read-only endpoints from one Sophos Firewall into a
# directory that sfos-topology can replay with -config ... offlineDir.
#
#   ./capture.sh 192.168.101.99:4444 "$SFOS_TOKEN" captures/fw01
#
# The token is read from argv here for brevity; in anything but a lab, export
# it and pass "$SFOS_TOKEN" so it does not land in your shell history.
#
# -k skips certificate validation because appliances ship self-signed certs.
# Pin the fingerprint properly in the collector; do not carry -k into anything
# that runs unattended.
set -euo pipefail

HOST="${1:?usage: capture.sh host:port token outdir}"
TOKEN="${2:?missing token}"
OUT="${3:?missing output directory}"

BASE="https://${HOST}/api/firewall-config/v1"
mkdir -p "$OUT"

get() {
  local path="$1" file="$2" paged="${3:-yes}"
  local url="${BASE}${path}"
  [ "$paged" = "yes" ] && url="${url}?pageSize=100&pageTotal=true"
  if curl -sk --fail-with-body \
      -H "Accept: application/json" \
      -H "Authorization: Bearer ${TOKEN}" \
      "$url" -o "${OUT}/${file}"; then
    printf '  ok   %s\n' "$file"
  else
    # A restricted API profile may deny individual endpoints. The collector
    # degrades rather than failing, so a missing file is not fatal.
    printf '  skip %s (denied or unavailable)\n' "$file"
    rm -f "${OUT}/${file}"
  fi
}

printf 'capturing %s -> %s\n' "$HOST" "$OUT"
get /network/zones                              zones.json
get /network/interfaces/network-interfaces      interfaces.json
get /routing/gateways/ipv4                      gateways.json
get /routing/gateways/wan/ipv4                  wan-gateways.json
get /routing/static-unicast-routes/ipv4         routes.json
get /network/dhcp/servers/ipv4                  dhcp-servers.json
get /ipsec-vpn/site-to-site/connections/ipv4    ipsec.json
get /network/addresses/ipv4                     ip-addresses.json
get /administration/system-settings             system-settings.json no
get /sophos-central/status                      central-status.json no

printf 'done. replay with: sfos-topology -config devices.json\n'
