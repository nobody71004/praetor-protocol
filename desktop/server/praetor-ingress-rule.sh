#!/bin/sh
# Nexus Shield owns the `nexus_edge` table and regenerates it from its JSON
# config. This oneshot service runs after shield and adds the single PRAETOR
# ingress allowance without touching any other rule. It is PartOf the shield
# unit, so a shield restart re-runs it.
set -eu

if ! nft list table inet nexus_edge >/dev/null 2>&1; then
  echo "nexus_edge table is missing; refusing to guess a firewall layout" >&2
  exit 1
fi

if nft list chain inet nexus_edge input | grep -q 'praetor:egress'; then
  exit 0
fi

nft insert rule inet nexus_edge input tcp dport 9443 accept comment '"praetor:egress"'
