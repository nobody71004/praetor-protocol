#!/usr/bin/env bash
# Deploy the PRAETOR egress data plane to the Dallas exit host.
#
# Run from the workspace root after building:
#   cd praetor
#   node_modules/.bin/esbuild bin/praetor-egress.js --bundle --platform=node \
#     --format=esm --target=node20 --outfile=dist/praetor-egress.mjs
#
# Then:
#   vanta-repo/desktop/server/deploy.sh
set -euo pipefail

HOST="${PRAETOR_EGRESS_SSH:-root@104.251.218.227}"
SSH_KEY="${PRAETOR_EGRESS_SSH_KEY:-tmp/relay_ed25519}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ssh -i "$SSH_KEY" -o BatchMode=yes "$HOST" 'mkdir -p /opt/praetor-egress'

scp -i "$SSH_KEY" -q praetor/dist/praetor-egress.mjs "$HOST:/opt/praetor-egress/praetor-egress.mjs"
scp -i "$SSH_KEY" -q "$HERE/keys/praetor-server.key" "$HOST:/opt/praetor-egress/server.key"
scp -i "$SSH_KEY" -q "$HERE/praetor-egress.service" "$HOST:/etc/systemd/system/praetor-egress.service"
scp -i "$SSH_KEY" -q "$HERE/praetor-ingress.service" "$HOST:/etc/systemd/system/praetor-ingress.service"
scp -i "$SSH_KEY" -q "$HERE/praetor-ingress-rule.sh" "$HOST:/usr/local/sbin/praetor-ingress-rule.sh"

ssh -i "$SSH_KEY" -o BatchMode=yes "$HOST" '
  set -e
  chmod 600 /opt/praetor-egress/server.key
  chmod 755 /usr/local/sbin/praetor-ingress-rule.sh
  systemctl daemon-reload
  systemctl enable --now praetor-ingress.service
  systemctl enable --now praetor-egress.service
  sleep 1
  systemctl --no-pager --lines=10 status praetor-egress.service
'

echo "PRAETOR egress deployed to $HOST"
