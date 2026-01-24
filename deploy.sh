#!/bin/bash
set -e

cd ~/projects/wireguard-panel

# Commit and push
git add -A
git commit -m "${1:-Update from Claude Code}" || echo "Nothing to commit"
git push

# Deploy to server (git pull as ubuntu, restart as sudo)
ssh -i ~/.ssh/aws_vpn ubuntu@16.54.39.228 'cd /opt/wg-panel && git pull && sudo systemctl restart wg-panel'

echo "✓ Deployed and restarted wg-panel"
