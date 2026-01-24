#!/bin/bash
set -e

cd ~/projects/wireguard-panel

# Commit and push
git add -A
git commit -m "${1:-Update from Claude Code}" || echo "Nothing to commit"
git push

# Deploy to server
ssh -i ~/.ssh/aws_vpn ubuntu@16.54.39.228 'cd /opt/wg-panel && sudo git pull && sudo systemctl restart wg-panel'

echo "✓ Deployed and restarted wg-panel"
