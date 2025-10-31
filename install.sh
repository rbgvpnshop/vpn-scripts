#!/usr/bin/env bash
set -e
REPO_RAW="https://raw.githubusercontent.com/rbgvpnshop/vpn-scripts/main"
curl -fsSL "$REPO_RAW/plusx.sh" -o /usr/local/bin/plusx.sh
chmod +x /usr/local/bin/plusx.sh
echo "Installed: /usr/local/bin/plusx.sh"
echo "Run: sudo plusx.sh"
