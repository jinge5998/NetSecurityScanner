#!/bin/bash
# NetSecurityScanner - Linux Startup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "NetSecurityScanner.Linux" ]; then
    echo "Error: NetSecurityScanner.Linux not found"
    exit 1
fi

chmod +x NetSecurityScanner.Linux 2>/dev/null || true

echo "========================================"
echo "  NetSecurity Scanner v1.0 (Linux)"
echo "========================================"

./NetSecurityScanner.Linux "$@"
