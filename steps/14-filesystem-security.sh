#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "${SCRIPT_DIR}/config.sh" ]] || [[ ! -f "${SCRIPT_DIR}/helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source "${SCRIPT_DIR}/config.sh"
source "${SCRIPT_DIR}/helpers.sh"

# 14. File system security
log_info "Step 14: Securing file system permissions"

# Find and fix world-writable files (limit to avoid long execution)
find /usr /etc /bin /sbin -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null | head -100

# Remove unnecessary SUID/SGID bits
chmod u-s /usr/bin/at 2>/dev/null || true
chmod u-s /usr/bin/lppasswd 2>/dev/null || true
chmod u-s /usr/bin/newgrp 2>/dev/null || true
chmod g-s /usr/bin/wall 2>/dev/null || true

log_success "File system permissions secured"