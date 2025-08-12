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

# 1. System Update
log_info "Step 1: Updating system packages"

dnf update -y
dnf install -y dnf-automatic

# Configure automatic security updates
backup_file "/etc/dnf/automatic.conf"

# Ensure upgrade_type is set to security (uncomment or add if missing)
if grep -qE '^\s*#?\s*upgrade_type\s*=' /etc/dnf/automatic.conf; then
    sed -i 's|^\s*#\?\s*upgrade_type\s*=.*|upgrade_type = security|' /etc/dnf/automatic.conf
    log_info "Set upgrade_type to security in dnf-automatic.conf"
else
    echo "upgrade_type = security" >> /etc/dnf/automatic.conf
fi

# Ensure apply_updates is set to yes (uncomment or add if missing)
if grep -qE '^\s*#?\s*apply_updates\s*=' /etc/dnf/automatic.conf; then
    sed -i 's|^\s*#\?\s*apply_updates\s*=.*|apply_updates = yes|' /etc/dnf/automatic.conf
    log_info "Set apply_updates to yes in dnf-automatic.conf"
else
    echo "apply_updates = yes" >> /etc/dnf/automatic.conf
fi

systemctl enable --now dnf-automatic.timer

log_success "System updated and automatic security updates configured"
