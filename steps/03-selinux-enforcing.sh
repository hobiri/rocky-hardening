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

# 3. SELinux Configuration
log_info "Step 3: Configuring SELinux"

# Ensure SELinux is enforcing
if selinuxenabled; then
    setenforce 1
else
    log_info "SELinux is not enabled; skipping setenforce."
fi

sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# Install SELinux tools
dnf install -y setools-console policycoreutils-python-utils setroubleshoot-server

# Set secure SELinux booleans
setsebool -P deny_execmem on
setsebool -P secure_mode_insmod on
setsebool -P ssh_sysadm_login off

# Configure SSH port in SELinux (Idempotent and safe approach)
SELINUX_STATUS="Disabled"

if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce)
fi

if [ "$SELINUX_STATUS" != "Disabled" ]; then
    if command -v semanage &>/dev/null; then
        if ! semanage port -l | grep -E "^ssh_port_t\s+tcp\s+.*?\b$SSH_PORT\b" &>/dev/null; then
            semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"
            log_success "Added SELinux rule for SSH port $SSH_PORT (SELinux: $SELINUX_STATUS)"
        else
            log_info "SELinux rule for SSH port $SSH_PORT already exists"
        fi
    else
        log_warning "semanage command not found, cannot configure SELinux for SSH port $SSH_PORT"
    fi
else
    log_info "SELinux is Disabled, skipping port configuration"
fi

log_success "SELinux configured and enforcing"