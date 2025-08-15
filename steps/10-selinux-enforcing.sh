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

# 10. SELinux Configuration
log_info "Step 10: Configuring SELinux"

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

# Configure SSH port in SELinux
semanage port -a -t ssh_port_t -p tcp $SSH_PORT 2>/dev/null || \
semanage port -m -t ssh_port_t -p tcp $SSH_PORT

log_success "SELinux configured and enforcing"