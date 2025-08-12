#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 10. SELinux Configuration
log_info "Step 10: Configuring SELinux"

# Ensure SELinux is enforcing
setenforce 1
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