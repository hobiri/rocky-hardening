#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 13. Configure secure time synchronization
log_info "Step 13: Configuring secure time synchronization"

dnf install -y chrony

backup_file "/etc/chrony.conf"
cat > /etc/chrony.conf << 'EOF'
# Use Rocky Linux NTP servers
server 0.rocky.pool.ntp.org iburst
server 1.rocky.pool.ntp.org iburst
server 2.rocky.pool.ntp.org iburst
server 3.rocky.pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization
rtcsync

# Specify directory for log files
logdir /var/log/chrony

# Select which information is logged
log measurements statistics tracking

# Deny all clients by default
deny all

# Allow only localhost
allow 127.0.0.1
allow ::1
EOF

systemctl enable --now chronyd
log_success "Secure time synchronization configured"