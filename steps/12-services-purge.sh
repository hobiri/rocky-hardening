#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 12. Disable unnecessary services
log_info "Step 12: Disabling unnecessary services"

SERVICES_TO_DISABLE="avahi-daemon cups bluetooth kdump"
for service in $SERVICES_TO_DISABLE; do
    systemctl disable --now "$service" 2>/dev/null || true
done

# Disable unnecessary network protocols
cat > /etc/modprobe.d/disable-protocols.conf << 'EOF'
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    
log_success "Disabled unnecessary services and protocols"
    