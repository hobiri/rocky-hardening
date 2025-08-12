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

# 8. NFT Firewall Configuration
log_info "Step 8: Configuring NFT firewall"
backup_file "/etc/nftables.conf"

# Disable and stop firewalld
systemctl disable --now firewalld 2>/dev/null || true

# Install and configure nftables
dnf install -y nftables

# Create nftables configuration
cat > /etc/nftables/main.nft << EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow loopback
        iif lo accept
        
        # Allow established connections
        ct state established,related accept
        
        # Drop invalid connections
        ct state invalid drop
        
        # Allow ICMP with rate limiting
        ip protocol icmp icmp type { echo-request, echo-reply } limit rate 10/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply } limit rate 10/second accept
        
        # Allow SSH with rate limiting
        tcp dport $SSH_PORT ct state new limit rate 3/minute accept
        
        # Allow HTTP/HTTPS
        tcp dport { 80, 443 } accept
        
        # Log dropped packets (uncomment if needed)
        # log prefix "[nftables] Dropped: " level info
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

log_info "Validating nftables configuration..."

if nft -c -f /etc/nftables/main.nft; then
    log_success "nftables configuration is valid"
else
    log_error "nftables configuration validation failed"
    exit 1
fi

# Set proper permissions and enable nftables
chmod 755 /etc/nftables/main.nft
systemctl enable --now nftables
log_success "nftables firewall configured and enabled"