#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 9. CrowdSec Configuration
log_info "Step 9: Configuring CrowdSec"
backup_file "/etc/crowdsec/config.yaml"

# Install CrowdSec repository
RETRY_COUNT=3

for i in $(seq 1 $RETRY_COUNT); do
    if curl -s --max-time 10 https://packagecloud.io &>/dev/null; then
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash
        break
    elif [[ $i -eq $RETRY_COUNT ]]; then
        log_warning "CrowdSec repository unreachable. Skipping CrowdSec installation."
        return 0
    else
        log_info "Repository unreachable, retrying in 10 seconds... ($i/$RETRY_COUNT)"
        sleep 10
    fi
done

# Install CrowdSec and nftables bouncer
dnf install -y crowdsec crowdsec-firewall-bouncer-nftables

# Configure CrowdSec
systemctl enable --now crowdsec

# Wait for CrowdSec to fully initialize
log_info "Waiting for CrowdSec to initialize..."
sleep 30

# Check if CrowdSec is running
if systemctl is-active --quiet crowdsec; then
    log_success "CrowdSec service is running"
else
    log_warning "CrowdSec service may not be running properly"
    systemctl status crowdsec --no-pager
fi

# Configure the nftables bouncer
# The bouncer should auto-register during installation
if systemctl enable crowdsec-firewall-bouncer; then
    if systemctl start crowdsec-firewall-bouncer; then
        sleep 5
        if systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_success "CrowdSec nftables bouncer is running successfully"
            
            # Verify bouncer registration
            if command -v cscli &> /dev/null; then
                log_info "Checking bouncer registration:"
                cscli bouncers list 2>/dev/null || log_warning "Could not list bouncers"
            fi
        else
            log_warning "CrowdSec bouncer failed to start"
            log_info "Check bouncer logs with: journalctl -u crowdsec-firewall-bouncer -f"
            systemctl status crowdsec-firewall-bouncer --no-pager
        fi
    else
        log_warning "Failed to start CrowdSec bouncer service"
        systemctl status crowdsec-firewall-bouncer --no-pager
    fi
else
    log_warning "Failed to enable CrowdSec bouncer service"
fi

# Install and update collections if cscli is available
if command -v cscli &> /dev/null; then
    log_info "Installing CrowdSec security collections..."
    
    # Install common collections
    cscli collections install crowdsecurity/sshd 2>/dev/null || log_info "SSH collection may already be installed"
    cscli collections install crowdsecurity/linux 2>/dev/null || log_info "Linux collection may already be installed"
    
    # Update all collections
    cscli collections upgrade 2>/dev/null || true
    
    # Reload CrowdSec to apply new collections
    systemctl reload crowdsec 2>/dev/null || true
    
    log_success "CrowdSec collections installed and updated"
else
    log_warning "CrowdSec CLI (cscli) not available yet"
fi
