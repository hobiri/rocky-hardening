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

# 9. CrowdSec Configuration
log_info "Step 9: Configuring CrowdSec"
backup_file "/etc/crowdsec/config.yaml"

# Function to check if CrowdSec is responsive
check_crowdsec_ready() {
    local timeout=30
    local count=0
    
    while [ $count -lt $timeout ]; do
        if cscli version &>/dev/null && systemctl is-active --quiet crowdsec; then
            log_info "CrowdSec is ready and responsive"
            
            return 0
        fi
        
        sleep 2
        ((count += 2))
    done
    
    log_error "CrowdSec failed to become ready within $timeout seconds"
    
    return 1
}

# Install CrowdSec repository
RETRY_COUNT=3
REPO_INSTALLED=false

for i in $(seq 1 $RETRY_COUNT); do
    if curl -s --max-time 10 https://packagecloud.io &>/dev/null; then
        curl -sSf "https://packagecloud.io/install/repositories/crowdsec/crowdsec/config_file.repo?os=rpm_any&dist=rpm_any&source=script" > "/etc/yum.repos.d/crowdsec_crowdsec.repo"
        REPO_INSTALLED=true
        break
    else
        log_info "Repository unreachable, retrying in 10 seconds... ($i/$RETRY_COUNT)"
        sleep 10
    fi
done

# Check if the repository was installed successfully
if [ "$REPO_INSTALLED" = false ]; then
    log_warning "CrowdSec repository unreachable. Skipping CrowdSec installation."
    exit 0
fi

# Install CrowdSec and nftables bouncer
dnf install -y crowdsec crowdsec-firewall-bouncer-nftables

# Configure CrowdSec
systemctl enable --now crowdsec

if ! systemctl start crowdsec; then
    log_error "Failed to start CrowdSec service"
    systemctl status crowdsec --no-pager
else
    check_crowdsec_ready
fi

# Be sure CrowdSec service starts after nftables
BOUNCER_OVERRIDE_DIR="/etc/systemd/system/crowdsec-firewall-bouncer.service.d"
mkdir -p "$BOUNCER_OVERRIDE_DIR"
SERVICE_FILE="$BOUNCER_OVERRIDE_DIR/override.conf"
cat << 'EOF' > "${BOUNCER_OVERRIDE_DIR}/override.conf"
[Unit]
After=nftables.service
Requires=nftables.service
EOF

systemctl daemon-reload
log_info "Applied systemd drop-in override for crowdsec-firewall-bouncer"

# Generate API key for nftables bouncer and configure it
BOUNCER_KEY=$(cscli bouncers add nftables-bouncer -o raw | tr -d '\n')
if [[ -z "$BOUNCER_KEY" ]]; then
    log_error "Failed to generate API key for nftables bouncer"
    exit 1
fi

BOUNCER_CONFIG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
if [[ -f "$BOUNCER_CONFIG" ]]; then
    backup_file "$BOUNCER_CONFIG"
fi

#sed -i "s#^api_key: .*|api_key: ${BOUNCER_KEY}|" "$BOUNCER_CONFIG"
awk -v key="$BOUNCER_KEY" '/^api_key:/ {$2=key} 1' "$BOUNCER_CONFIG" > "${BOUNCER_CONFIG}.tmp"
cat "${BOUNCER_CONFIG}.tmp" > "$BOUNCER_CONFIG"
rm "${BOUNCER_CONFIG}.tmp"

log_info "API key for nftables bouncer added to $BOUNCER_CONFIG"

systemctl enable --now crowdsec-firewall-bouncer
