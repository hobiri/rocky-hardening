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
log_info "Step 9: Installing CrowdSec"
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
