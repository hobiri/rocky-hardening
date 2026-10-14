#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "${SCRIPT_DIR}/config.sh" ]] || [[ ! -f "${SCRIPT_DIR}/helpers.sh" ]]; then
    echo "Error: Required files not found. Run from the repository directory."
    exit 1
fi

# Load config and helpers once
source "${SCRIPT_DIR}/config.sh"
source "${SCRIPT_DIR}/helpers.sh"

# Extra: Rocky Linux 10 SIG Core Infra repository
log_info "Extra: Adding Rocky Linux 10 SIG Core Infra repository"

check_root

REPO_ID="rocky-core-infra"
REPO_FILE="/etc/yum.repos.d/${REPO_ID}.repo"
REPO_ARCH="$(uname -m)"
GPG_KEY_URL="https://download.rockylinux.org/pub/sig/10/core/${REPO_ARCH}/core-infra/RPM-GPG-KEY-Rocky-SIG-Core"

mkdir -p /etc/yum.repos.d

# Back up an existing definition before overwriting it
backup_file "$REPO_FILE"

# $basearch is expanded by dnf, so it must not be expanded by the shell
cat > "$REPO_FILE" << 'EOF'
[rocky-core-infra]
name=Rocky Linux 10 - SIG Core Infra
baseurl=https://download.rockylinux.org/pub/sig/10/core/$basearch/core-infra/
enabled=1
gpgcheck=1
gpgkey=https://download.rockylinux.org/pub/sig/10/core/$basearch/core-infra/RPM-GPG-KEY-Rocky-SIG-Core
EOF
chmod 644 "$REPO_FILE"

# Import the SIG Core GPG key so signature checks do not prompt on first use
if rpm --import "$GPG_KEY_URL"; then
    log_success "Imported GPG key from $GPG_KEY_URL"
else
    log_warning "Could not import GPG key from $GPG_KEY_URL (dnf will fetch it on first use)"
fi

# Refresh metadata so the new repository is usable immediately
dnf clean all
dnf -y makecache --disablerepo='*' --enablerepo="$REPO_ID"
