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

# 6. Configure PAM security
log_info "Step 6: Configuring PAM security"

authselect current
authselect select sssd with-faillock with-pwhistory --force

cat >/etc/security/faillock.conf <<EOF
deny = 5
unlock_time = 900
audit
even_deny_root
EOF

cat >/etc/security/pwhistory.conf <<EOF
remember = 24
enforce_for_root
EOF

authselect apply-changes

log_success "Configured PAM security"