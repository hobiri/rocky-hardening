#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 6. Configure PAM security
log_info "Step 6: Configuring PAM security"

# Password history
if ! grep -q "pam_pwhistory" /etc/pam.d/system-auth; then
    sed -i '/^password.*requisite.*pam_pwquality.so/a password requisite pam_pwhistory.so remember=24 enforce_for_root' /etc/pam.d/system-auth
fi

# Account lockout
if ! grep -q "pam_faillock" /etc/pam.d/system-auth; then
    sed -i '/^auth.*sufficient.*pam_unix.so/i auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/system-auth
    sed -i '/^auth.*sufficient.*pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/system-auth
    sed -i '/^account.*required.*pam_unix.so/i account required pam_faillock.so' /etc/pam.d/system-auth
fi

log_success "Configured PAM security"