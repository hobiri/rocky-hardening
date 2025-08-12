#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 5. Configure password policies
log_info "Step 5: Configuring password policies"

backup_file "/etc/security/pwquality.conf"

cat > /etc/security/pwquality.conf.d/90-hobiri-security.conf << 'EOF'
# Password quality requirements
minlen = 14
minclass = 4
maxrepeat = 2
maxclassrepeat = 2
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
EOF

backup_file "/etc/login.defs"

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs

log_success "Configured password policies"
