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

# 10. Configure auditd
log_info "Step 10: Configuring system auditing"

dnf install -y audit

# On RHEL/Rocky 10 the rules directory (and auditctl/augenrules) moved from the
# 'audit' package to the 'audit-rules' subpackage, so installing 'audit' alone
# leaves /etc/audit/rules.d missing. Make sure it exists on every release.
if [[ ! -d /etc/audit/rules.d ]]; then
    dnf install -y audit-rules 2>/dev/null || log_warning "audit-rules package not available"

    mkdir -p /etc/audit/rules.d
fi

# Configure audit rules
{
cat << 'EOF'
# Delete existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/gshadow -p wa -k gshadow_changes

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor network changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
EOF

# Monitor login/logout events. Watch rules must target existing files:
# auditctl/augenrules fail on missing paths and /var/log/faillog and
# /var/log/lastlog are not present on every release.
for logfile in /var/log/faillog /var/log/lastlog; do
    if [[ -e "$logfile" ]]; then
        echo "-w $logfile -p wa -k logins"
    fi
done

cat << 'EOF'

# Monitor file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make configuration immutable
-e 2
EOF
} > /etc/audit/rules.d/security.rules

systemctl enable --now auditd
log_success "System auditing configured"