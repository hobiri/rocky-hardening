#!/bin/bash
set -euo pipefail

if [[ ! -f "../config.sh" ]] || [[ ! -f "../helpers.sh" ]]; then
    echo "Error: Required files not found. Run from script directory."
    exit 1
fi

# Load config and helpers once
source ../config.sh
source ../helpers.sh

# 15. Create security monitoring scripts
log_info "Step 15: Creating security monitoring scripts"

# Create security compliance check script
cat > /usr/local/bin/security-compliance-check.sh << 'EOF'
#!/bin/bash
# Rocky Linux Security Compliance Check

REPORT_FILE="/var/log/security-compliance-$(date +%Y%m%d).log"

echo "Rocky Linux Security Compliance Report" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "========================================" >> $REPORT_FILE

# Check SELinux status
echo -e "\n[SELinux Status]" >> $REPORT_FILE
getenforce >> $REPORT_FILE

# Check firewall status
echo -e "\n[nftables Status]" >> $REPORT_FILE
systemctl is-active nftables >> $REPORT_FILE

# Check for system updates
echo -e "\n[Available Security Updates]" >> $REPORT_FILE
dnf check-update --security -q | grep -E "^[a-zA-Z0-9]" | wc -l >> $REPORT_FILE

# Check SSH configuration
echo -e "\n[SSH Configuration]" >> $REPORT_FILE
grep -E "^PermitRootLogin|^PasswordAuthentication|^Port" /etc/ssh/sshd_config.d/*.conf >> $REPORT_FILE 2>/dev/null

# Check for failed login attempts
echo -e "\n[Recent Failed Login Attempts]" >> $REPORT_FILE
grep "Failed password" /var/log/secure | tail -10 >> $REPORT_FILE

# Check listening services
echo -e "\n[Listening Services]" >> $REPORT_FILE
ss -tlnp | grep LISTEN >> $REPORT_FILE

echo "Report generated: $REPORT_FILE"
EOF

chmod +x /usr/local/bin/security-compliance-check.sh
log_success "Security monitoring scripts created"