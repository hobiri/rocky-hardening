#!/bin/bash

#########################################################################
# Hobiri Security Hardening Script
# Based on https://krython.com/post/rocky-linux-security-checklist/
# 
# Additional Features:
# - Creates customizable unprivileged user with sudo access
# - Uses *.d configuration files where possible
# - SSH on port 2222 with ssh-users and sftp-users groups
# - nftables instead of firewalld
# - CrowdSec with nftables bouncer instead of fail2ban
#########################################################################

set -euo pipefail

# Configuration Variables
USER_NAME="hobot"
USER_GROUP=""  # Will use username if empty
IPV6="0"  # Set to "1" to enable IPv6
SSH_PORT="2222"
SSH_USERS_GROUP="ssh-users"
SFTP_USERS_GROUP="sftp-users"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOGFILE="/var/log/rocky-hardening-$(date +%Y%m%d_%H%M%S).log"

# Helper functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOGFILE"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOGFILE"
}

backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backed up $file"
    fi
}

generate_random_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-20
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -n, --name NAME.            Set custom user name (default: hobot)
    -g, --group GROUP           Set custom user group (default: same as user name)
    -p, --ssh-port PORT         Set custom SSH port (default: 2222)
    -i, --ipv6                  Enable IPv6 support (default: disabled)
    -h, --help                  Show this help message

Examples:
    $0                          # Use default settings
    $0 -n myuser -g mygroup     # Custom user and group
    
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            USER_NAME="$2"
            shift 2
            ;;
        -g|--group)
            USER_GROUP="$2"
            shift 2
            ;;
        -p|--ssh-port)
            SSH_PORT="$2"
            if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
                log_error "Invalid SSH port: $SSH_PORT. Must be between 1 and 65535."
                exit 1
            fi
            shift 2
            ;;
        -i|--ipv6)
            IPV6="1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set default group to username if not specified
if [[ -z "$USER_GROUP" ]]; then
    USER_GROUP="$USER_NAME"
fi

main() {
  # Get user input for customization
  echo
  info "Starting Rocky Linux 9 hardening process..."
  info "Log file: $LOGFILE"

  check_root

    # 1. System Update
    log_info "Step 1: Updating system packages"
    dnf update -y
    dnf install -y dnf-automatic epel-release
    
    # Configure automatic security updates
    backup_file "/etc/dnf/automatic.conf"
    sed -i 's/^upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf
    sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer
    log_success "System updated and automatic security updates configured"

    log "System updated and automatic security updates configured"

    # 2. Create new unprivileged user
    log_info "Step 2: Creating new user '$USER_NAME'"
    
    # Create group if it doesn't exist
    if ! getent group "$USER_GROUP" > /dev/null 2>&1; then
        groupadd "$USER_GROUP"
        log_info "Created group: $USER_GROUP"
    fi
    
    # Generate random password
    USER_PASSWORD=$(generate_random_password)
    
    # Create user
    if ! id "$USER_NAME" &>/dev/null; then
        useradd -m -g "$USER_GROUP" -s /bin/bash "$USER_NAME"
        echo "$USER_NAME:$USER_PASSWORD" | chpasswd
        log_success "Created user: $USER_NAME"
        log_success "Generated password: $USER_PASSWORD"
        echo "User: $USER_NAME" >> /root/user_credentials.txt
        echo "Password: $USER_PASSWORD" >> /root/user_credentials.txt
        chmod 600 /root/user_credentials.txt
    else
        log_warning "User $USER_NAME already exists"
    fi
    
    # Add user to wheel group for sudo without password
    usermod -aG wheel "$USER_NAME"
    
    # Configure sudo without password for the user
    echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/50-${USER_NAME}"
    chmod 440 "/etc/sudoers.d/50-${USER_NAME}"
    log_success "User added to sudoers with NOPASSWD"

    # 3. Configure secure kernel parameters
    log_info "Step 3: Setting secure kernel parameters"
    backup_file "/etc/default/grub"
    
    # Update GRUB with security parameters
    GRUB_SECURITY_PARAMS="audit=1 kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.kexec_load_disabled=1 kernel.yama.ptrace_scope=3 kernel.unprivileged_bpf_disabled=1 net.core.bpf_jit_harden=2"
    
    if ! grep -q "audit=1" /etc/default/grub; then
        sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"$GRUB_SECURITY_PARAMS /" /etc/default/grub
        
        # Rebuild GRUB configuration
        if [[ -d /boot/efi/EFI/rocky ]]; then
            grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg
        else
            grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
        log_success "Updated GRUB with security parameters"
    fi
    
    # 4. Configure system security limits
    log_info "Step 4: Configuring system security limits"
    cat > /etc/security/limits.d/50-hobiri-security.conf << 'EOF'
# Security limits configuration
* hard nproc 1000
* hard core 0
* hard memlock 64
* hard fsize 1000000
root hard nproc unlimited
EOF
    log_success "Configured system security limits"
    
    # 5. Configure sysctl security parameters
    log_info "Step 5: Configuring sysctl security parameters"
    cat > /etc/sysctl.d/50-hobiri-security.conf << 'EOF'
# Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel Security
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1

# System Limits
fs.file-max = 65535
kernel.pid_max = 65535
EOF
    
    sysctl -p /etc/sysctl.d/50-hobiri-security.conf
    log_success "Applied sysctl security parameters"
    
    # 6. Configure password policies
    log_info "Step 6: Configuring password policies"
    backup_file "/etc/security/pwquality.conf"
    cat > /etc/security/pwquality.d/50-hobiri-security.conf << 'EOF'
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
    
    # 7. Configure PAM security
    log_info "Step 7: Configuring PAM security"
    
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
    
    # 8. SSH Hardening
    log_info "Step 8: Hardening SSH configuration"
    backup_file "/etc/ssh/sshd_config"
    
    groupadd "$SSH_USERS_GROUP" 2>/dev/null || true
    groupadd "$SFTP_USERS_GROUP" 2>/dev/null || true
    usermod -aG "$SSH_USERS_GROUP" "$DEFAULT_USERNAME"

    # Create SSH configuration in drop-in directory
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/50-hobiri-security.conf << EOF
# Network and Protocol
Port $SSH_PORT
Protocol 2
AddressFamily inet
ListenAddress 0.0.0.0

# Host Keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 10
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

# User Access
AllowGroups $SSH_USERS_GROUP $SFTP_USERS_GROUP
DenyUsers root

# Security Features
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
PermitUserEnvironment no
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
MaxStartups 10:30:100
PermitTunnel no

# Crypto Settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# SFTP Configuration for SFTP-only users
Match Group $SFTP_USERS_GROUP
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication no

# Banner
Banner /etc/issue.net
EOF
    
    # Create login banner
    cat > /etc/issue.net << 'EOF'
============================================================
This system is for authorized use only.

All access is monitored and logged for security purposes.
Unauthorized access attempts are a violation of company policy
and applicable laws.

By continuing, you agree to comply with all security policies.
============================================================
EOF
    
    chmod 600 /etc/ssh/sshd_config.d/50-hobiri-security.conf
    chmod 644 /etc/issue.net
    
    # Test SSH configuration
    if sshd -t; then
        systemctl restart sshd
        log_success "SSH hardening completed successfully"
    else
        log_error "SSH configuration test failed"
        exit 1
    fi
    
    # 9. Configure nftables firewall
    log_info "Step 9: Configuring nftables firewall"
    
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
    
    # Set proper permissions and enable nftables
    chmod 755 /etc/nftables/main.nft
    systemctl enable --now nftables
    log_success "nftables firewall configured and enabled"
    
    # 10. Install and configure CrowdSec
    log_info "Step 10: Installing and configuring CrowdSec"
    
    # Install CrowdSec repository
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash
    
    # Install CrowdSec and nftables bouncer
    dnf install -y crowdsec crowdsec-firewall-bouncer-nftables
    
    # Configure CrowdSec
    systemctl enable --now crowdsec
    
    # Configure nftables bouncer
    if command -v cscli &> /dev/null; then
        # Get bouncer API key
        BOUNCER_KEY=$(cscli bouncers add nftables-bouncer -o raw 2>/dev/null || echo "")
        
        if [[ -n "$BOUNCER_KEY" ]]; then
            # Configure bouncer
            sed -i "s/api_key:.*/api_key: $BOUNCER_KEY/" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
            systemctl enable --now crowdsec-firewall-bouncer
            log_success "CrowdSec and nftables bouncer configured"
        else
            log_warning "Could not configure CrowdSec bouncer automatically"
        fi
    fi
    
    # 11. SELinux Configuration
    log_info "Step 11: Configuring SELinux"
    
    # Ensure SELinux is enforcing
    setenforce 1
    sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    
    # Install SELinux tools
    dnf install -y setools-console policycoreutils-python-utils setroubleshoot-server
    
    # Set secure SELinux booleans
    setsebool -P deny_execmem on
    setsebool -P secure_mode_insmod on
    setsebool -P ssh_sysadm_login off
    
    # Configure SSH port in SELinux
    semanage port -a -t ssh_port_t -p tcp $SSH_PORT 2>/dev/null || \
    semanage port -m -t ssh_port_t -p tcp $SSH_PORT
    
    log_success "SELinux configured and enforcing"
    
    # 12. Configure auditd
    log_info "Step 12: Configuring system auditing"
    
    dnf install -y audit
    
    # Configure audit rules
    cat > /etc/audit/rules.d/security.rules << 'EOF'
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

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

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
    
    systemctl enable --now auditd
    log_success "System auditing configured"
    
    # 13. Disable unnecessary services
    log_info "Step 13: Disabling unnecessary services"
    
    SERVICES_TO_DISABLE="avahi-daemon cups bluetooth kdump"
    for service in $SERVICES_TO_DISABLE; do
        systemctl disable --now "$service" 2>/dev/null || true
    done
    
    # Disable unnecessary network protocols
    cat > /etc/modprobe.d/disable-protocols.conf << 'EOF'
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    
    log_success "Disabled unnecessary services and protocols"
    
    # 14. Configure secure time synchronization
    log_info "Step 14: Configuring secure time synchronization"
    
    dnf install -y chrony
    
    backup_file "/etc/chrony.conf"
    cat > /etc/chrony.conf << 'EOF'
# Use Rocky Linux NTP servers
server 0.rocky.pool.ntp.org iburst
server 1.rocky.pool.ntp.org iburst
server 2.rocky.pool.ntp.org iburst
server 3.rocky.pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization
rtcsync

# Specify directory for log files
logdir /var/log/chrony

# Select which information is logged
log measurements statistics tracking

# Deny all clients by default
deny all

# Allow only localhost
allow 127.0.0.1
allow ::1
EOF
    
    systemctl enable --now chronyd
    log_success "Secure time synchronization configured"
    
    # 15. File system security
    log_info "Step 15: Securing file system permissions"
    
    # Find and fix world-writable files (limit to avoid long execution)
    find /usr /etc /bin /sbin -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null | head -100
    
    # Remove unnecessary SUID/SGID bits
    chmod u-s /usr/bin/at 2>/dev/null || true
    chmod u-s /usr/bin/lppasswd 2>/dev/null || true
    chmod u-s /usr/bin/newgrp 2>/dev/null || true
    chmod g-s /usr/bin/wall 2>/dev/null || true
    
    log_success "File system permissions secured"
    
    # 16. Create security monitoring scripts
    log_info "Step 16: Creating security monitoring scripts"
    
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
    
    # 17. Final system configuration
    log_info "Step 17: Final system configuration and cleanup"
    
    # Set secure umask for all users
    echo "umask 077" >> /etc/bashrc
    echo "umask 077" >> /etc/profile
    
    # Update system one more time
    dnf update -y
    
    # Generate final report
    log_info "Generating final security report..."
    /usr/local/bin/security-compliance-check.sh
    
    log_success "Rocky Linux 9 security hardening completed successfully!"
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}    HARDENING COMPLETED SUCCESSFULLY   ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${YELLOW}Important Information:${NC}"
    echo -e "• User created: ${BLUE}$USER_NAME${NC}"
    echo -e "• User password: ${BLUE}$USER_PASSWORD${NC}"
    echo -e "• SSH port changed to: ${BLUE}$SSH_PORT${NC}"
    echo -e "• SSH access group: ${BLUE}$SSH_USERS_GROUP${NC}"
    echo -e "• SFTP access group: ${BLUE}$SFTP_USERS_GROUP${NC}"
    echo -e "• Credentials saved to: ${BLUE}/root/user_credentials.txt${NC}"
    echo -e "• Log file: ${BLUE}$LOGFILE${NC}"
    echo
    echo -e "${RED}IMPORTANT:${NC} System will require reboot to apply all kernel security parameters."
    echo -e "${RED}WARNING:${NC} Make sure to test SSH connectivity on port $SSH_PORT before rebooting!"
    echo
    echo -e "To connect via SSH: ${BLUE}ssh -p $SSH_PORT $USER_NAME@$(hostname -I | awk '{print $1}')${NC}"
    echo
}

# Trap to ensure cleanup on script exit
trap 'log_error "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"
