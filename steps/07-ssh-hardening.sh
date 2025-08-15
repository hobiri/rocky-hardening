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

# 7. SSH Hardening
log_info "Step 7: Hardening SSH configuration"
backup_file "/etc/ssh/sshd_config"

groupadd -g 9999 "$SSH_USERS_GROUP" 2>/dev/null || true
groupadd -g 9998 "$SFTP_USERS_GROUP" 2>/dev/null || true
usermod -aG "$SSH_USERS_GROUP" "$USER_NAME"

# Create login banner
cat > /etc/issue.net << 'EOF'
===============================================================
This system is for authorized use only.

All access is monitored and logged for security purposes.
Unauthorized access attempts are a violation of company policy
and applicable laws.

By continuing, you agree to comply with all security policies.
===============================================================
EOF
chmod 444 /etc/issue.net

# Generate SSH host keys if they do not exist
[[ -f /etc/ssh/ssh_host_ed25519_key ]] || ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
[[ -f /etc/ssh/ssh_host_rsa_key ]] || ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# Create SSH configuration in drop-in directory
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-hobiri-security.conf << EOF
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
ChrootDirectory /var/sftp/%u
ForceCommand internal-sftp
AllowTcpForwarding no
X11Forwarding no
PasswordAuthentication no

# Banner
Banner /etc/issue.net
EOF
chmod 600 /etc/ssh/sshd_config.d/10-hobiri-security.conf

# Test SSH configuration
if sshd -t; then
    systemctl restart sshd
    log_info "Testing SSH configuration..."
    
    if timeout 10 ssh -o ConnectTimeout=5 -o BatchMode=yes -p $SSH_PORT localhost exit 2>/dev/null; then
        log_success "SSH connectivity test passed"
    else
        log_warning "SSH connectivity test failed - manual verification required"
        echo "CRITICAL: Test SSH access before rebooting!"
        echo "Command: ssh -p $SSH_PORT $USER_NAME@\$(hostname -I | awk '{print \$1}')"
    fi
else
    log_error "SSH service restart failed"
    exit 1
fi
