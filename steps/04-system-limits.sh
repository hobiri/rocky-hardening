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

# 4. Configure system security limits
log_info "Step 4: Configuring system security limits"

cat > /etc/security/limits.d/90-hobiri-security.conf << 'EOF'
# Prevent fork bombs
* hard nproc 1000
root hard nproc unlimited

# Limit core dumps
* hard core 0
root hard core unlimited

# Maximum locked memory (64KB)
* soft memlock 65536
* hard memlock 65536

# Maximum file size (1GB)
* hard fsize 1000000

# Maximum number of open files
* soft nofile 4096
* hard nofile 65536
root soft nofile 4096
root hard nofile 65536
EOF

cat > /etc/sysctl.d/90-hobiri-security.conf << EOF
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
EOF

# Handle IPv6 disabling based on config.sh
if [[ "${IPV6:-0}" == "0" ]]; then
    echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.d/90-hobiri-security.conf
    echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.d/90-hobiri-security.conf
else
    echo 'net.ipv6.conf.all.disable_ipv6 = 0' >> /etc/sysctl.d/90-hobiri-security.conf
    echo 'net.ipv6.conf.default.disable_ipv6 = 0' >> /etc/sysctl.d/90-hobiri-security.conf
fi

# Additional security parameters
cat >> /etc/sysctl.d/90-hobiri-security.conf << 'EOF'
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

sysctl -p /etc/sysctl.d/90-hobiri-security.conf

log_success "Configured system security limits"