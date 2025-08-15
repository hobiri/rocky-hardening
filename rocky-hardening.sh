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

VERSION="1.0.0"

# Load config and helpers once
source ./config.sh
source ./helpers.sh

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -n, --name NAME             Set custom user name (default: hobot)
    -g, --group GROUP           Set custom user group (default: same as user name)
    -p, --port PORT             Set custom SSH port (default: 2222)
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
        -p|--port)
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
    log_info "Starting Rocky Linux 9 hardening process..."
    log_info "Log file: $LOGFILE"

    check_root

    ./steps/01-system-update.sh
    ./steps/02-user-creation.sh
    ./steps/03-kernel-hardening.sh
    ./steps/04-system-limits.sh
    ./steps/05-password-policies.sh
    ./steps/06-pam-security.sh
    ./steps/07-ssh-hardening.sh
    ./steps/08-nft-firewall-configuration.sh
    ./steps/09-crowdsec.sh
    ./steps/10-selinux-enforcing.sh
    ./steps/11-system-auditing.sh
    ./steps/12-services-purge.sh
    ./steps/13-secure-time-sync.sh
    ./steps/14-filesystem-security.sh
    ./steps/15-security-monitoring.sh

    # Final system configuration
    log_info "Step 99: Final system configuration and cleanup"
    
    # Set secure umask for all users
    echo "umask 077" >> /etc/bashrc
    echo "umask 077" >> /etc/profile
    
    # Update system one more time
    dnf update -y
    
    # Generate final report
    log_info "Generating final security report..."
    /usr/local/bin/security-compliance-check.sh
    
    log_success "Rocky Linux 9 security hardening completed successfully!"
    
    USER_PASSWORD=$(grep "Password:" /root/user_credentials.txt | cut -d' ' -f2)

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
