# config.sh - Configuration file for Rocky Linux hardening script

USER_NAME="admin"               # Default username
USER_GROUP=""                   # User group, will use username if empty
IPV6="0"                        # Set to "1" to enable IPv6
SSH_PORT="2222"                 # Default SSH port
SSH_USERS_GROUP="ssh-users"     # Group for SSH users
SFTP_USERS_GROUP="sftp-users"   # Group for SFTP users

# Logging
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/var/log/rocky-hardening-$TIMESTAMP.log"