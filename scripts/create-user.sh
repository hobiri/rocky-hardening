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

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Validate required variables
if [[ -z "${SFTP_USERS_GROUP:-}" ]]; then
    error_exit "SFTP_USERS_GROUP not defined in config"
fi

# Check if SFTP_USERS_GROUP exists
if ! getent group "$SFTP_USERS_GROUP" >/dev/null; then
    error_exit "SFTP_USERS_GROUP '$SFTP_USERS_GROUP' does not exist"
fi

# Compute CRC32 hex (more portable approach)
BASE_NAME=$(dd if=/dev/urandom bs=1 count=20 2>/dev/null | LC_ALL=C tr -dc 'a-zA-Z0-9_-' | head -c 20)
if [[ -z "$BASE_NAME" ]]; then
    # Fallback method
    BASE_NAME=$(date +%s%N | sha256sum | cut -c1-20)
fi

HASH_HEX=$(printf '%s' "$BASE_NAME" | cksum | awk '{printf "%08x", $1}')
SFTP_DIR="/var/sftp/${HASH_HEX}"

# Enhanced password generation with better entropy
gen_pass() {
    local length=${1:-16}
    # Use /dev/urandom with openssl for better password generation
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-${length}
    else
        # Fallback to original method with improvements
        dd if=/dev/urandom bs=1 count=${length} 2>/dev/null | LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c ${length}
    fi
}

# Test password generation
if ! gen_pass 8 >/dev/null 2>&1; then
    error_exit "Password generation failed. Check system entropy."
fi

# Check for existing users and handle gracefully
check_user_exists() {
    local username="$1"
    if id "$username" &>/dev/null; then
        log_warning "User $username already exists"
        return 0
    fi
    return 1
}

# 1. Create user
log_info "1. Creating user account $HASH_HEX with home $SFTP_DIR"

# Check if group exists, create if not
if getent group "$HASH_HEX" >/dev/null; then
    log_info "Group $HASH_HEX already exists"
else
    if groupadd "$HASH_HEX"; then
        log_info "Created group $HASH_HEX"
    else
        error_exit "Failed to create group $HASH_HEX"
    fi
fi

if check_user_exists "$HASH_HEX"; then
    log_warning "Skipping user creation for $HASH_HEX"
else
    if ! useradd -g "$HASH_HEX" -G "$SFTP_USERS_GROUP" -m -d "$SFTP_DIR" -s /bin/false "$HASH_HEX"; then
        error_exit "Failed to create main user: $HASH_HEX"
    fi

    log_info "Successfully created user: $HASH_HEX"
fi

# Set password for main user
PASSW=$(gen_pass 20)
if ! echo "$HASH_HEX:$PASSW" | chpasswd; then
    error_exit "Failed to set password for user: $HASH_HEX"
fi

# 2. Prepare SFTP chroot directory with proper structure
log_info "2. Setting up SFTP chroot directory: $SFTP_DIR"
if ! mkdir -p "$SFTP_DIR/data" "$SFTP_DIR/logs"; then
    error_exit "Failed to create SFTP directory structure"
fi

# Set proper ownership and permissions for chroot
chown root:root "$SFTP_DIR"
chmod 755 "$SFTP_DIR"
# Set up data directory permissions
chown "$HASH_HEX:$HASH_HEX" "$SFTP_DIR/data"
chmod 755 "$SFTP_DIR/data"
# Set up logs directory
chown "$HASH_HEX:$HASH_HEX" "$SFTP_DIR/logs"
chmod 755 "$SFTP_DIR/logs"

log_info "SFTP directory structure created successfully"

echo "============================================"
echo " SFTP Access Credentials"
echo " User: $HASH_HEX"
echo " Password: $PASSW"
echo " Home Directory: $SFTP_DIR"
echo " Generated: $(date)"
echo "============================================"
echo ""
echo "SFTP CONNECTION INFO:"
echo "  Server: $(hostname -f 2>/dev/null || hostname)"
echo "  Port: 2222"
echo "  SFTP Root: $SFTP_DIR"
echo "  Data Directory: $SFTP_DIR/data"
echo "  Logs Directory: $SFTP_DIR/logs"
echo ""
echo "SECURITY NOTES:"
echo "  - Keep this file secure and private"
echo "  - SFTP users are chrooted to $SFTP_DIR"
echo "  - Only password authentication is enabled"
echo "  - Session limits are enforced"
echo "============================================"
echo ""
echo "Example SFTP connection:"
echo "  sftp ${HASH_HEX}@$(hostname)"
echo ""

# Clear passwords from memory
unset PASSW