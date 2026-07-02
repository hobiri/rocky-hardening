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

# 2. Create new unprivileged user
log_info "Step 2: Creating new user '$USER_NAME'"

# Create group if it doesn't exist
if ! getent group "$USER_GROUP" > /dev/null 2>&1; then
    groupadd "$USER_GROUP"

    log_info "Created group: $USER_GROUP"
fi

user_home_dir="${USER_HOME:-/home/$USER_NAME}"

# Create user
if ! id "$USER_NAME" &>/dev/null; then
    useradd -m -g "$USER_GROUP" -d "$user_home_dir" -s /bin/bash "$USER_NAME"

    if [[ -n "${USER_PUB_KEY:-}" ]]; then
        user_ssh_dir="$user_home_dir/.ssh"

        mkdir -p "$user_ssh_dir"
        
        echo "$USER_PUB_KEY" > "$user_ssh_dir/authorized_keys"
        
        chmod 700 "$user_ssh_dir"
        chmod 600 "$user_ssh_dir/authorized_keys"
        chown -R "$USER_NAME:$USER_GROUP" "$user_ssh_dir"
        
        log_success "Added SSH public key for $USER_NAME"
    else
        cp -r /root/.ssh "$user_home_dir/"
        chown -R "$USER_NAME:$USER_GROUP" "$user_home_dir/.ssh"

        log_info "Copied SSH keys from root to $USER_NAME"
    fi

    passwd -l "$USER_NAME"
 
    log_success "Created user: $USER_NAME"
else
    log_warning "User $USER_NAME already exists"
fi

# Add user to wheel group for sudo without password
usermod -aG wheel "$USER_NAME"

# Configure sudo without password for the user
echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USER_NAME}"
chmod 440 "/etc/sudoers.d/${USER_NAME}"

log_success "User added to sudoers with NOPASSWD"
