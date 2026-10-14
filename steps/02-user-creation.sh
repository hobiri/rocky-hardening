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

# Enforce the permissions/ownership/SELinux context required by sshd
# (StrictModes) for pubkey authentication.
# Critical when the home directory lives outside /home (e.g. /srv/<user>):
# the default SELinux policy does not label such .ssh directories as
# ssh_home_t, so sshd cannot read authorized_keys and login fails with
# "Permission denied (publickey)".
fix_ssh_home_security() {
    local home_dir="${1%/}"
    local ssh_dir="$home_dir/.ssh"

    [[ -d "$ssh_dir" ]] || return 0

    # Every ancestor above the home dir must be traversable by sshd,
    # otherwise StrictModes rejects the authorized_keys file
    local parent_dir
    parent_dir="$(dirname "$home_dir")"
    while [[ "$parent_dir" != "/" && -n "$parent_dir" ]]; do
        chmod 755 "$parent_dir" 2>/dev/null || true
        parent_dir="$(dirname "$parent_dir")"
    done

    chmod 700 "$home_dir"
    chmod 700 "$ssh_dir"
    if [[ -f "$ssh_dir/authorized_keys" ]]; then
        chmod 600 "$ssh_dir/authorized_keys"
    fi
    local owner_grp
    owner_grp="$(id -gn "$USER_NAME" 2>/dev/null || echo "$USER_GROUP")"
    chown -R "$USER_NAME:$owner_grp" "$home_dir"

    # Home outside /home: register a file-context rule so the .ssh tree is
    # labeled ssh_home_t, then relabel. semanage -a fails when the rule
    # already exists; ignore that so the script stays idempotent.
    if [[ "$home_dir" != /home/* ]]; then
        if command -v semanage >/dev/null 2>&1; then
            # Escape regex metacharacters (dots) in the home path
            local home_re="${home_dir//./\\.}"
            semanage fcontext -a -t ssh_home_t "${home_re}(/.*)?" 2>/dev/null || true
            restorecon -R -v "$ssh_dir" 2>/dev/null || true
            semanage fcontext -a -t ssh_home_t "${home_re}/\.ssh(/.*)?" 2>/dev/null || true
            restorecon -R -v "$ssh_dir" 2>/dev/null || true
        else
            log_warning "semanage not found: $ssh_dir may keep a wrong SELinux label"
        fi
    fi

    log_info "SSH directory security applied to $home_dir"
}

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

        log_success "Added SSH public key for $USER_NAME"
    else
        cp -r /root/.ssh "$user_home_dir/"

        log_info "Copied SSH keys from root to $USER_NAME"
    fi

    # Permissions/ownership + SELinux context (needed for homes outside /home)
    fix_ssh_home_security "$user_home_dir"

    passwd -l "$USER_NAME"

    log_success "Created user: $USER_NAME"
else
    log_warning "User $USER_NAME already exists"

    # Re-apply SSH directory security in case the home lives outside /home
    fix_ssh_home_security "$user_home_dir"
fi

# Add user to wheel group for sudo without password
usermod -aG wheel "$USER_NAME"

# Configure sudo without password for the user
echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USER_NAME}"
chmod 440 "/etc/sudoers.d/${USER_NAME}"

log_success "User added to sudoers with NOPASSWD"
