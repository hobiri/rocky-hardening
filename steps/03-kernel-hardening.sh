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

# 3. Configure secure kernel parameters
log_info "Step 3: Setting secure kernel parameters"
backup_file "/etc/default/grub"

# Define security parameters as array for better processing
GRUB_SECURITY_PARAMS=(
    "audit=1"
    "kernel.kptr_restrict=2"
    "kernel.dmesg_restrict=1"
    "kernel.kexec_load_disabled=1"
    "kernel.yama.ptrace_scope=3"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
)
# Extract existing GRUB_CMDLINE_LINUX line
CURRENT_CMDLINE=$(grep ^GRUB_CMDLINE_LINUX= /etc/default/grub | cut -d'"' -f2)
# Ensure all security parameters are present
UPDATED_CMDLINE="$CURRENT_CMDLINE"

for param in "${GRUB_SECURITY_PARAMS[@]}"; do
    if [[ "$UPDATED_CMDLINE" != *"$param"* ]]; then
        UPDATED_CMDLINE="$UPDATED_CMDLINE $param"
    fi
done

# Remove leading/trailing spaces
UPDATED_CMDLINE=$(echo "$UPDATED_CMDLINE" | xargs)

# Update the GRUB_CMDLINE_LINUX line if changes are needed
if [[ "$CURRENT_CMDLINE" != "$UPDATED_CMDLINE" ]]; then
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$UPDATED_CMDLINE\"|" /etc/default/grub
    log_info "Updated GRUB_CMDLINE_LINUX with secure kernel parameters."
else
    log_info "GRUB_CMDLINE_LINUX already contains all required security parameters."
fi

# Check grub2-mkconfig availability
if ! command -v grub2-mkconfig &>/dev/null; then
    log_error "grub2-mkconfig not found. Cannot update GRUB configuration."
fi

# Rebuild GRUB configuration safely (BIOS & EFI compatible)
if grub2-mkconfig -o /boot/grub2/grub.cfg; then
    log_success "GRUB configuration rebuilt successfully."
else
    log_error "Failed to rebuild GRUB configuration."
    
    # Rollback grub file if backup exists
    if [[ -f "/etc/default/grub.backup.$TIMESTAMP" ]]; then
        log_warning "Restoring original GRUB configuration from backup."
        cp "/etc/default/grub.backup.$TIMESTAMP" /etc/default/grub
    fi
fi

# EFI Detection Log (Informational)
if [[ -d /boot/efi/EFI ]]; then
    log_warning "EFI system detected. Ensure secure boot policies do not conflict with these kernel parameters."
fi