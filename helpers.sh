# helpers.sh - Helper functions for script logging and file management

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOGFILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOGFILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOGFILE"
    exit 1
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOGFILE"
}

backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$TIMESTAMP"
        log_info "Backed up $file"
    fi
}

rollback_changes() {
    local step=$1
    log_warning "Rolling back changes for step: $step"
    
    case $step in
        "ssh")
            if [[ -f "/etc/ssh/sshd_config.backup.$TIMESTAMP" ]]; then
                cp "/etc/ssh/sshd_config.backup.$TIMESTAMP" /etc/ssh/sshd_config
                systemctl restart sshd
                log_info "SSH configuration rolled back"
            fi
            ;;
        "firewall")
            systemctl enable --now firewalld 2>/dev/null || true
            systemctl disable --now nftables 2>/dev/null || true
            log_info "Firewall configuration rolled back"
            ;;
    esac
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