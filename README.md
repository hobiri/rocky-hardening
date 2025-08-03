# Hobiri Security Hardening Script - Rocky Linux 9 edition

This script provides comprehensive security hardening for Rocky Linux 9 servers based on industry best practices and security guidelines.

## Features

### 🔒 Core Security Hardening
- **System Updates**: Automatic security updates configuration
- **Kernel Security**: Secure boot parameters and kernel hardening
- **User Management**: Secure user creation with strong password policies
- **SSH Hardening**: Comprehensive SSH security configuration
- **Firewall**: nftables-based firewall with service-specific rules
- **SELinux**: Enforcing mode with security-focused boolean settings
- **System Auditing**: Comprehensive audit trail configuration

### 🛡️ Advanced Security Features
- **CrowdSec Integration**: Modern intrusion prevention system
- **Password Policies**: Strong password requirements and aging
- **PAM Security**: Account lockout and password history
- **File System Security**: Secure permissions and mount options
- **Network Security**: IP spoofing protection and attack mitigation
- **Service Hardening**: Disable unnecessary services and protocols

### 📊 Monitoring & Compliance
- **Security Monitoring**: Automated compliance checking
- **Audit Logging**: Comprehensive system activity logging
- **Incident Response**: Evidence collection toolkit
- **Reporting**: Regular security status reports

## Quick Start

### Prerequisites
- Rocky Linux 9 server with root access
- Internet connection for package installation
- Basic understanding of Linux system administration

### Installation

1. **Download the script:**
```bash
wget https://raw.githubusercontent.com/hobiri/rocky-hardening/main/rocky-hardening.sh
chmod +x rocky-hardening.sh
```

2. **Run with default settings:**
```bash
sudo ./rocky-hardening.sh
```

3. **Run with custom user:**
```bash
sudo ./rocky-hardening.sh -u myuser -g mygroup
```

## Configuration Options

### Command Line Arguments

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --name` | Custom name for new user | `admin` |
| `-g, --group` | Custom group for new user | Same as username |
| `-p, --port` | SSH port | 2222 |
| `-i, --ipv6` | Enable IPv6 (default disabled) | - |
| `-h, --help` | Show help message | - |

### Default Configuration

- **SSH Port**: 2222 (configurable in script)
- **SSH Groups**: 
  - `ssh-users` (full SSH access)
  - `sftp-users` (SFTP-only access)
- **Firewall**: nftables with HTTP(80), HTTPS(443), SSH(2222)
- **Security Updates**: Automatic installation enabled

## What the Script Does

### 1. System Updates & Base Configuration
- Updates all system packages
- Configures automatic security updates
- Sets up DNF automatic with security-only updates

### 2. User Management
- Creates new unprivileged user with sudo access
- Generates secure random password
- Adds user to appropriate groups
- Configures passwordless sudo access

### 3. Kernel Hardening
- Enables audit subsystem
- Restricts kernel pointer access
- Disables kexec and unprivileged BPF
- Enables ASLR and other memory protections

### 4. Network Security
- Configures IP spoofing protection
- Disables IPv6 (if not needed)
- Enables SYN cookies and TCP hardening
- Sets up secure sysctl parameters

### 5. SSH Security
- Changes SSH port to 2222
- Disables root login and password authentication
- Configures secure ciphers and key exchange
- Sets up user group restrictions
- Implements SFTP chroot for SFTP-only users

### 6. Firewall Configuration
- Replaces firewalld with nftables
- Implements default-deny policy
- Allows only necessary services
- Rate limits SSH connections
- Logs dropped packets (optional)

### 7. CrowdSec Integration (Replaces fail2ban)
- Installs CrowdSec intrusion prevention
- Configures nftables bouncer

### 8. SELinux Hardening
- Enforces SELinux in enforcing mode
- Disables dangerous booleans
- Configures SSH port in SELinux context

### 9. System Auditing
- Configures comprehensive audit rules
- Monitors critical file changes
- Tracks user activities and system calls
- Logs security-relevant events

## Post-Installation Steps

### 1. Verify SSH Access
**CRITICAL**: Test SSH connectivity before rebooting!

```bash
# From another terminal/machine
ssh -p 2222 username@server-ip
```

### 2. Add Users to SSH Groups
```bash
# For full SSH access
sudo usermod -aG ssh-users username

# For SFTP-only access
sudo usermod -aG sftp-users username
```

### 3. Configure SSH Keys
```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "user@domain.com"

# Copy public key to server
ssh-copy-id -p 2222 username@server-ip
```

### 4. System Reboot
```bash
sudo reboot
```

## File Locations

### Configuration Files
- **User credentials**: `/root/user_credentials.txt`
- **SSH config**: `/etc/ssh/sshd_config.d/50-hobiri-security.conf`
- **nftables rules**: `/etc/nftables/main.nft`
- **Security limits**: `/etc/security/limits.d/50-{username}.conf`
- **Sysctl security**: `/etc/sysctl.d/50-hobiri-security.conf`
- **Audit rules**: `/etc/audit/rules.d/security.rules`

### Log Files
- **Hardening log**: `/var/log/rocky-hardening-YYYYMMDD_HHMMSS.log`
- **Security compliance**: `/var/log/security-compliance-YYYYMMDD.log`
- **SSH logs**: `/var/log/secure`
- **Audit logs**: `/var/log/audit/audit.log`

### Scripts
- **Compliance check**: `/usr/local/bin/security-compliance-check.sh`

## Security Features Detail

### Password Policy
- Minimum length: 14 characters
- Requires 4 character classes
- Maximum repeat: 2 characters
- Password history: 24 passwords
- Password aging: 90 days max, 7 days min

### SSH Security
- **Port**: 2222 (non-standard)
- **Authentication**: Key-based only
- **Root access**: Disabled
- **Group restrictions**: ssh-users and sftp-users only
- **Rate limiting**: 3 attempts per minute
- **Encryption**: Modern ciphers only

### Firewall Rules
```bash
# View current nftables rules
sudo nft list ruleset

# Check rule statistics
sudo nft list table inet filter -a
```

### CrowdSec Management
```bash
# Check CrowdSec status
sudo systemctl status crowdsec

# View active decisions
sudo cscli decisions list

# Check bouncer status
sudo systemctl status crowdsec-firewall-bouncer
```

## Monitoring & Maintenance

### Daily Checks
- Review authentication logs: `sudo journalctl -u sshd -f`
- Check CrowdSec decisions: `sudo cscli metrics`
- Monitor system resources: `htop` or `top`

### Weekly Tasks
- Run compliance check: `sudo /usr/local/bin/security-compliance-check.sh`
- Review audit logs: `sudo aureport --summary`
- Check for updates: `sudo dnf check-update --security`

### Monthly Tasks
- Review user accounts and permissions
- Audit sudo usage: `sudo grep sudo /var/log/secure`
- Check file integrity: `sudo rpm -Va`

## Troubleshooting

### SSH Connection Issues
1. **Cannot connect on port 2222**:
   ```bash
   # Check if SSH is running
   sudo systemctl status sshd
   
   # Check firewall rules
   sudo nft list table inet filter
   
   # Check SELinux context
   sudo semanage port -l | grep ssh
   ```

2. **Permission denied**:
   ```bash
   # Check user groups
   groups username
   
   # Check SSH configuration
   sudo sshd -T | grep -i allowgroups
   ```

### Firewall Issues
1. **Service not accessible**:
   ```bash
   # Check nftables status
   sudo systemctl status nftables
   
   # View rules
   sudo nft list ruleset
   
   # Test rule syntax
   sudo nft -c -f /etc/nftables/main.nft
   ```

2. **CrowdSec bouncer not working**:
   ```bash
   # Check bouncer logs
   sudo journalctl -u crowdsec-firewall-bouncer
   
   # Verify API key
   sudo cscli bouncers list
   ```

### SELinux Issues
1. **SELinux denials**:
   ```bash
   # Check for denials
   sudo ausearch -m avc -ts recent
   
   # Generate policy
   sudo audit2allow -a
   
   # Check SELinux status
   sudo sestatus
   ```

## Security Considerations

### ⚠️ Important Warnings
- **Always test SSH access** before rebooting
- **Keep backup access method** available (console/IPMI)
- **Document all changes** for compliance
- **Test restore procedures** regularly

### 🔍 Security Notes
- Script creates backups of modified files with timestamps
- All actions are logged to `/var/log/rocky-hardening-*.log`
- Generated passwords are stored in `/root/user_credentials.txt`
- Some changes require system reboot to take effect

### 📋 Compliance
This hardening script addresses requirements from:
- CIS (Center for Internet Security) benchmarks
- NIST Cybersecurity Framework
- STIG (Security Technical Implementation Guide) recommendations
- Common security best practices

## Customization

### Adding Custom nftables Rules
Edit `/etc/nftables/main.nft` after script execution:
```bash
# Add custom rules before the log/drop section
tcp dport 8080 accept  # Example: Allow port 8080
```

### Custom Security Limits
Add to `/etc/security/limits.d/50-{username}.conf`:
```bash
# Example: Limit max processes for specific user
myuser hard nproc 500
```

## Support & Contributing

### Getting Help
- Check the troubleshooting section above
- Review log files for error messages
- Ensure all prerequisites are met

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Reporting Issues
- Include system information (`uname -a`, `cat /etc/os-release`)
- Provide relevant log file excerpts
- Describe expected vs actual behavior
- Include steps to reproduce

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### Version 1.0
- Initial release
- Core hardening features
- nftables firewall
- CrowdSec integration
- Comprehensive SSH hardening
- SELinux enforcement
- System auditing

---

**Remember**: Security is an ongoing process. Regularly review and update your security configuration based on new threats and organizational requirements.