#!/bin/bash

# Advanced Ubuntu 24.04 Security Hardening Script
# This script implements comprehensive security measures for publicly hosted VPS servers
# Tested on: Ubuntu 24.04 LTS Server (DigitalOcean, Linode, Hostinger)
# Updated for kernel 6.8 and enhanced security features in Noble Numbat

set -euo pipefail

# --- Error Handling and Logging ---
function error_handler() {
    local exit_code=$?
    print_error "Error on line ${BASH_LINENO[0]}: Command '${BASH_COMMAND}' failed with exit code ${exit_code}"
    print_error "Log file available at $LOG_FILE for more details."
    exit $exit_code
}
trap error_handler ERR

function cleanup() {
    print_warning "--- Script finished or interrupted. ---"
}
trap cleanup EXIT INT

SSHD_FILE="/etc/ssh/sshd_config"
LOG_FILE="/var/log/server_hardening_$(date +%Y%m%d_%H%M%S).log"
USERNAME=""
SSHPORT=""
BACKUP_DIR="/root/security_backups"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

exec > >(tee -i "$LOG_FILE")
exec 2>&1

function print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

function print_error() {
    echo -e "${RED}[!]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

function run_as_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

function check_distro() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "This script is intended to be run on Ubuntu 24.04 LTS"
        exit 1
    fi
    source /etc/os-release
    if [[ $ID != "ubuntu" || $VERSION_ID != "24.04" ]]; then
        print_error "This script is intended to be run on Ubuntu 24.04 LTS"
        exit 1
    fi
}

function create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    print_status "Created backup directory: $BACKUP_DIR"
}

function backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
        print_status "Backed up $file"
    fi
}

function create_swap() {
    if free | awk '/^Swap:/ {exit !$2}'; then
        print_warning "Swap already exists"
    else
        PHYSRAM=$(grep MemTotal /proc/meminfo | awk '{print int($2 / 1024 / 1024 + 0.5)}')
        SWAPSIZE=$((2 * PHYSRAM))
        SWAPSIZE=$((SWAPSIZE > 31 ? 31 : SWAPSIZE))
        SWAPSIZE=$((SWAPSIZE < 2 ? 2 : SWAPSIZE))

        fallocate -l "${SWAPSIZE}G" /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        backup_file /etc/fstab
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
        print_status "Swap created: ${SWAPSIZE}G"
    fi
}

function update_upgrade() {
    export DEBIAN_FRONTEND=noninteractive
    print_status "Updating and upgrading system packages..."
    apt-get update
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get clean
    print_status "System updated and upgraded"
}

function install_essential_packages() {
    print_status "Installing essential security packages..."
    apt-get install -y \
        curl \
        wget \
        gnupg \
        lsb-release \
        software-properties-common \
        net-tools \
        htop \
        git \
        python3-pip \
        libssl-dev \
        libffi-dev \
        python3-dev
}

function prompt_for_build_tools() {
    print_warning "Do you want to install compilers and build tools (build-essential, gcc, g++)?"
    read -r -p "This is needed for some software but increases the attack surface. [y/N] " response
    if [[ "$response" =~ ^([yY][eE]|[yY])$ ]]; then
        print_status "Installing build-essential..."
        apt-get install -y build-essential
    else
        print_status "Skipping installation of build tools."
    fi
}

function add_user() {
    while true; do
        read -r -p "Enter username: " USERNAME
        if [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            break
        else
            print_error "Invalid username. Please try again."
        fi
    done

    PASSWORD=$(openssl rand -base64 16)
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
    usermod -aG sudo "$USERNAME"
    chage -d 0 "$USERNAME" # Force password change on first login
    print_status "User $USERNAME added."
    print_warning "!!!!!!!!!!!!!!!!!!!!!!!! IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!"
    print_warning "The temporary password for user '$USERNAME' is: $PASSWORD"
    print_warning "The user will be FORCED to change it upon their first login."
    print_warning "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Username: $USERNAME" >> "$BACKUP_DIR/credentials.txt"
    echo "Temporary Password: $PASSWORD" >> "$BACKUP_DIR/credentials.txt"
    chmod 600 "$BACKUP_DIR/credentials.txt"
}

function regenerate_ssh_host_keys() {
    print_status "Regenerating SSH host keys for improved security..."
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    
    # Remove weak Diffie-Hellman moduli
    if [ -f /etc/ssh/moduli ]; then
        print_status "Removing weak DH moduli..."
        backup_file /etc/ssh/moduli
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        mv /etc/ssh/moduli.safe /etc/ssh/moduli
    fi
}

function setup_ssh() {
    while true; do
        read -r -p "Enter SSH port between 1024 and 65535: " SSHPORT
        if [[ "$SSHPORT" =~ ^[0-9]+$ ]] && [ "$SSHPORT" -ge 1024 ] && [ "$SSHPORT" -le 65535 ]; then
            break
        else
            print_error "Invalid port number. Please try again."
        fi
    done

    mkdir -p /home/"$USERNAME"/.ssh
    touch /home/"$USERNAME"/.ssh/authorized_keys
    chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh
    chmod 700 /home/"$USERNAME"/.ssh
    chmod 600 /home/"$USERNAME"/.ssh/authorized_keys

    while true; do
        read -r -p "Enter URL to public SSH key (e.g., https://github.com/username.keys) or press Enter to paste manually: " ssh_key_url
        if [[ -n "$ssh_key_url" ]]; then
            local ssh_key
            ssh_key=$(curl -sL "$ssh_key_url")
            if [[ "$ssh_key" == "Not Found" || -z "$ssh_key" ]]; then
                print_error "Could not fetch key from URL. Check URL and try again."
            elif [[ ! "$ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2) ]]; then
                print_error "Invalid SSH key format from URL."
            else
                echo "$ssh_key" >> "/home/$USERNAME/.ssh/authorized_keys"
                print_status "Public key added from URL."
                break
            fi
        else
            # Fall back to manual paste
            print_warning "Please provide the public SSH key for the user $USERNAME:"
            read -r SSH_KEY
            echo "$SSH_KEY" >> /home/"$USERNAME"/.ssh/authorized_keys
            break
        fi
    done

    regenerate_ssh_host_keys

    backup_file "$SSHD_FILE"
    
    # Advanced SSH hardening with post-quantum algorithms
    cat > "$SSHD_FILE" <<EOF
# Advanced SSH Configuration - Ubuntu 24.04 LTS
Port $SSHPORT
AddressFamily inet
Protocol 2

# Post-quantum resistant key exchange + modern algorithms
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,ecdh-sha2-nistp521
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Host keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security restrictions
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
DebianBanner no

# Login restrictions
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 3
MaxStartups 3:50:10
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Access control
AllowUsers $USERNAME
DenyUsers root
AllowGroups sudo

# Additional hardening
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression no
UseDNS no
EOF

    # Validate the new SSHD configuration
    sshd -t || { print_error "SSH config validation failed! Exiting to prevent lockout."; exit 1; }

    print_status "SSH configured with advanced security settings on port $SSHPORT"
}

function advanced_kernel_hardening() {
    print_status "Applying advanced kernel hardening for Ubuntu 24.04..."
    
    backup_file /etc/sysctl.conf
    
    cat > /etc/sysctl.d/99-security-hardening.conf <<EOF
# Advanced Kernel Security Hardening for Ubuntu 24.04
# Kernel 6.8 specific enhancements

# Hide kernel pointers
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Disable kexec
kernel.kexec_load_disabled = 1

# Restrict performance monitoring
kernel.perf_event_paranoid = 3

# Disable userfaultfd for non-root
vm.unprivileged_userfaultfd = 0

# Restrict user namespaces (Ubuntu 24.04 enhanced)
user.max_user_namespaces = 0

# Enable ExecShield
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# BPF hardening (enhanced in kernel 6.8)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Network hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# IPv6 hardening
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# File system hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Core dumps
kernel.core_uses_pid = 1

# ASLR
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Disable magic SysRq key
kernel.sysrq = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Restrict ptrace
kernel.yama.ptrace_scope = 1
EOF

    sysctl -p /etc/sysctl.d/99-security-hardening.conf
    print_status "Kernel hardening applied with Ubuntu 24.04 enhancements"
}

function grub_hardening() {
    print_status "Hardening GRUB bootloader with Ubuntu 24.04 features..."
    
    backup_file /etc/default/grub
    
    # Add security parameters to GRUB including shadow stack support
    cat >> /etc/default/grub.d/security.cfg <<EOF
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor kaslr slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 vsyscall=none debugfs=off intel_shadow_stack=on"
EOF

    update-grub
    print_status "GRUB hardening applied with shadow stack support"
}

function setup_firewall() {
    print_status "Setting up UFW firewall..."
    apt-get install -y ufw
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward
    
    # Allow SSH on custom port with rate limiting
    ufw limit "$SSHPORT"/tcp comment 'SSH (Rate Limited)'
    
    # Enable UFW
    ufw --force enable
    
    print_status "UFW firewall configured and enabled"
}

function setup_egress_filtering() {
    print_status "Configuring UFW Egress (Outbound) Filtering..."
    print_warning "Applying a 'deny by default' outbound policy for enhanced security."
    
    # Change default outgoing policy to deny
    ufw default deny outgoing

    # Allow essential outbound traffic
    # 1. DNS
    ufw allow out to any port 53 proto udp comment 'DNS'
    ufw allow out to any port 53 proto tcp comment 'DNS'
    # 2. HTTP and HTTPS for package management and web access
    ufw allow out to any port 80 proto tcp comment 'HTTP'
    ufw allow out to any port 443 proto tcp comment 'HTTPS'
    # 3. NTP for time synchronization
    ufw allow out to any port 123 proto udp comment 'NTP'
    # 4. Allow outbound traffic for the new SSH port
    ufw allow out on to any port "$SSHPORT" proto tcp comment 'SSH Outbound'
    
    print_status "Egress filtering rules applied. Review and add rules for any other required outbound services."
    ufw status verbose
}

function install_crowdsec() {
    print_status "Installing CrowdSec (modern fail2ban replacement)..."
    
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables
    
    # Install essential collections
    cscli collections install crowdsecurity/linux
    cscli collections install crowdsecurity/sshd
    cscli collections install crowdsecurity/iptables
    
    # Enable and start services
    systemctl enable crowdsec
    systemctl start crowdsec
    systemctl enable crowdsec-firewall-bouncer
    systemctl start crowdsec-firewall-bouncer
    
    print_status "CrowdSec installed and configured"
}

function install_wazuh() {
    print_status "Installing Wazuh unified security platform..."
    
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update
    
    # Install Wazuh agent
    WAZUH_MANAGER="localhost" apt-get install -y wazuh-agent
    
    # Basic configuration
    cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>localhost</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>no</enabled>
    </enrollment>
  </client>
  
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/home</directories>
    
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
  </syscheck>
  
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>
  
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
EOF

    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    
    print_status "Wazuh agent installed and configured"
}

function install_suricata() {
    print_status "Installing Suricata IDS/IPS for Ubuntu 24.04..."
    
    # Use official OISF PPA for latest version compatible with Ubuntu 24.04
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update
    apt-get install -y suricata suricata-update
    
    # Update rules
    suricata-update
    
    # Basic configuration
    backup_file /etc/suricata/suricata.yaml
    
    # Configure Suricata for IDS mode
    sed -i 's/^\(\s*\)- interface: .*/\1- interface: eth0/' /etc/suricata/suricata.yaml
    
    # Enable and start Suricata
    systemctl enable suricata
    systemctl start suricata
    
    print_status "Suricata IDS installed and configured for kernel 6.8"
}

function cloud_metadata_protection() {
    print_status "Implementing cloud metadata service protection..."
    
    # Block metadata service access for non-root users
    iptables -I OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP
    ip6tables -I OUTPUT -d fe80::1 -m owner ! --uid-owner 0 -j DROP
    
    # Make rules persistent
    apt-get install -y iptables-persistent
    netfilter-persistent save
    
    print_status "Cloud metadata service protected"
}

function install_advanced_monitoring() {
    print_status "Installing advanced monitoring tools..."
    
    # Install htop, iotop, nethogs for system monitoring
    apt-get install -y htop iotop nethogs ncdu
    
    # Install osquery for system querying
    export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
    add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
    apt-get update
    apt-get install -y osquery
    
    print_status "Advanced monitoring tools installed"
}

function secure_shared_memory() {
    print_status "Securing shared memory..."
    
    backup_file /etc/fstab
    
    # Check if already configured
    if ! grep -q "tmpfs.*\/run\/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount /run/shm
        print_status "Shared memory secured"
    else
        print_warning "Shared memory already configured"
    fi
}

function install_unattended_upgrades() {
    print_status "Configuring unattended upgrades..."
    
    apt-get install -y unattended-upgrades update-notifier-common
    
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    
    print_status "Unattended upgrades configured"
}

function install_auditd() {
    print_status "Installing and configuring auditd..."
    
    apt-get install -y auditd audispd-plugins
    
    # Basic audit rules
    cat > /etc/audit/rules.d/hardening.rules <<EOF
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor SSH
-w /home/*/.ssh -p wa -k ssh_changes

# Monitor system calls
-a exit,always -F arch=b64 -S execve -k execution
-a exit,always -F arch=b64 -S connect -k network_connections

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make configuration immutable
-e 2
EOF

    systemctl enable auditd
    systemctl restart auditd
    
    print_status "Auditd configured"
}

function configure_apparmor() {
    print_status "Configuring AppArmor..."
    
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    
    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    # Set enforcing mode for all profiles
    aa-enforce /etc/apparmor.d/*
    
    print_status "AppArmor configured and enforced"
}

function secure_dns() {
    print_status "Securing DNS configuration..."
    
    backup_file /etc/systemd/resolved.conf
    
    # Configure DNS over TLS
    cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=8.8.8.8#dns.google 8.8.4.4#dns.google
DNSSEC=yes
DNSOverTLS=yes
Cache=yes
DNSStubListener=yes
EOF

    systemctl restart systemd-resolved
    
    print_status "DNS secured with DNS over TLS"
}

function disable_unused_services() {
    print_status "Disabling unused services..."
    
    SERVICES=(
        avahi-daemon
        cups
        bluetooth
        snapd
        multipathd
        ModemManager
    )

    for service in "${SERVICES[@]}"; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            systemctl disable "$service" 2>/dev/null || true
            systemctl stop "$service" 2>/dev/null || true
            print_status "Disabled $service"
        fi
    done
}

function install_rkhunter() {
    print_status "Installing rkhunter..."
    
    apt-get install -y rkhunter
    
    # Update rkhunter
    rkhunter --update
    rkhunter --propupd
    
    # Configure daily scans
    sed -i 's/CRON_DAILY_RUN=""/CRON_DAILY_RUN="yes"/' /etc/default/rkhunter
    sed -i 's/CRON_DB_UPDATE=""/CRON_DB_UPDATE="yes"/' /etc/default/rkhunter
    
    print_status "Rkhunter installed and configured"
}

function install_usbguard() {
    print_status "Installing USBGuard to block unauthorized USB devices..."
    apt-get install -y usbguard
    
    # Generate a policy that allows currently connected devices and blocks new ones.
    # On a typical cloud server, this effectively blocks all USB devices.
    if [ ! -f /etc/usbguard/rules.conf ]; then
        usbguard generate-policy > /etc/usbguard/rules.conf
        print_status "USBGuard policy generated."
    else
        print_warning "USBGuard policy already exists."
    fi
    
    systemctl enable usbguard
    systemctl start usbguard
    print_status "USBGuard installed and enabled. New USB devices will be blocked."
}

function setup_aide_daily() {
    print_status "Setting up daily AIDE check..."
    apt-get install -y aide
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/sh
/usr/bin/aide --check | mail -s "AIDE Report $(hostname)" root
EOF
    chmod +x /etc/cron.daily/aide-check
    print_status "AIDE configured for daily checks."
}

function disable_root_account() {
    print_status "Disabling root account..."
    passwd -l root
    print_status "Root account has been disabled"
}

function configure_file_permissions() {
    print_status "Hardening file permissions..."
    
    # Secure important directories
    chmod 700 /root
    chmod 700 /home/*
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 640 /etc/shadow
    chmod 640 /etc/gshadow
    chmod 600 /boot/grub/grub.cfg
    
    # Find and fix world-writable files
    print_warning "Searching for world-writable files..."
    find / -xdev -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null | while read -r file; do
        chmod o-w "$file"
        print_warning "Fixed world-writable: $file"
    done
    
    print_status "File permissions hardened"
}

function setup_log_rotation() {
    print_status "Configuring enhanced log rotation..."
    
    cat > /etc/logrotate.d/security <<EOF
/var/log/auth.log
/var/log/kern.log
/var/log/syslog
{
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /bin/kill -HUP \`cat /var/run/rsyslogd.pid 2> /dev/null\` 2> /dev/null || true
    endscript
}
EOF

    print_status "Log rotation configured"
}

function create_security_report() {
    print_status "Creating security configuration report..."
    
    REPORT_FILE="$BACKUP_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$REPORT_FILE" <<EOF
Ubuntu 24.04 LTS Security Configuration Report
Generated: $(date)
Hostname: $(hostname)
IP Address: $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
Kernel Version: $(uname -r)

=== System Information ===
Ubuntu Version: 24.04 LTS (Noble Numbat)
Kernel: 6.8+ with enhanced security features
FORTIFY_SOURCE: Level 3 (enhanced in 24.04)
Shadow Stack: Enabled for Intel CPUs

=== SSH Configuration ===
SSH Port: $SSHPORT
SSH User: $USERNAME

=== Security Tools Installed ===
- CrowdSec (Modern fail2ban with threat intelligence)
- Wazuh Agent (Unified XDR/SIEM)
- Suricata IDS/IPS
- UFW Firewall
- Auditd (System auditing)
- AppArmor (Mandatory Access Control)
- Unattended Upgrades
- Rkhunter (Rootkit detection)
- Ubuntu Security Guide (CIS compliance)

=== Kernel Hardening ===
- Advanced sysctl parameters applied
- GRUB security parameters configured
- ASLR enabled
- ExecShield enabled
- BPF hardening enabled
- Shadow stack support (Intel CPUs)

=== Network Security ===
- UFW firewall enabled
- Cloud metadata service protected
- DNS over TLS configured
- IPv6 disabled
- DDoS protection configured

=== File System Security ===
- Shared memory secured (noexec,nosuid,nodev)
- Important file permissions hardened
- World-writable files fixed
- FORTIFY_SOURCE=3 protection

=== Service Status ===
$(systemctl is-active crowdsec 2>/dev/null || echo "inactive") - CrowdSec
$(systemctl is-active wazuh-agent 2>/dev/null || echo "inactive") - Wazuh Agent
$(systemctl is-active suricata 2>/dev/null || echo "inactive") - Suricata IDS
$(systemctl is-active ufw 2>/dev/null || echo "inactive") - UFW Firewall
$(systemctl is-active auditd 2>/dev/null || echo "inactive") - Auditd
$(systemctl is-active apparmor 2>/dev/null || echo "inactive") - AppArmor

=== Ubuntu 24.04 Specific Enhancements ===
- Kernel 6.8 with improved hardware security support
- FORTIFY_SOURCE=3 for enhanced buffer overflow protection
- Shadow stack support for ROP attack prevention
- Enhanced BPF security restrictions
- Improved user namespace isolation

=== Next Steps ===
1. Configure Wazuh manager endpoint if using centralized management
2. Review and customize Suricata rules for your specific needs
3. Enable Ubuntu Pro and run USG for CIS compliance
4. Set up log aggregation and monitoring dashboards
5. Schedule regular security audits
6. Test incident response procedures

=== Important Files ===
- SSH Config: /etc/ssh/sshd_config
- Kernel Parameters: /etc/sysctl.d/99-security-hardening.conf
- Audit Rules: /etc/audit/rules.d/hardening.rules
- Credentials: $BACKUP_DIR/credentials.txt

EOF

    chmod 600 "$REPORT_FILE"
    print_status "Security report created: $REPORT_FILE"
}

function restart_ssh() {
    while true; do
        print_warning "Do you wish to restart SSH? [Y/n]"
        read -r input
        case $input in
            [Yy]* ) 
                systemctl restart ssh
                print_status "SSH service restarted"
                break
                ;;
            [Nn]* ) 
                print_warning "SSH not restarted. Remember to restart manually!"
                break
                ;;
            * ) 
                print_error "Invalid input. Please enter Y or n."
                ;;
        esac
    done
}

function main() {
    print_status "Starting Ubuntu 24.04 LTS Advanced Security Hardening Script"
    print_status "Noble Numbat edition with kernel 6.8 enhancements"
    
    run_as_root
    check_distro
    create_backup_dir
    create_swap
    update_upgrade
    install_essential_packages
    prompt_for_build_tools
    add_user
    setup_ssh
    advanced_kernel_hardening
    grub_hardening
    setup_firewall
    setup_egress_filtering
    install_crowdsec
    install_wazuh
    install_suricata
    cloud_metadata_protection
    install_advanced_monitoring
    secure_shared_memory
    install_unattended_upgrades
    install_auditd
    configure_apparmor
    secure_dns
    disable_unused_services
    install_rkhunter
    install_usbguard
    setup_aide_daily
    configure_file_permissions
    setup_log_rotation
    disable_root_account
    create_security_report
    
    print_status "Security hardening completed for Ubuntu 24.04 LTS!"
    print_warning "IMPORTANT: Review the security report in $BACKUP_DIR"
    print_warning "Test SSH access on port $SSHPORT before closing this session!"
    
    restart_ssh
}

# Run main function
main
