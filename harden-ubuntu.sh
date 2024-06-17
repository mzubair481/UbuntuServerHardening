#!/bin/bash

# This script is intended to be run as root on a fresh install of Ubuntu 22.04 LTS server.

set -euo pipefail

SSHD_FILE="/etc/ssh/sshd_config"
LOG_FILE="/var/log/server_setup.log"
USERNAME=""
SSHPORT=""

exec > >(tee -i "$LOG_FILE")
exec 2>&1

function run_as_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

function check_distro() {
    if [[ ! -f /etc/os-release ]]; then
        echo "This script is intended to be run on Ubuntu 22.04 LTS"
        exit 1
    fi
    source /etc/os-release
    if [[ $ID != "ubuntu" || $VERSION_ID != "22.04" ]]; then
        echo "This script is intended to be run on Ubuntu 22.04 LTS"
        exit 1
    fi
}

function create_swap() {
    if free | awk '/^Swap:/ {exit !$2}'; then
        echo "Swap already exists"
    else
        PHYSRAM=$(grep MemTotal /proc/meminfo | awk '{print int($2 / 1024 / 1024 + 0.5)}')
        SWAPSIZE=$((2 * PHYSRAM))
        SWAPSIZE=$((SWAPSIZE > 31 ? 31 : SWAPSIZE))
        SWAPSIZE=$((SWAPSIZE < 2 ? 2 : SWAPSIZE))

        fallocate -l "${SWAPSIZE}G" /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        cp /etc/fstab /etc/fstab.bak
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
        echo "Swap created"
    fi
}

function update_upgrade() {
    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y
}

function add_user() {
    while true; do
        read -r -p "Enter username: " USERNAME
        if [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            break
        else
            echo "Invalid username. Please try again."
        fi
    done

    PASSWORD=$(openssl rand -base64 12)
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
    usermod -aG sudo "$USERNAME"
    echo "User $USERNAME added with password $PASSWORD"
}

function setup_ssh() {
    while true; do
        read -r -p "Enter ssh port between 1024 and 65535: " SSHPORT
        if [[ "$SSHPORT" =~ ^[0-9]+$ ]] && [ "$SSHPORT" -ge 1024 ] && [ "$SSHPORT" -le 65535 ]; then
            break
        else
            echo "Invalid port number. Please try again."
        fi
    done

    mkdir -p /home/"$USERNAME"/.ssh
    touch /home/"$USERNAME"/.ssh/authorized_keys
    chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh
    chmod 700 /home/"$USERNAME"/.ssh
    chmod 600 /home/"$USERNAME"/.ssh/authorized_keys

    echo "Please provide the public SSH key for the user $USERNAME:"
    read -r SSH_KEY
    echo "$SSH_KEY" >> /home/"$USERNAME"/.ssh/authorized_keys

    sed -i "s/#Port 22/Port $SSHPORT/g" "$SSHD_FILE"
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" "$SSHD_FILE"
    sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" "$SSHD_FILE"
    sed -i "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" "$SSHD_FILE"
    sed -i "s/X11Forwarding yes/X11Forwarding no/g" "$SSHD_FILE"
    sed -i "s/#AllowTcpForwarding yes/AllowTcpForwarding no/g" "$SSHD_FILE"
    sed -i "s/#LogLevel INFO/LogLevel VERBOSE/g" "$SSHD_FILE"
    sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" "$SSHD_FILE"
    sed -i "s/#MaxSessions 10/MaxSessions 3/g" "$SSHD_FILE"
    echo "AllowUsers $USERNAME" >> "$SSHD_FILE"

    # Disable root login via SSH
    sed -i "s/^PermitRootLogin.*/PermitRootLogin no/g" "$SSHD_FILE"
}

function setup_firewall() {
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSHPORT"/tcp
    ufw --force enable
}

function harden_server() {
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    apt install unattended-upgrades fail2ban auditd logwatch -y
    dpkg-reconfigure --priority=low unattended-upgrades

    cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSHPORT
logpath = /var/log/auth.log
maxretry = 3
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    systemctl enable auditd
    systemctl start auditd
    echo "logwatch --output mail" >> /etc/cron.daily/00logwatch
}

function install_intrusion_detection() {
    apt install psad -y
    systemctl enable psad
    systemctl start psad
    psad --sig-update
}

function install_ddos_protection() {
    apt install dnsutils -y
    apt install iptables-persistent -y

    iptables -A INPUT -p tcp --dport "$SSHPORT" -m connlimit --connlimit-above 3 -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSHPORT" -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSHPORT" -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport "$SSHPORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

    netfilter-persistent save
    netfilter-persistent start
}

function disable_unused_services() {
    SERVICES=(avahi-daemon cups bluetooth)

    for service in "${SERVICES[@]}"; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            systemctl disable "$service"
        else
            echo "$service.service does not exist, skipping."
        fi
    done
}

function setup_aide() {
    apt install aide -y
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo "0 3 * * * root /usr/bin/aide --check" >> /etc/crontab
}

function disable_root_account() {
    passwd -l root
    echo "Root account has been disabled."
}

function restart_ssh() {
    while true; do
        read -r -p "Do you wish to restart ssh? [Y/n] " input
        case $input in
            [Yy]* ) systemctl restart ssh; break;;
            [Nn]* ) exit;;
            * ) echo "Invalid input. Please enter Y or n.";;
        esac
    done
}

run_as_root
check_distro
create_swap
update_upgrade
add_user
setup_ssh
setup_firewall
harden_server
install_intrusion_detection
install_ddos_protection
disable_unused_services
setup_aide
disable_root_account
restart_ssh
