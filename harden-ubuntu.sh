#!/bin/bash

# This script is intended to be run as root.
# This script is intended to be run on a fresh install of Ubuntu 22.04 LTS.
# This script is intended to be run on a server, not a desktop.

sshd_file="/etc/ssh/sshd_config"

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
    if [[ $ID != "ubuntu" ]]; then
        echo "This script is intended to be run on Ubuntu 22.04 LTS"
        exit 1
    fi
    if [[ $VERSION_ID != "22.04" ]]; then
        echo "This script is intended to be run on Ubuntu 22.04 LTS"
        exit 1
    fi
}

function create_swap() {
    if free | awk '/^Swap:/ {exit !$2}'; then
        sleep 2
        echo "Swap already exists"
    else
        PHYSRAM=$(grep MemTotal /proc/meminfo | awk '{print int($2 / 1024 / 1024 + 0.5)}')
        let "SWAPSIZE=2*$PHYSRAM"
        (($SWAPSIZE >= 1 && $SWAPSIZE >= 31)) && SWAPSIZE=31
        (($SWAPSIZE <= 2)) && SWAPSIZE=2

        fallocate -l ${SWAPSIZE}G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && cp /etc/fstab /etc/fstab.bak && echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
        sleep 2
        echo "Swap created"
    fi
}

function update_upgrade() {
    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y
}

function add_user() {
    read -r -p "Enter username: " username
    adduser $username
    usermod -aG sudo $username
}

function setup_ssh() {
    if [[ -f /root/.ssh/authorized_keys ]]; then
        mkdir /home/$username/.ssh
        cp /root/.ssh/authorized_keys /home/$username/.ssh/authorized_keys
        chown -R $username:$username /home/$username/.ssh
        chmod 700 /home/$username/.ssh
        chmod 600 /home/$username/.ssh/authorized_keys
    fi

    read -r -p "Enter ssh port between 1024 and 65535: " sshport

    sed -i "s/#Port 22/Port $sshport/g" $sshd_file
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" $sshd_file
    sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" $sshd_file
    sed -i "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" $sshd_file
    sed -i "s/X11Forwarding yes/X11Forwarding no/g" $sshd_file
    sed -i "s/#AllowTcpForwarding yes/AllowTcpForwarding no/g" $sshd_file
    sed -i "s/#LogLevel INFO/LogLevel VERBOSE/g" $sshd_file
    sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" $sshd_file
    sed -i "s/#MaxSessions 10/MaxSessions 3/g" $sshd_file
}

function setup_firewall() {
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $sshport
    ufw enable
}

function harden_server() {
    if grep -q "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    fi

    apt install unattended-upgrades -y
    dpkg-reconfigure --priority=low unattended-upgrades
}

function restart_ssh() {
    while true; do
    read -r -p "Do you wish to restart ssh? [Y/n] " input
    case $input in
        [Yy]* ) systemctl restart ssh; break;;
        [Nn]* ) exit;;
        * ) echo "Invalid input...";;
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
restart_ssh