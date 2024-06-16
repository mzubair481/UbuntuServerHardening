# Server Hardening and Security Automation

The project aims to automate the process of hardening and securing a fresh installation of Ubuntu 22.04 LTS on a server. This script enhances the security posture of your server by implementing best practices for system and network security, including firewall configuration, SSH hardening, intrusion detection, and DDoS protection.

## Features

- **Swap Creation:** Automatically creates swap space based on physical memory.
- **System Update and Upgrade:** Ensures the server has the latest updates and security patches.
- **User Management:** Adds a new user and configures SSH keys for secure access.
- **SSH Configuration:** Hardens SSH configuration by changing the default port, disabling root login, and enforcing key-based authentication.
- **Firewall Setup:** Configures UFW firewall with default deny rules and allows necessary ports.
- **Server Hardening:** Includes various security measures such as installing fail2ban, configuring unattended-upgrades, and securing shared memory.
- **Intrusion Detection:** Installs and configures PSAD for network intrusion detection.
- **DDoS Protection:** Implements iptables rules to protect against DDoS attacks.
- **Service Disabling:** Disables unnecessary services to reduce attack surface.
- **File Integrity Monitoring:** Sets up AIDE for regular file system integrity checks.
- **Logging and Monitoring:** Installs auditd and configures logwatch for enhanced logging and monitoring.

## Prerequisites

- A fresh installation of Ubuntu 22.04 LTS.
- Root access to the server.

## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mzubair481/UbuntuServerHardening.git
   cd UbuntuServerHardening
   ```
2. **Make the script executable:**
   ```bash
    chmod +x harden-ubuntu.sh
    ```
3. **Run the script:**
    ```bash
    sudo ./harden-ubuntu.sh
    ```
4. **Follow the on-screen instructions to configure the script.**

## Configuration Details

### SSH Configuration

The script modifies `/etc/ssh/sshd_config` to enhance SSH security:
- Changes the SSH port (user-specified).
- Disables root login.
- Enforces public key authentication.
- Limits authentication attempts and sessions.

### Firewall Configuration

The script sets up UFW with the following rules:
- Deny all incoming traffic by default.
- Allow all outgoing traffic by default.
- Allow SSH on the user-specified port.

### Fail2Ban Configuration

Configures fail2ban to protect against brute-force attacks:
- Monitors SSH access attempts.
- Bans IPs with too many failed login attempts.

### PSAD Configuration

Installs and configures PSAD for intrusion detection:
- Monitors network traffic for suspicious activity.
- Updates signature database.

### AIDE Configuration

Sets up AIDE for file integrity monitoring:
- Initializes the AIDE database.
- Schedules daily checks for file integrity.

## Customization

You can customize various aspects of the script by modifying the respective functions within the `harden-ubuntu.sh` file. For example, you can change the default SSH port, add additional firewall rules, or configure different fail2ban settings.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This script is provided as-is and without warranty. Always review and test the script in a safe environment before using it in production.

## Acknowledgments

- [Ubuntu Server Guide](https://help.ubuntu.com/lts/serverguide/index.html)
- [DigitalOcean Linux Basic Tutorials](https://www.digitalocean.com/community/tags/linux-basics)
- [Linode Security Guides](https://www.linode.com/docs/guides/security/)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [OWASP](https://owasp.org/)
