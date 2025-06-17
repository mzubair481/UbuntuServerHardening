# Advanced Ubuntu 24.04 LTS Server Hardening Script

This project provides a comprehensive shell script to automate the security hardening of a fresh Ubuntu 24.04 LTS (Noble Numbat) server. It implements a wide range of modern security best practices to establish a robust baseline for public-facing servers.

## Key Features

This script is designed to be idempotent and includes the following security enhancements:

- **Automated System Setup**:
  - Creates a swap file based on system RAM.
  - Updates and upgrades all system packages.
  - Creates a new administrative user with `sudo` privileges and forces a password change on first login.

- **Advanced SSH Hardening**:
  - Changes the default SSH port to a user-specified value.
  - Disables root login and password-based authentication.
  - Enforces modern, secure SSH key exchange algorithms, including post-quantum resistant ciphers.
  - Regenerates SSH host keys and removes weak Diffie-Hellman moduli.
  - Allows fetching SSH public keys directly from a URL (e.g., GitHub).
  - Validates the SSH configuration before applying it to prevent lockouts.

- **Comprehensive Firewall Configuration**:
  - Configures `UFW` (Uncomplicated Firewall) with a default-deny ingress policy.
  - Implements strict egress filtering, allowing only essential outbound traffic (DNS, HTTP/S, NTP, SSH).
  - Applies rate limiting to the SSH port to mitigate brute-force attacks.

- **Intrusion Detection and Prevention (IDS/IPS)**:
  - **CrowdSec**: Deploys the modern, collaborative IDS/IPS to replace `fail2ban`.
  - **Wazuh**: Installs the Wazuh agent for unified XDR and SIEM capabilities.
  - **Suricata**: Sets up the Suricata IDS/IPS engine for network threat detection.
  - **AIDE**: Configures the Advanced Intrusion Detection Environment for file integrity monitoring with daily checks.
  - **Rkhunter**: Installs a rootkit scanner for malware detection.

- **System and Kernel Hardening**:
  - Applies security-focused kernel parameters via `sysctl`.
  - Hardens the GRUB bootloader.
  - Enforces AppArmor profiles for mandatory access control.
  - Configures `auditd` for detailed system auditing.
  - Secures shared memory (`/run/shm`).

- **Service and Filesystem Security**:
  - **USBGuard**: Installs and configures USBGuard to block unauthorized USB devices.
  - Disables unnecessary services to reduce the attack surface.
  - Hardens file permissions on critical system files and directories.
  - Protects the cloud metadata service from unauthorized access.

- **Logging and Reporting**:
  - Redirects all script output to a detailed log file in `/var/log`.
  - Generates a comprehensive security report summarizing the applied hardening measures.

## Prerequisites

- A fresh installation of Ubuntu 24.04 LTS.
- Root (`sudo`) access to the server.

## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/UbuntuServerHardening.git
   cd UbuntuServerHardening
   ```
2. **Make the script executable:**
   ```bash
   chmod +x main.sh
   ```
3. **Run the script as root:**
   ```bash
   sudo ./main.sh
   ```
4. **Follow the on-screen prompts** to provide a new username and a custom SSH port.

## Security Report

After the script completes, a detailed security report will be generated in the `/root/security_backups` directory. This report provides a summary of all the security measures that have been applied, as well as the status of key security services.

## Disclaimer

This script is provided "as is" and without warranty. It makes significant changes to your system's security configuration. Always review the script and test it in a non-production environment before deploying it on a live server. The authors are not responsible for any damage or loss of data.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
