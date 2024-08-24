
# Linux Security Audit and Hardening Script

## Overview

This Bash script automates the process of auditing security and hardening Linux servers. It performs various security checks and implements best practices for securing servers.

## Features

- **User and Group Audits**: Lists all users and groups, checks for users with UID 0 (root privileges), and identifies users without passwords or with weak passwords.
- **File and Directory Permissions**: Scans for files and directories with world-writable permissions, checks for `.ssh` directories, and reports files with SUID or SGID bits set.
- **Service Audits**: Lists all running services, ensures critical services (e.g., sshd, iptables) are active, and checks for services running on non-standard or insecure ports.
- **Firewall and Network Security**: Verifies firewall status, checks for open ports and IP forwarding, and ensures secure IP configurations.
- **IP and Network Configuration Checks**: Identifies public vs. private IPs, ensures sensitive services are not exposed on public IPs.
- **Security Updates and Patching**: Checks for and applies available security updates.
- **Log Monitoring**: Monitors logs for suspicious activity.
- **Server Hardening**: Implements SSH hardening, disables IPv6 if not required, secures the bootloader, configures firewall settings, and sets up automatic updates.
- **Custom Security Checks**: Allows for easy extension with custom security checks based on specific organizational policies.
- **Reporting and Alerting**: Generates a comprehensive report of the security audit and hardening process and can send alerts for critical vulnerabilities.

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/skaftab-in/linux-security-audit.git
   cd linux-security-audit
   ```

2. Make the script executable:
   ```bash
   chmod +x security_audit_and_hardening.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./security_audit_and_hardening.sh
   ```

4. The audit and hardening report will be saved to `/var/log/security_audit_final.log`.

## Customization

- You can customize the script to include additional checks or modify existing ones based on your specific server environment and security requirements.
- Modify the script directly or add custom functions to extend its capabilities.

## Contributing

- Fork the repository.
- Create a new branch (`git checkout -b feature-branch`).
- Commit your changes (`git commit -m 'Add new feature'`).
- Push to the branch (`git push origin feature-branch`).
- Open a pull request.


