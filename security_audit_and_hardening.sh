#!/bin/bash

# Function to check if running as root
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root" 
    exit 1
  fi
}

# Function to audit users and groups
audit_users_and_groups() {
  echo "Auditing Users and Groups..." | tee -a /var/log/security_audit_final.log

  echo "1. Listing all users and groups:" | tee -a /var/log/security_audit_final.log
  cat /etc/passwd | tee -a /var/log/security_audit_final.log
  cat /etc/group | tee -a /var/log/security_audit_final.log

  echo "2. Checking for users with UID 0 (root privileges):" | tee -a /var/log/security_audit_final.log
  awk -F: '($3 == 0) {print}' /etc/passwd | tee -a /var/log/security_audit_final.log

  echo "3. Identifying users without passwords or with weak passwords:" | tee -a /var/log/security_audit_final.log
  awk -F: '($2 == "" ) {print $1}' /etc/shadow | tee -a /var/log/security_audit_final.log
}

# Function to audit file and directory permissions
audit_file_permissions() {
  echo "Auditing File and Directory Permissions..." | tee -a /var/log/security_audit_final.log

  echo "1. Scanning for files and directories with world-writable permissions:" | tee -a /var/log/security_audit_final.log
  find / -perm -0002 -type d 2>/dev/null | tee -a /var/log/security_audit_final.log

  echo "2. Checking for .ssh directories with secure permissions:" | tee -a /var/log/security_audit_final.log
  find /home -name ".ssh" -exec ls -ld {} \; | tee -a /var/log/security_audit_final.log

  echo "3. Reporting files with SUID or SGID bits set:" | tee -a /var/log/security_audit_final.log
  find / -perm /6000 -type f 2>/dev/null | tee -a /var/log/security_audit_final.log
}

# Function to audit services
audit_services() {
  echo "Auditing Services..." | tee -a /var/log/security_audit_final.log

  echo "1. Listing all running services:" | tee -a /var/log/security_audit_final.log
  systemctl list-units --type=service --state=running | tee -a /var/log/security_audit_final.log

  echo "2. Checking for critical services (e.g., sshd, iptables):" | tee -a /var/log/security_audit_final.log
  systemctl is-active sshd | tee -a /var/log/security_audit_final.log
  systemctl is-active iptables | tee -a /var/log/security_audit_final.log

  echo "3. Checking for non-standard ports:" | tee -a /var/log/security_audit_final.log
  netstat -tuln | grep -vE '22|80|443' | tee -a /var/log/security_audit_final.log
}

# Function to check firewall and network security
check_firewall_and_network() {
  echo "Checking Firewall and Network Security..." | tee -a /var/log/security_audit_final.log

  echo "1. Verifying if firewall is active:" | tee -a /var/log/security_audit_final.log
  ufw status || iptables -L | tee -a /var/log/security_audit_final.log

  echo "2. Checking for open ports and associated services:" | tee -a /var/log/security_audit_final.log
  netstat -tuln | tee -a /var/log/security_audit_final.log

  echo "3. Checking for IP forwarding or other insecure configurations:" | tee -a /var/log/security_audit_final.log
  sysctl net.ipv4.ip_forward | tee -a /var/log/security_audit_final.log
}

# Function to check IP and network configurations
check_ip_network_configs() {
  echo "Checking IP and Network Configurations..." | tee -a /var/log/security_audit_final.log

  echo "1. Identifying public vs. private IPs:" | tee -a /var/log/security_audit_final.log
  ip addr | grep 'inet ' | tee -a /var/log/security_audit_final.log

  echo "2. Ensuring sensitive services are not exposed on public IPs:" | tee -a /var/log/security_audit_final.log
  iptables -L -v -n | tee -a /var/log/security_audit_final.log
}

# Function to apply security updates and patching
apply_security_updates() {
  echo "Applying Security Updates and Patching..." | tee -a /var/log/security_audit_final.log

  echo "1. Checking for available updates:" | tee -a /var/log/security_audit_final.log
  apt-get update | tee -a /var/log/security_audit_final.log

  echo "2. Applying updates:" | tee -a /var/log/security_audit_final.log
  apt-get upgrade -y | tee -a /var/log/security_audit_final.log
}

# Function to monitor logs
monitor_logs() {
  echo "Monitoring Logs..." | tee -a /var/log/security_audit_final.log

  echo "1. Checking for suspicious log entries:" | tee -a /var/log/security_audit_final.log
  grep 'Failed password' /var/log/auth.log | tee -a /var/log/security_audit_final.log
}

# Function to implement server hardening steps
server_hardening() {
  echo "Implementing Server Hardening..." | tee -a /var/log/security_audit_final.log

  echo "1. SSH Configuration:" | tee -a /var/log/security_audit_final.log
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  systemctl reload sshd

  echo "2. Disabling IPv6 if not required:" | tee -a /var/log/security_audit_final.log
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  sysctl -p | tee -a /var/log/security_audit_final.log

  echo "3. Securing the bootloader:" | tee -a /var/log/security_audit_final.log
  grub-mkpasswd-pbkdf2
  # Add the password hash to /etc/grub.d/40_custom and update-grub

  echo "4. Configuring automatic updates:" | tee -a /var/log/security_audit_final.log
  apt-get install unattended-upgrades -y
  dpkg-reconfigure --priority=low unattended-upgrades | tee -a /var/log/security_audit_final.log
}

# Function to report and alert based on the audit and hardening process
report_and_alert() {
  echo "Generating Report and Alerts..."

  # Final report is already being written to /var/log/security_audit_final.log
  echo "Final report saved to /var/log/security_audit_final.log"
  
  # Placeholder for email or notification system
  # mail -s "Security Audit and Hardening Report" admin@example.com < /var/log/security_audit_final.log
}

# Main function to orchestrate the script
main() {
  check_root
  audit_users_and_groups
  audit_file_permissions
  audit_services
  check_firewall_and_network
  check_ip_network_configs
  apply_security_updates
  monitor_logs
  server_hardening

  report_and_alert
}

# Execute main function
main
