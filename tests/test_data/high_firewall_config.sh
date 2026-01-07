#!/usr/bin/env bash
# High risk script - Firewall configuration utility
# Modifies iptables rules - improper use can lock you out of the system
# WARNING: Incorrect configuration may block all network access

set -e

ACTION="${1:-status}"
SSH_PORT="${SSH_PORT:-22}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

echo "========================================="
echo "     FIREWALL CONFIGURATION UTILITY      "
echo "========================================="
echo ""
echo "WARNING: This script modifies firewall rules."
echo "Incorrect usage may result in loss of network access."
echo ""

show_status() {
    echo "--- Current iptables rules ---"
    iptables -L -n -v 2>/dev/null || echo "Unable to read iptables (need root?)"
    echo ""
    echo "--- Current connections ---"
    ss -tuln 2>/dev/null | head -20
}

configure_basic_firewall() {
    echo "Configuring basic firewall rules..."
    
    # Flush existing rules
    iptables -F
    iptables -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (critical - don't lock yourself out!)
    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
    
    # Allow HTTP/HTTPS
    iptables -A INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTPS_PORT -j ACCEPT
    
    # Allow ping
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    echo "Basic firewall configured successfully"
    echo "Allowed ports: SSH($SSH_PORT), HTTP($HTTP_PORT), HTTPS($HTTPS_PORT)"
}

disable_firewall() {
    echo "Disabling firewall (allowing all traffic)..."
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    echo "Firewall disabled - all traffic allowed"
}

case "$ACTION" in
    status)
        show_status
        ;;
    configure)
        configure_basic_firewall
        ;;
    disable)
        disable_firewall
        ;;
    *)
        echo "Usage: $0 {status|configure|disable}"
        echo ""
        echo "Commands:"
        echo "  status    - Show current firewall rules"
        echo "  configure - Apply basic firewall configuration"
        echo "  disable   - Disable firewall (allow all)"
        exit 1
        ;;
esac

echo ""
echo "Operation completed."
