#!/usr/bin/env bash
# Low risk script - Simple system information display
# Safe for general use

echo "========================================="
echo "        SYSTEM INFORMATION REPORT        "
echo "========================================="
echo ""

echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "Date: $(date)"
echo ""

echo "--- Operating System ---"
if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo "OS: $PRETTY_NAME"
fi
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""

echo "--- Memory Usage ---"
free -h 2>/dev/null || echo "Memory info not available"
echo ""

echo "--- Disk Usage ---"
df -h / 2>/dev/null | tail -1
echo ""

echo "--- CPU Info ---"
if [ -f /proc/cpuinfo ]; then
    grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs
    echo "Cores: $(nproc)"
fi
echo ""

echo "--- Uptime ---"
uptime
echo ""

echo "========================================="
echo "        Report completed successfully    "
echo "========================================="
