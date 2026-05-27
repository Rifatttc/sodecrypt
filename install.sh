#!/data/data/com.termux/files/usr/bin/bash

# Colors
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[1;36m'
W='\033[1;37m'
N='\033[0m'

clear
echo -e "${C}╔══════════════════════════════════════╗${N}"
echo -e "${C}║   SO DECRYPTOR INSTALLER v1.0       ║${N}"
echo -e "${C}╚══════════════════════════════════════╝${N}"

echo -e "${Y}[*] Updating Termux packages...${N}"
pkg update -y && pkg upgrade -y

echo -e "${Y}[*] Installing dependencies...${N}"
pkg install -y python python-pip binutils file clang make git

echo -e "${Y}[*] Installing Python libraries...${N}"
pip install --upgrade pip
pip install pyelftools capstone lief colorama rich pycryptodome

echo -e "${G}[✓] Installation Complete!${N}"
echo -e "${C}[*] Run with: python sodecrypt.py${N}"
