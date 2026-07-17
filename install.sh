#!/bin/bash
# VEX - Vulnerability Explorer
# Kali Linux / Linux Installation Script

set -e

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "██╗   ██╗███████╗██╗  ██╗"
echo "██║   ██║██╔════╝╚██╗██╔╝"
echo "██║   ██║█████╗   ╚███╔╝ "
echo "╚██╗ ██╔╝██╔══╝   ██╔██╗ "
echo " ╚████╔╝ ███████╗██╔╝ ██╗"
echo "  ╚═══╝  ╚══════╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${GREEN}VEX - Vulnerability Explorer Installer${NC}"
echo -e "${YELLOW}Kali Linux / Linux${NC}"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 is required. Install it with: sudo apt install python3${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Python3 found: $(python3 --version)${NC}"

# Install pip if needed
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!] pip3 not found. Installing...${NC}"
    sudo apt update && sudo apt install -y python3-pip
fi

# Install dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

# Install VEX
echo -e "${CYAN}[*] Installing VEX...${NC}"
pip3 install -e .

# Optional: install AI extras
echo ""
echo -e "${YELLOW}[?] Install AI engine support (OpenAI)? [y/N]${NC}"
read -r answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    pip3 install -e ".[ai]"
    echo -e "${GREEN}[+] AI engine installed${NC}"
fi

# Optional: install recommended tools
echo ""
echo -e "${YELLOW}[?] Install recommended security tools (sqlmap, nuclei, etc.)? [y/N]${NC}"
read -r answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}[*] Installing tools...${NC}"
    if command -v apt &> /dev/null; then
        sudo apt install -y sqlmap
        # Nuclei
        if ! command -v nuclei &> /dev/null; then
            echo -e "${CYAN}[*] Installing nuclei...${NC}"
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || \
                wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip && \
                unzip -o nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/ && rm nuclei_linux_amd64.zip
        fi
    fi
    echo -e "${GREEN}[+] Security tools installed${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  VEX installed successfully!          ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Usage: vex -u https://target.com     ║${NC}"
echo -e "${GREEN}║  Help:  vex -h                        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
