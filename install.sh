#!/bin/bash
# VEX - Vulnerability Explorer
# Kali Linux / Linux Installation Script
# ============================================

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
    echo -e "${RED}[!] Python3 bulunamadi!${NC}"
    echo -e "${YELLOW}  Cozum: sudo apt install python3${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] Python3: $(python3 --version)${NC}"

# Check/install pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!] pip3 bulunamadi, kuruluyor...${NC}"
    sudo apt update && sudo apt install -y python3-pip
fi
echo -e "${GREEN}[✔] pip3: $(pip3 --version 2>&1 | head -1)${NC}"

# Check venv
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}[!] Sanal ortam (venv) aktif degil.${NC}"
    echo -e "${YELLOW}  Onerilen: python3 -m venv .venv && source .venv/bin/activate${NC}"
    echo -e "${YELLOW}  Devam etmek icin Enter, iptal icin Ctrl+C${NC}"
    read -r
fi

# Upgrade pip
echo -e "${CYAN}[*] pip guncelleniyor...${NC}"
pip3 install --upgrade pip -q

# Install dependencies
echo -e "${CYAN}[*] Bagimliliklar yukleniyor...${NC}"
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Bagimliliklar yuklenemedi!${NC}"
    echo -e "${YELLOW}  Cozum: pip3 install requests beautifulsoup4 colorama python-dotenv${NC}"
    pip3 install requests beautifulsoup4 colorama python-dotenv
fi
echo -e "${GREEN}[✔] Bagimliliklar yuklendi${NC}"

# Install VEX
echo -e "${CYAN}[*] VEX yukleniyor...${NC}"
pip3 install -e .
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] 'pip install -e .' basarisiz, alternatif yontem deneniyor...${NC}"
    # Fallback: just install deps + make module available
    python3 -c "
import sys
sys.path.insert(0, '.')
from vex.__main__ import main
print('[✔] VEX dogrudan calisiyor')
"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] VEX kullanima hazir (pip paketi olmadan)${NC}"
        echo -e "${YELLOW}  Kullanim: python3 -m vex -u https://site.com${NC}"
    fi
fi

# Verify installation
echo -e "${CYAN}[*] VEX test ediliyor...${NC}"
python3 -m vex --version &> /dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✔] VEX basariyla kuruldu!${NC}"
else
    # Try fallback
    python3 -c "import vex; print(f'VEX v{vex.__version__}')" &> /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] VEX modulu import edilebiliyor${NC}"
        echo -e "${YELLOW}  Kullanim: python3 -m vex -u https://site.com${NC}"
    else
        echo -e "${RED}[!] VEX kurulamadi!${NC}"
        echo -e "${YELLOW}  Manuel kurulum:${NC}"
        echo -e "${YELLOW}    1. python3 -m venv .venv${NC}"
        echo -e "${YELLOW}    2. source .venv/bin/activate${NC}"
        echo -e "${YELLOW}    3. pip3 install -r requirements.txt${NC}"
        echo -e "${YELLOW}    4. pip3 install -e .${NC}"
        echo -e "${YELLOW}    5. vex -u https://site.com${NC}"
        exit 1
    fi
fi

# Optional: AI extras
echo ""
echo -e "${YELLOW}[?] AI motoru (OpenAI) kurulsun mu? [e/H]${NC}"
read -r answer
if [[ "$answer" =~ ^[Ee]$ ]]; then
    echo -e "${CYAN}[*] AI motoru yukleniyor...${NC}"
    pip3 install openai
    echo -e "${GREEN}[✔] AI motoru kuruldu${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  VEX basariyla kuruldu!                     ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Kullanim:                                  ║${NC}"
echo -e "${GREEN}║    vex -u https://hedef-site.com            ║${NC}"
echo -e "${GREEN}║    vex -u https://site.com --type sqli xss  ║${NC}"
echo -e "${GREEN}║    vex --help-vulns                         ║${NC}"
echo -e "${GREEN}║    vex --help-tools                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Yardim: vex -h                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
