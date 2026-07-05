#!/bin/bash

# VEX - Vulnerability Explorer Kurulum Scripti
# Kali Linux ve benzeri Debian tabanlı sistemler için

echo "██╗   ██╗███████╗██╗  ██╗"
echo "██║   ██║██╔════╝╚██╗██╔╝"
echo "██║   ██║█████╗   ╚███╔╝ "
echo "╚██╗ ██╔╝██╔══╝   ██╔██╗ "
echo " ╚████╔╝ ███████╗██╔╝ ██╗"
echo "  ╚═══╝  ╚══════╝╚═╝  ╚═╝"
echo "VEX - Vulnerability Explorer"
echo ""

# Python 3 ve pip kontrolü
echo "[*] Python 3 ve pip kontrol ediliyor..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 bulunamadı! Kuruluyor..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    echo "[+] Python 3 bulundu"
fi

# Proje dizinine git
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Gerekli paketleri yükle (pip install -e .)
echo "[*] Gerekli Python paketleri yükleniyor..."
pip3 install -e .

# (Opsiyonel) AI özellikleri için openai yükle
echo ""
read -p "AI (OpenAI) özelliklerini yüklemek istiyor musun? (e/H): " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[EeYy]$ ]]; then
    echo "[*] OpenAI bağımlılıkları yükleniyor..."
    pip3 install -e ".[ai]"
fi

echo ""
echo "[+] Kurulum tamamlandı!"
echo "[*] Yardım için: vex -h"
echo "[*] Kullanım örneği: vex -u https://ornek.site"
echo ""
echo "[*] (İpucu: .env.example dosyasını .env olarak kopyalayıp düzenleyerek AI motorunu yapılandırabilirsiniz!)"
