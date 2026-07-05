#!/usr/bin/env python3
import sys
from pathlib import Path

# Proje kök dizinini Python yoluna ekle
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from vex.__main__ import main

if __name__ == "__main__":
    main()
