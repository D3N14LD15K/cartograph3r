#!/usr/bin/env python3
import sys
from urllib.parse import urljoin

if len(sys.argv) != 3:
    print("", end="")
    exit(0)

base = sys.argv[1].strip()
rel = sys.argv[2].strip()

try:
    result = urljoin(base, rel)
    print(result)
except Exception:
    print("", end="")
