#!/usr/bin/env python3
import sys
from urllib.parse import urljoin

try:
    # Read base + rel from stdin (not command line)
    data = sys.stdin.read().strip().splitlines()
    if len(data) < 2:
        print("", end="")
        exit(0)
    base = data[0].strip()
    rel = data[1].strip()

    # Resolve
    result = urljoin(base, rel)
    print(result)
except Exception:
    print("", end="")
