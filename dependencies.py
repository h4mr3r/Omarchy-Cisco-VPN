#!/usr/bin/env python3
"""Report missing system packages without importing optional VPN dependencies."""

import json
import subprocess
import sys


PACKAGES = ("networkmanager-openconnect", "python-gobject")


def missing_packages():
    result = subprocess.run(
        ["pacman", "-Qq"], capture_output=True, text=True, timeout=10, check=True
    )
    installed = set(result.stdout.splitlines())
    return [package for package in PACKAGES if package not in installed]


if __name__ == "__main__":
    try:
        print(json.dumps({"ok": True, "missing": missing_packages()}))
    except (OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "error": "Could not check installed packages"}))
        sys.exit(1)
