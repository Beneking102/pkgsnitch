#!/usr/bin/env python3
"""Ask PyPI which versions of each package exist.

    pyversions.py <name>...

Prints one line per known package: its name, a tab, and a JSON object with
the latest version and all versions that have not been withdrawn. This is
the same shape pkgsnitch reads from `npm view`.
"""
import json
import sys
import urllib.request

for name in sys.argv[1:]:
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as response:
            package = json.load(response)
    except Exception:
        continue
    versions = [
        version
        for version, files in package.get("releases", {}).items()
        if files and not all(f.get("yanked") for f in files)
    ]
    answer = {"dist-tags.latest": package["info"]["version"], "versions": versions}
    print(f"{name}\t{json.dumps(answer)}")
