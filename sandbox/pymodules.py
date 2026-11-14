#!/usr/bin/env python3
"""Print the importable top-level modules of an installed distribution.

    pymodules.py <normalized-name>

Reads the installed metadata as plain files. It is run with the system
interpreter and `-I -S`, so nothing from the observed environment (not even
a `.pth` file) executes while it looks.
"""
import glob
import os
import re
import sys

wanted = sys.argv[1] or "pkgsnitch-baseline"
SITE = "/work/venv/lib/python*/site-packages"


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_name(info):
    # Wheels leave a `.dist-info` with METADATA; a source distribution
    # installed the old way leaves an `.egg-info` with PKG-INFO.
    for metadata in ("METADATA", "PKG-INFO"):
        path = os.path.join(info, metadata)
        if os.path.isfile(path):
            with open(path, errors="replace") as handle:
                for line in handle:
                    if line.lower().startswith("name:"):
                        return line[5:].strip()
    return ""


def modules(info):
    top_level = os.path.join(info, "top_level.txt")
    if os.path.exists(top_level):
        with open(top_level) as handle:
            return [line.strip() for line in handle if line.strip()]
    # No top_level.txt: derive the names from the list of installed files.
    names = []
    record = os.path.join(info, "RECORD")
    if os.path.exists(record):
        with open(record) as handle:
            for line in handle:
                first = line.split(",")[0].split("/")[0]
                name = first[:-3] if first.endswith(".py") else first
                if name.isidentifier() and name not in names:
                    names.append(name)
    return names


for info in sorted(glob.glob(f"{SITE}/*.dist-info") + glob.glob(f"{SITE}/*.egg-info")):
    if os.path.isdir(info) and normalize(declared_name(info)) == wanted:
        print(" ".join(m for m in modules(info) if m.isidentifier()))
        break
