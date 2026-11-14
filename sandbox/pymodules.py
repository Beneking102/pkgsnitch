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


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def modules(info):
    top_level = os.path.join(info, "top_level.txt")
    if os.path.exists(top_level):
        with open(top_level) as handle:
            return [line.strip() for line in handle if line.strip()]
    # No top_level.txt: derive the names from the list of installed files.
    names = []
    with open(os.path.join(info, "RECORD")) as handle:
        for line in handle:
            first = line.split(",")[0].split("/")[0]
            name = first[:-3] if first.endswith(".py") else first
            if name.isidentifier() and name not in names and "." not in first.replace(".py", ""):
                names.append(name)
    return names


for info in glob.glob("/work/venv/lib/python*/site-packages/*.dist-info"):
    with open(os.path.join(info, "METADATA"), errors="replace") as handle:
        declared = next((line[5:].strip() for line in handle if line.lower().startswith("name:")), "")
    if normalize(declared) == wanted:
        print(" ".join(m for m in modules(info) if m.isidentifier()))
        break
