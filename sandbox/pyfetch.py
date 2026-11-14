#!/usr/bin/env python3
"""Fetch phase for PyPI: download a package without running any of its code.

    pyfetch.py requests==2.32.3     a registry package
    pyfetch.py ""                   the empty baseline

pip only runs package code when it has to build a source distribution, so
wheels are downloaded with `--only-binary`. A package that ships no wheel is
fetched as the plain source archive; its build script then runs later, in
the observed install phase, which is exactly where an attack would live.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile

WHEELS = "/work/wheels"
OUT = "/out"
PIP = ["/work/venv/bin/pip", "--disable-pip-version-check", "--no-input"]
BASELINE = ("pkgsnitch_baseline", "1.0.0")


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def write(name, text):
    with open(os.path.join(OUT, name), "w") as handle:
        handle.write(text)


def baseline_wheel():
    """A do-nothing package, so the baseline exercises a real pip install."""
    name, version = BASELINE
    info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(f"{WHEELS}/{name}-{version}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"{name}/__init__.py", "")
        wheel.writestr(f"{info}/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        wheel.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\nGenerator: pkgsnitch\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        wheel.writestr(f"{info}/top_level.txt", f"{name}\n")
        wheel.writestr(f"{info}/RECORD", "")


def download_wheels(*requirements, deps=True):
    command = PIP + ["download", "--quiet", "--only-binary=:all:", "--dest", WHEELS]
    if not deps:
        command.append("--no-deps")
    return subprocess.run(command + list(requirements)).returncode == 0


def download_sdist(name, version):
    """Take the source archive straight from the index, untouched."""
    url = f"https://pypi.org/pypi/{name}/json" if version is None else f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=60) as response:
        release = json.load(response)
    for candidate in release["urls"]:
        if candidate["packagetype"] == "sdist":
            urllib.request.urlretrieve(candidate["url"], os.path.join(WHEELS, candidate["filename"]))
            return
    sys.exit(f"{name}: the index offers neither a usable wheel nor a source distribution")


def downloaded():
    """Every archive in the wheel directory as (name, version, is_sdist)."""
    for filename in sorted(os.listdir(WHEELS)):
        if filename.endswith(".whl"):
            dist, version = filename.split("-")[:2]
            yield normalize(dist), version, False
        else:
            stem = re.sub(r"\.(tar\.gz|tar\.bz2|zip|tgz)$", "", filename)
            dist, _, version = stem.rpartition("-")
            yield normalize(dist), version, True


def main():
    spec = sys.argv[1]
    os.makedirs(WHEELS, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", "/work/venv"], check=True)

    if not spec:
        baseline_wheel()
        write("name", "")
        write("pipspec", "==".join(BASELINE))
        write("nodeps", "")
        write("lock.json", "{}")
        write("manifest.json", "{}")
        return

    if spec.startswith("file:"):
        # A local archive, already copied next to the downloads.
        local = os.path.join(WHEELS, spec[len("file:"):])
        wanted, version, local_sdist = next(entry for entry in downloaded())
        name = wanted
        # A wheel names its dependencies in plain metadata; a source
        # distribution only reveals them by running, so it gets none.
        with_deps = not local_sdist and download_wheels(local)
        if local_sdist:
            download_wheels("setuptools", "wheel")
        return record(name, wanted, with_deps, install=local)

    name, _, version = spec.partition("==")
    wanted = normalize(name)
    with_deps = download_wheels(spec)
    if not with_deps and not download_wheels(spec, deps=False):
        # No wheel at all. The dependencies of a source distribution are only
        # known once its own code has run, so it is installed without them.
        download_sdist(name, version or None)
        download_wheels("setuptools", "wheel")

    record(name, wanted, with_deps)


def record(name, wanted, with_deps, install=None):
    """Write down what was fetched, for the install phase and the report."""
    packages = {}
    target = None
    for dist, found_version, is_sdist in downloaded():
        if dist == wanted:
            target = (found_version, is_sdist)
        elif with_deps:
            packages[dist] = {"version": found_version, "hasInstallScript": is_sdist}
    if target is None:
        sys.exit(f"{name}: nothing was downloaded")

    found_version, is_sdist = target
    scripts = {"install": "source distribution: its build script runs on install"} if is_sdist else {}
    write("name", wanted)
    write("pipspec", install or f"{name}=={found_version}")
    write("nodeps", "" if with_deps else "1")
    write("lock.json", json.dumps({"packages": packages}))
    write("manifest.json", json.dumps({"version": found_version, "scripts": scripts}))


if __name__ == "__main__":
    main()
