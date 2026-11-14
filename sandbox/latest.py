#!/usr/bin/env python3
"""Ask package registries for the latest stable version of many packages.

Reads lines of `<registry>\t<name>` on standard input and prints
`<registry>\t<name>\t<version>` for every package a registry knows.
Packages that cannot be looked up are simply left out.

Runs inside the sandbox image, so the host needs nothing but Docker.
"""
import json
import re
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

AGENT = "pkgsnitch (https://github.com/Beneking102/pkgsnitch)"
RAW = "https://raw.githubusercontent.com"


def get(url, accept=None):
    headers = {"User-Agent": AGENT}
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", "replace")


def key(version):
    """Sort key for versions: numeric segments, releases after prereleases."""
    version = version.lstrip("vV").split("+")[0]
    match = re.match(r"[0-9.]*", version)
    numbers = [int(part) for part in match.group(0).strip(".").split(".") if part]
    return (numbers, version[match.end():] == "")


def stable(version):
    """True for a plain release: digits and dots, nothing appended."""
    return re.fullmatch(r"[vV]?\d+(\.\d+)*", version.split("+")[0]) is not None


def newest(versions):
    plain = [v for v in versions if stable(v)]
    return max(plain or list(versions), key=key, default=None)


def npm(name):
    data = json.loads(get(f"https://registry.npmjs.org/{name.replace('/', '%2f')}",
                          accept="application/vnd.npm.install-v1+json"))
    return data["dist-tags"]["latest"]


def pypi(name):
    return json.loads(get(f"https://pypi.org/pypi/{name}/json"))["info"]["version"]


def crates(name):
    crate = json.loads(get(f"https://crates.io/api/v1/crates/{name}"))["crate"]
    return crate.get("max_stable_version") or crate["max_version"]


def packagist(name):
    data = json.loads(get(f"https://repo.packagist.org/p2/{name}.json"))
    return newest(entry["version"] for entry in data["packages"][name])


def rubygems(name):
    return json.loads(get(f"https://rubygems.org/api/v1/versions/{name}/latest.json"))["version"]


def go(name):
    # The module proxy writes capitals as `!` plus the lower-case letter.
    escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
    return json.loads(get(f"https://proxy.golang.org/{escaped}/@latest"))["Version"]


def nuget(name):
    data = json.loads(get(f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json"))
    return newest(data["versions"])


def maven(name):
    group, artifact = name.split(":", 1)
    xml = get(f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/maven-metadata.xml")
    # `<release>` may name a release candidate; prefer the newest plain one.
    return newest(re.findall(r"<version>([^<]+)</version>", xml))


def vcpkg(name):
    data = json.loads(get(f"{RAW}/microsoft/vcpkg/master/versions/{name[0]}-/{name}.json"))
    newest_entry = data["versions"][0]
    for field in ("version", "version-semver", "version-date", "version-string"):
        if field in newest_entry:
            return newest_entry[field]
    return None


def conan(name):
    text = get(f"{RAW}/conan-io/conan-center-index/master/recipes/{name}/config.yml")
    return newest(re.findall(r'^\s+"?([^\s":]+)"?:\s*$', text, re.M))


REGISTRIES = {
    "npm": npm, "pypi": pypi, "crates": crates, "packagist": packagist, "rubygems": rubygems,
    "go": go, "nuget": nuget, "maven": maven, "vcpkg": vcpkg, "conan": conan,
}


def lookup(line):
    registry, _, name = line.partition("\t")
    try:
        version = REGISTRIES[registry](urllib.parse.quote(name, safe="/@:.-_~"))
    except Exception:
        return None
    return f"{registry}\t{name}\t{version.lstrip('vV')}" if version else None


def main():
    wanted = [line.rstrip("\n") for line in sys.stdin if "\t" in line]
    with ThreadPoolExecutor(max_workers=12) as pool:
        for answer in pool.map(lookup, wanted):
            if answer:
                print(answer, flush=True)


if __name__ == "__main__":
    main()
