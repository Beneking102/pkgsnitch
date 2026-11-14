#!/bin/sh
# Phase 0: download the package and its dependencies WITHOUT running any of
# their code. This is the only step that has network access.
#
#   fetch.sh npm left-pad@1.3.0        a registry package
#   fetch.sh npm /tmp/target.tgz       a local tarball copied into the sandbox
#   fetch.sh pypi requests==2.32.3
#   fetch.sh <ecosystem> ""            the empty baseline project
set -eu
ecosystem="$1"
spec="$2"

cd /work

if [ "$ecosystem" = pypi ]; then
    exec timeout -k 5 300 python3 /opt/pkgsnitch/pyfetch.py "$spec"
fi

printf '{"name":"pkgsnitch-probe","version":"0.0.0","private":true}\n' > package.json

name=""
if [ -n "$spec" ]; then
    timeout -k 5 300 npm install --ignore-scripts --no-audit --no-fund --loglevel=error -- "$spec"
    # npm recorded the package's real name as our only direct dependency.
    name=$(node -p 'Object.keys(require("/work/package.json").dependencies || {})[0] || ""')
fi
printf '%s' "$name" > /out/name

if [ -f package-lock.json ]; then cp package-lock.json /out/lock.json; else echo '{}' > /out/lock.json; fi
if [ -n "$name" ] && [ -f "node_modules/$name/package.json" ]; then
    cp "node_modules/$name/package.json" /out/manifest.json
else
    echo '{}' > /out/manifest.json
fi
