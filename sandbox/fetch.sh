#!/bin/sh
# Phase 0: download the package and its dependencies WITHOUT running any of
# their code. This is the only step that has network access.
#
#   fetch.sh left-pad@1.3.0        a registry package
#   fetch.sh /tmp/target.tgz       a local tarball copied into the sandbox
#   fetch.sh ""                    the empty baseline project
set -eu
spec="$1"

cd /work
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
