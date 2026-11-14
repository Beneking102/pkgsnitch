#!/bin/sh
# Phases 1 and 2: run the package's code under strace, with the network gone.
#
#   trace.sh <timeout-seconds> <install|import> <npm|pypi>
#
# Runs as root so that the evidence lands in /probe, which the observed code
# cannot write to. The code itself runs as the unprivileged user `dev`
# (`strace -u`), without any capabilities.
set -u
limit="$1"
phase="$2"
ecosystem="$3"
# Copied here by the orchestrator before any package code had a chance to run.
name=$(cat /probe/name)

export HOME=/home/dev USER=dev LOGNAME=dev

# Secrets in the environment, where CI systems put them. They carry the same
# marker as the honeytoken files (see src/canary.rs).
CANARY=pkgsnitchCanary7f3a9c51d2
export NPM_TOKEN="npm_$CANARY" NODE_AUTH_TOKEN="npm_$CANARY"
export GITHUB_TOKEN="ghp_$CANARY" GH_TOKEN="ghp_$CANARY"
export AWS_ACCESS_KEY_ID=AKIAPKGSNITCHHONEY00 AWS_SECRET_ACCESS_KEY="$CANARY"
export TWINE_USERNAME=__token__ TWINE_PASSWORD="pypi-$CANARY"

SYSCALLS=execve,execveat,clone,clone3,fork,vfork,chdir,connect,sendto,sendmsg,sendmmsg
SYSCALLS=$SYSCALLS,open,openat,openat2,creat,unlink,unlinkat,rmdir,rename,renameat,renameat2
SYSCALLS=$SYSCALLS,chmod,fchmodat,truncate,mkdir,mkdirat,link,linkat,symlink,symlinkat

now() { date +%s%3N; }

# observe <command...>
observe() {
    start=$(now)
    timeout -k 5 "$limit" strace -u dev -f -qq -y -s 256 -e trace="$SYSCALLS" -o "/probe/$phase.trace" "$@" \
        > "/probe/$phase.log" 2>&1
    echo $? > "/probe/$phase.rc"
    echo "$phase $start $(now)" >> /probe/times
}

cd /work

case "$ecosystem-$phase" in
npm-install)
    # Lifecycle scripts of the package and everything it pulled in.
    observe npm rebuild --foreground-scripts
    ;;
npm-import)
    # Load the entry point. Works for CommonJS and ES modules alike; the
    # short wait gives deferred code (timers, microtasks) a chance to act.
    observe node -e '
const done = () => setTimeout(() => process.exit(0), 2000);
import(process.argv[1]).then(done, done);
' "${name:-node:path}"
    ;;
pypi-install)
    # Offline install from what the fetch downloaded. For a wheel this only
    # unpacks files; for a source distribution it runs the build script.
    nodeps=""
    [ -n "$(cat /probe/nodeps)" ] && nodeps="--no-deps"
    observe /work/venv/bin/pip install --disable-pip-version-check --no-input --no-cache-dir \
        --no-index --find-links /work/wheels $nodeps "$(cat /probe/pipspec)"
    ;;
pypi-import)
    # The module names are read from the installed metadata by the system
    # interpreter in isolated mode, so nothing of the package runs untraced.
    modules=$(python3 -I -S /opt/pkgsnitch/pymodules.py "$name")
    # shellcheck disable=SC2086
    observe /work/venv/bin/python -c '
import importlib, sys, time
for module in sys.argv[1:]:
    try:
        importlib.import_module(module)
    except BaseException:
        pass
time.sleep(2)
' $modules
    ;;
*)
    echo "unknown phase: $ecosystem-$phase" >&2
    exit 2
    ;;
esac
