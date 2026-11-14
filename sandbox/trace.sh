#!/bin/sh
# Phases 1 and 2: run the package's code under strace, with the network gone.
#
#   trace.sh <timeout-seconds>
#
# Runs as root so that the evidence lands in /probe, which the observed code
# cannot write to. The code itself runs as the unprivileged user `dev`
# (`strace -u`), without any capabilities.
set -u
limit="$1"
# Copied here by the orchestrator before any package code had a chance to run.
name=$(cat /probe/name)

export HOME=/home/dev USER=dev LOGNAME=dev

SYSCALLS=execve,execveat,clone,clone3,fork,vfork,chdir,connect,sendto,sendmsg,sendmmsg
SYSCALLS=$SYSCALLS,open,openat,openat2,creat,unlink,unlinkat,rmdir,rename,renameat,renameat2
SYSCALLS=$SYSCALLS,chmod,fchmodat,truncate,mkdir,mkdirat,link,linkat,symlink,symlinkat

now() { date +%s%3N; }

# observe <phase> <command...>
observe() {
    phase="$1"
    shift
    start=$(now)
    timeout -k 5 "$limit" strace -u dev -f -qq -y -s 256 -e trace="$SYSCALLS" -o "/probe/$phase.trace" "$@" \
        > "/probe/$phase.log" 2>&1
    echo $? > "/probe/$phase.rc"
    echo "$phase $start $(now)" >> /probe/times
}

cd /work
: > /probe/times

# Phase 1: lifecycle scripts of the package and everything it pulled in.
observe install npm rebuild --foreground-scripts

# Phase 2: load the entry point. Works for CommonJS and ES modules alike;
# the short wait gives deferred code (timers, microtasks) a chance to act.
target="${name:-node:path}"
observe import node -e '
const done = () => setTimeout(() => process.exit(0), 2000);
import(process.argv[1]).then(done, done);
' "$target"
