#!/bin/sh
# Phases 1 and 2: run the package's code under strace, with the network gone.
#
#   trace.sh <timeout-seconds>
set -u
limit="$1"
# Written by fetch.sh, before any package code had a chance to run.
name=$(cat /out/name)

/opt/pkgsnitch/honey.sh

SYSCALLS=execve,execveat,clone,clone3,fork,vfork,chdir,connect,sendto,sendmsg,sendmmsg
SYSCALLS=$SYSCALLS,open,openat,openat2,creat,unlink,unlinkat,rmdir,rename,renameat,renameat2
SYSCALLS=$SYSCALLS,chmod,fchmodat,truncate,mkdir,mkdirat,link,linkat,symlink,symlinkat

now() { date +%s%3N; }

# observe <phase> <command...>
observe() {
    phase="$1"
    shift
    start=$(now)
    timeout -k 5 "$limit" strace -f -qq -y -s 256 -e trace="$SYSCALLS" -o "/out/$phase.trace" "$@" \
        > "/out/$phase.log" 2>&1
    echo $? > "/out/$phase.rc"
    echo "$phase $start $(now)" >> /out/times
}

cd /work
: > /out/times

# Phase 1: lifecycle scripts of the package and everything it pulled in.
observe install npm rebuild --foreground-scripts

# Phase 2: load the entry point. Works for CommonJS and ES modules alike;
# the short wait gives deferred code (timers, microtasks) a chance to act.
target="${name:-node:path}"
observe import node -e '
const done = () => setTimeout(() => process.exit(0), 2000);
import(process.argv[1]).then(done, done);
' "$target"
