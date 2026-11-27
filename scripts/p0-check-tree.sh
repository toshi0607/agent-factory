#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    printf 'usage: %s <tree> <task-id> <p0check-binary> <out-dir>\n' "$0" >&2
    exit 14
fi

tree=$1
task=$2
p0check=$3
out=$4
if [[ $p0check != /* ]]; then
    p0check="$PWD/$p0check"
fi
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd -P)
cd -- "$tree"

# Permit the caller's local file proxy, or use the existing module cache only.
case ${GOPROXY:-off} in
    *','*|*'|'*) export GOPROXY=off ;;
    file://*) export GOPROXY ;;
    *) export GOPROXY=off ;;
esac
export GOTOOLCHAIN=local GONOPROXY=none GOSUMDB=off

if ! make gen-only >"$out/gen.log" 2>&1; then
    exit 10
fi

if ! {
    git status --porcelain=v1 -z --untracked-files=all --no-renames |
        while IFS= read -r -d '' entry; do
            printf '%s\n' "${entry:3}"
        done | LC_ALL=C sort >"$out/gen-changed-paths.txt" &&
        git -c core.hooksPath=/dev/null -c core.fsmonitor=false add -A &&
        git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
            diff --cached --binary --no-ext-diff --no-textconv --no-renames HEAD >"$out/gen.diff" &&
        git -c core.hooksPath=/dev/null -c core.fsmonitor=false write-tree >"$out/judged-tree.txt"
} 2>"$out/gen-status.log"; then
    exit 14
fi

if ! go build -buildvcs=false -o "$out/emulator" ./cmd/google-cloud-emulator >"$out/build.log" 2>&1; then
    exit 11
fi

emulator_pid=
stop_emulator() {
    if [[ -n $emulator_pid ]]; then
        kill -KILL "$emulator_pid" 2>/dev/null || true
        wait "$emulator_pid" 2>/dev/null || true
    fi
}
trap stop_emulator EXIT
trap 'exit 14' HUP INT TERM
: >"$out/emulator.log"
"$out/emulator" -addr 127.0.0.1:0 >"$out/emulator.log" 2>"$out/emulator.stderr.log" &
emulator_pid=$!

prefix='google-cloud-emulator listening on '
deadline=$((SECONDS + 20))
addr=
while ((SECONDS < deadline)) && kill -0 "$emulator_pid" 2>/dev/null; do
    while ((SECONDS < deadline)) && IFS= read -r line; do
        if [[ $line == "$prefix"?* ]]; then
            addr=${line#"$prefix"}
            break
        fi
    done <"$out/emulator.log"
    if [[ -n $addr ]]; then
        break
    fi
    sleep 0.1
done
if [[ -z $addr ]] || ! kill -0 "$emulator_pid" 2>/dev/null; then
    exit 12
fi

code=0
"$p0check" -task "$task" -addr "$addr" >"$out/p0check.json" 2>"$out/p0check.log" || code=$?
case $code in
    0|1) exit "$code" ;;
    2) exit 13 ;;
    *) printf 'p0check exited %s\n' "$code" >>"$out/p0check.log"; exit 14 ;;
esac
