#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'usage: %s <tree> <out-dir>\n' "$0" >&2
    exit 14
fi

tree=$1
out=$2
mkdir -p -- "$out" || exit 14
out=$(cd -- "$out" && pwd -P) || exit 14
cd -- "$tree" || exit 14

# Permit the caller's local file proxy, or use the existing module cache only.
case ${GOPROXY:-off} in
    *','*|*'|'*) export GOPROXY=off ;;
    file://*) export GOPROXY ;;
    *) export GOPROXY=off ;;
esac
export GOTOOLCHAIN=local GONOPROXY=none GOSUMDB=off

if ! command -v go >/dev/null; then
    printf 'go is required for the build\n' >&2
    exit 14
fi
exec 3>"$out/build.log" || exit 14
if ! go build -buildvcs=false -o "$out/emulator" ./cmd/google-cloud-emulator >&3 2>&1; then
    exit 11
fi
