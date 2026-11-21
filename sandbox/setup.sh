#!/usr/bin/env bash
set -euo pipefail

delivery="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
work="${FACTORY_WORK_DIR:-/tmp/factory}"
mkdir -p -- "$work"
work="$(cd -- "$work" && pwd -P)"
if [[ -e "$work/product" || -L "$work/product" ]]; then
  printf 'Product directory already exists: %s\n' "$work/product" >&2
  exit 1
fi

shopt -s nullglob
toolchains=("$delivery"/go*.linux-amd64.tar.gz)
if (( ${#toolchains[@]} != 1 )); then
  printf 'Expected exactly one Go toolchain archive\n' >&2
  exit 1
fi
archives=("$delivery/product.tar.gz" "${toolchains[0]}")
proxy=https://proxy.golang.org
if [[ -f "$delivery/modproxy.tar.gz" ]]; then
  archives+=("$delivery/modproxy.tar.gz")
  proxy="file://$work/modproxy,$proxy"
fi

for archive in "${archives[@]}"; do
  name="${archive##*/}"
  if command -v python3 >/dev/null; then
    hash="$(python3 - "$delivery/manifest.json" "$name" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    files = json.load(stream)["files"]
matches = [entry["sha256"] for entry in files if entry["name"] == sys.argv[2]]
if len(matches) != 1:
    sys.exit("Expected one manifest entry for " + sys.argv[2])
print(matches[0])
PY
)"
  else
    hash="$(grep -F "\"name\":\"$name\"," "$delivery/manifest.json" |
      sed -nE 's/.*"sha256":"([[:xdigit:]]{64})".*/\1/p')"
  fi
  if [[ ! "$hash" =~ ^[[:xdigit:]]{64}$ ]]; then
    printf 'Invalid manifest checksum for %s\n' "$name" >&2
    exit 1
  fi
  printf '%s  %s\n' "$hash" "$name" | (cd -- "$delivery" && sha256sum -c -)
done

mkdir -- "$work/base" "$work/product" "$work/toolchain"
tar -xzf "${archives[0]}" -C "$work/base"
tar -xzf "${archives[0]}" -C "$work/product"
chmod -R a-w "$work/base"
tar -xzf "${toolchains[0]}" -C "$work/toolchain"
if [[ -f "$delivery/modproxy.tar.gz" ]]; then
  tar -xzf "$delivery/modproxy.tar.gz" -C "$work"
fi

{
  printf 'export PATH=%q:"$PATH"\n' "$work/toolchain/go/bin"
  printf 'export GOTOOLCHAIN=local\n'
  printf 'export GOCACHE=%q\n' "$work/gocache"
  printf 'export GOMODCACHE=%q\n' "$work/gomodcache"
  printf 'export GOSUMDB=sum.golang.org\n'
  printf 'export GOPROXY=%q\n' "$proxy"
} > "$work/env.sh"

if command -v git >/dev/null; then
  git -C "$work/product" init --quiet
  # The archive may contain tracked files that also match ignore rules.
  git -C "$work/product" add -f -A
  git -C "$work/product" -c core.hooksPath=/dev/null -c commit.gpgsign=false \
    -c user.name='Agent Factory' -c user.email='factory@example.invalid' \
    commit --quiet --allow-empty -m baseline
fi

printf 'Product: %s\nTask: %s\nsource %q\n' "$work/product" "$delivery/task.md" "$work/env.sh"
