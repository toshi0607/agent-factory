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
archives=("$delivery/product.tar.gz")
if [[ ${FACTORY_GO_ROOT+x} ]]; then
  go_bin="$FACTORY_GO_ROOT/bin"
  if [[ -z "$FACTORY_GO_ROOT" || ! -x "$go_bin/go" || ! -f "$go_bin/go" ]]; then
    printf 'FACTORY_GO_ROOT must contain an executable bin/go\n' >&2
    exit 1
  fi
  version="$(python3 - "$delivery/manifest.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    files = json.load(stream)["files"]
versions = [match[1] for entry in files if
            (match := re.fullmatch(r"(go[A-Za-z0-9.]+)\.linux-amd64\.tar\.gz", entry["name"]))]
if len(versions) != 1:
    sys.exit("Expected exactly one Go toolchain entry in the manifest")
print(versions[0])
PY
)"
  if ! installed="$(GOTOOLCHAIN=local "$go_bin/go" version)" || [[ " $installed " != *" $version "* ]]; then
    printf 'Installed Go version does not match manifest version %s\n' "$version" >&2
    exit 1
  fi
else
  toolchains=("$delivery"/go*.linux-amd64.tar.gz)
  if (( ${#toolchains[@]} != 1 )); then
    printf 'Expected exactly one Go toolchain archive\n' >&2
    exit 1
  fi
  archives+=("${toolchains[0]}")
  go_bin="$work/toolchain/go/bin"
fi
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

if [[ ${FACTORY_GO_ROOT+x} ]]; then
  mkdir -- "$work/base" "$work/product"
else
  mkdir -- "$work/base" "$work/product" "$work/toolchain"
fi
tar -xzf "${archives[0]}" -C "$work/base"
tar -xzf "${archives[0]}" -C "$work/product"
chmod -R a-w "$work/base"
if [[ ! ${FACTORY_GO_ROOT+x} ]]; then
  tar -xzf "${toolchains[0]}" -C "$work/toolchain"
fi
if [[ -f "$delivery/modproxy.tar.gz" ]]; then
  tar -xzf "$delivery/modproxy.tar.gz" -C "$work"
fi

{
  printf 'export PATH=%q:"$PATH"\n' "$go_bin"
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
