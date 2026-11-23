#!/usr/bin/env bash
set +ex
set -u
set -o pipefail

out="${FACTORY_OUT_DIR:-/mnt/session/outputs}"
mkdir -p -- "$out" 2>/dev/null || exit 0

scan_files() {
  local root=$1 label=$2 file
  [[ -d "$root" ]] || return 0
  find -H "$root" -maxdepth 4 \( -type f -o -type l \) \
    \( -iname '*token*' -o -iname '*credential*' -o -iname '*.pem' -o -iname '*.key' \) -print0 2>/dev/null |
    (
      local status=0
      while IFS= read -r -d '' file; do
        printf '%q -> yes\n' "$label/${file#"$root"/}"
        status=1
      done
      exit "$status"
    )
}

probe_url() {
  local url=$1 code status=0
  code=$(command curl --disable --silent --max-time 15 --output /dev/null --write-out '%{http_code}' -- "$url" 2>/dev/null) || status=$?
  if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then
    printf '%s -> %s\n' "$url" "$code"
    [[ $status == 0 && $code == [23]* ]] && return 0
    return 2
  fi
  printf '%s -> curl error %s\n' "$url" "$status"
  case $status in
    5|6|7|28|35|56|97) return 1 ;;
    *) return 2 ;;
  esac
}

probe_ssh_directory() (
  local entry type metadata marker count=0 scanned=0
  if [[ -z ${HOME:-} || ! -d $HOME/.ssh ]]; then
    printf 'absent\n'
    return
  fi
  shopt -s dotglob nullglob
  for entry in "$HOME"/.ssh/*; do
    ((scanned++ < 50)) || break
    if [[ -L $entry ]]; then
      type=link
    elif [[ -f $entry ]]; then
      type=file
    elif [[ -d $entry ]]; then
      type=dir
    else
      type=other
    fi
    metadata=$(command timeout 2 stat -c 'size %s mode %a' -- "$entry") ||
      metadata=$(command timeout 2 stat -f 'size %z mode %OLp' -- "$entry") || continue
    printf '%q %s %s' "${entry##*/}" "$type" "$metadata"
    if [[ $type == file ]]; then
      marker=no
      if command timeout 2 grep -q -- 'PRIVATE KEY' "$entry"; then
        marker=yes
      fi
      printf ' private_key_marker %s' "$marker"
    fi
    printf '\n'
    ((++count))
  done
  printf 'entries: %s\n' "$count"
)

probe_reachability() {
  local url=$1 response code status=0
  response=$(command curl --disable --silent --max-time 15 --output /dev/null \
    --dump-header - --write-out '%{http_code}\n' -- "$url") || status=$?
  code=${response##*$'\n'}
  if [[ $status != 0 || ! $code =~ ^[1-5][0-9][0-9]$ ]]; then
    printf '%s -> curl error %s\n' "$url" "$status"
    return
  fi
  printf '%s -> %s\n' "$url" "$code"
  # Keep the final response block if curl also receives CONNECT or interim headers.
  LC_ALL=C command timeout 2 awk '
    BEGIN {
      split("server via content-type x-proxy-error", allowed, " ")
      token = ENVIRON["ANTHROPIC_COMMIT_TOKEN"]
    }
    /^HTTP\// {
      for (name in headers) delete headers[name]
      request_id = 0
      next
    }
    {
      colon = index($0, ":")
      if (!colon) next
      name = tolower(substr($0, 1, colon - 1))
      if (name == "request-id") request_id = 1
      for (i = 1; i <= 4; i++) {
        if (name != allowed[i]) continue
        value = substr($0, colon + 1)
        gsub(/[[:cntrl:]]/, " ", value)
        sub(/^ +/, "", value)
        sub(/ +$/, "", value)
        if (token != "" && index(value, token)) value = "[redacted]"
        headers[name] = substr(value, 1, 256)
      }
    }
    END {
      for (i = 1; i <= 4; i++) {
        name = allowed[i]
        if (name in headers) printf "%s %s\n", name, headers[name]
      }
      print "request-id " (request_id ? "present" : "absent")
    }
  ' <<< "${response%$'\n'*}"
}

probe_token_claims() {
  if ! command -v python3 >/dev/null; then
    printf 'claims unavailable\n'
    return
  fi
  command timeout 5 python3 -I - <<'PY' || printf 'claims unavailable\n'
import base64
import binascii
import json
import math
import os
import re
import time

token = os.environ["ANTHROPIC_COMMIT_TOKEN"]
payload = token.split(".")[1]
if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", payload):
    raise SystemExit(0)
try:
    claims = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4), b"-_", validate=True))
except (binascii.Error, ValueError, RecursionError):
    raise SystemExit(0)
if not isinstance(claims, dict):
    raise SystemExit(0)


def report(label, value, limit=256):
    print(label, json.dumps(value).replace(token, "[redacted]")[:limit])


report("claims", sorted(claims), 1024)
for name in ("aud", "scope"):
    value = claims.get(name)
    if isinstance(value, str) or (isinstance(value, list) and all(isinstance(part, str) for part in value)):
        report(name, value)
expiration = claims.get("exp")
if type(expiration) is int or (isinstance(expiration, float) and math.isfinite(expiration)):
    report("exp - now", int(expiration) - int(time.time()))
PY
}

probe_platform_token() {
  local token=${ANTHROPIC_COMMIT_TOKEN-} set=no dots parts=0 prefix=no
  if [[ ${ANTHROPIC_COMMIT_TOKEN+x} ]]; then
    set=yes
    dots=${token//[^.]/}
    parts=$((${#dots} + 1))
    [[ $token == sk-ant-* ]] && prefix=yes
  fi
  printf 'ANTHROPIC_COMMIT_TOKEN\nset %s\nlength %s\nparts %s\nsk-ant- prefix %s\n' \
    "$set" "${#token}" "$parts" "$prefix"
  if ((parts == 3)); then
    probe_token_claims
  fi

  printf 'ANTHROPIC_COMMIT_SIGN_URL\n'
  if [[ ! ${ANTHROPIC_COMMIT_SIGN_URL+x} ]]; then
    printf 'set no\n'
    return
  fi
  printf 'set yes\n'
  local scheme authority
  if [[ $ANTHROPIC_COMMIT_SIGN_URL =~ ^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]+) ]]; then
    scheme=${BASH_REMATCH[1]}
    authority=${BASH_REMATCH[2]##*@}
    if [[ $authority =~ ^(\[[a-fA-F0-9:.]+\]|[a-zA-Z0-9._-]+)(:[0-9]+)?$ ]]; then
      printf 'scheme %s\nhost %s\n' "$scheme" "${BASH_REMATCH[1]}"
    fi
  fi
}

probe_token_request() {
  local label=$1 header=$2 token=${ANTHROPIC_COMMIT_TOKEN-} code
  # A valid HTTP header value cannot span multiple lines.
  [[ $token == *[$'\r\n']* ]] && token=
  code=$(printf '%s%s\n' "$header" "$token" |
    command curl --disable --silent --max-time 15 --output /dev/null --write-out '%{http_code}' \
      --header 'anthropic-version: 2023-06-01' --header @- -- https://api.anthropic.com/v1/models) || :
  [[ $code =~ ^[0-9]{3}$ ]] || code=000
  printf '%s -> %s\n' "$label" "$code"
}

{
  printf '== tools\n'
  for tool in git make curl python3 sha256sum diff go; do
    if ! command -v "$tool" >/dev/null; then
      printf '%s -> not found\n' "$tool"
      continue
    fi
    printf '%s -> found\n' "$tool"
    if [[ $tool == go ]]; then
      GOTOOLCHAIN=local command go version 2>/dev/null | head -n 1
    else
      command "$tool" --version 2>/dev/null | head -n 1
    fi
  done

  printf '== credential-like environment variable names\n'
  no_credential_env=PASS
  credential_name='key|token|secret|credential|password|anthropic|claude|github|google|gcp|aws|azure|cloudflare|openai'
  # Allow exact names separated by spaces or commas.
  allowlist=${PROBE_ALLOWED_ENV_NAMES:-}
  allowlist=${allowlist//,/ }
  allowlist=${allowlist//$'\n'/ }
  allowlist=${allowlist//$'\t'/ }
  platform_names=${PROBE_PLATFORM_ENV_NAMES-ANTHROPIC_COMMIT_TOKEN ANTHROPIC_COMMIT_SIGN_URL}
  platform_present=()
  while IFS= read -r name; do
    platform=false
    if [[ " $platform_names " == *" $name "* ]]; then
      platform_present+=("$name")
      platform=true
    fi
    shopt -s nocasematch
    if [[ $name =~ $credential_name ]]; then
      printf '%s\n' "$name"
      shopt -u nocasematch
      if [[ $platform == false && " $allowlist " != *" $name "* ]]; then
        no_credential_env=FAIL
      fi
    fi
    shopt -u nocasematch
  done < <(compgen -e | LC_ALL=C sort -u)

  printf '== credential-like files\n'
  no_credential_files=PASS
  home=${HOME:-}
  for file in .netrc .git-credentials .config/gh/hosts.yml .config/gcloud .aws .ssh \
    .docker/config.json .anthropic .claude .codex; do
    if [[ -n $home && ( -e "$home/$file" || -L "$home/$file" ) ]]; then
      printf '~/%s -> yes\n' "$file"
      no_credential_files=FAIL
    else
      printf '~/%s -> no\n' "$file"
    fi
  done
  if ! scan_files /mnt/session /mnt/session; then
    no_credential_files=FAIL
  fi
  if [[ -n $home ]] && ! scan_files "$home" '~'; then
    no_credential_files=FAIL
  fi

  printf '== egress\n'
  allowed_hosts_reachable=PASS
  for url in https://proxy.golang.org/ https://sum.golang.org/latest; do
    probe_url "$url" || allowed_hosts_reachable=FAIL
  done
  other_hosts_blocked=PASS
  for url in https://example.com/ https://github.com/ https://api.github.com/ \
    https://api.anthropic.com/ https://storage.googleapis.com/ https://go.dev/ \
    https://pypi.org/ https://registry.npmjs.org/; do
    status=0
    probe_url "$url" || status=$?
    if [[ $status != 1 ]]; then
      other_hosts_blocked=FAIL
    fi
  done

  printf '== ssh directory\n'
  probe_ssh_directory

  printf '== anthropic api reachability\n'
  for url in https://api.anthropic.com/ https://api.anthropic.com/v1/models https://example.com/; do
    probe_reachability "$url"
  done
  if [[ ${ANTHROPIC_COMMIT_SIGN_URL+x} ]]; then
    # The first line carries the URL; replace it so the path is not reported.
    probe_reachability "$ANTHROPIC_COMMIT_SIGN_URL" | sed '1s|^.* -> |sign url (unauthenticated GET) -> |'
  fi

  printf '== platform token\n'
  probe_platform_token

  printf '== platform token against the api\n'
  if [[ ${ANTHROPIC_COMMIT_TOKEN+x} ]]; then
    probe_token_request bearer 'Authorization: Bearer '
    probe_token_request x-api-key 'x-api-key: '
  else
    printf 'skipped\n'
  fi

  printf '== summary\n'
  printf 'platform_env_present: %s\n' "${platform_present[*]:-none}"
  printf 'no_credential_env %s\n' "$no_credential_env"
  printf 'no_credential_files %s\n' "$no_credential_files"
  printf 'allowed_hosts_reachable %s\n' "$allowed_hosts_reachable"
  printf 'other_hosts_blocked %s\n' "$other_hosts_blocked"
  printf '== done\n'
} > "$out/probe.txt" 2>/dev/null
exit 0
