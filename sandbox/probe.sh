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

  printf '== summary\n'
  printf 'platform_env_present: %s\n' "${platform_present[*]:-none}"
  printf 'no_credential_env %s\n' "$no_credential_env"
  printf 'no_credential_files %s\n' "$no_credential_files"
  printf 'allowed_hosts_reachable %s\n' "$allowed_hosts_reachable"
  printf 'other_hosts_blocked %s\n' "$other_hosts_blocked"
  printf '== done\n'
} > "$out/probe.txt" 2>/dev/null
exit 0
