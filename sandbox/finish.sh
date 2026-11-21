#!/usr/bin/env bash
set -euo pipefail

work="${FACTORY_WORK_DIR:-/tmp/factory}"
out="${FACTORY_OUT_DIR:-/mnt/session/outputs}"
mkdir -p -- "$out"
out="$(cd -- "$out" && pwd -P)"
cd -- "$work"

temp="$(mktemp -d "$PWD/.finish.XXXXXXXX")"
trap 'rm -rf -- "$temp"' EXIT

git_patch() {
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
  local product="$PWD/product" nested
  nested="$(find product -name .git -prune ! -path product/.git -print)" || return
  if [[ -n "$nested" ]]; then
    # Stage nested repository contents as ordinary files without their Git metadata.
    mkdir -- "$temp/product" || return
    tar --exclude=.git -cf - -C "$product" . | tar -xf - -C "$temp/product" || return
    product="$temp/product"
  fi
  local baseline=(git --git-dir="$temp/repo" --work-tree="$PWD/base")
  local current=(git --git-dir="$temp/repo" --work-tree="$product")
  "${baseline[@]}" init --quiet --template= || return
  # The archive can include tracked files that match ignore rules.
  "${baseline[@]}" add -f -A || return
  "${baseline[@]}" -c core.hooksPath=/dev/null -c commit.gpgsign=false \
    -c user.name='Agent Factory' -c user.email='factory@example.invalid' \
    commit --quiet --allow-empty -m baseline || return
  "${current[@]}" add -A || return
  "${current[@]}" diff --cached --binary --no-ext-diff --no-textconv HEAD > "$temp/patch.diff" || return
  "${current[@]}" diff --cached --name-only --no-renames -z HEAD |
    while IFS= read -r -d '' path; do printf '%s\n' "$path"; done |
    LC_ALL=C sort > "$temp/changed-paths.txt"
}

if ! command -v git >/dev/null || ! git_patch; then
  ln -sfn -- base a
  ln -sfn -- product b
  status=0
  LC_ALL=C TZ=UTC0 diff -ruN -x .git a b > "$temp/raw.diff" || status=$?
  if (( status > 1 )); then
    exit "$status"
  fi
  # BSD diff omits fractional seconds and the timezone. Git recognizes the
  # GNU epoch format in file headers as a creation or deletion.
  awk '
    /^diff -ruN / { headers = 2; print; next }
    headers { sub(/\t1970-01-01 00:00:00$/, "\t1970-01-01 00:00:00.000000000 +0000"); headers-- }
    { print }
  ' "$temp/raw.diff" > "$temp/patch.diff"
  find -H a b -name .git -prune -o \( -type f -o -type l \) -print0 |
    while IFS= read -r -d '' entry; do
      path="${entry#*/}"
      if ! cmp -s -- "a/$path" "b/$path"; then
        printf '%s\n' "$path"
      fi
    done | LC_ALL=C sort -u > "$temp/changed-paths.txt"
fi

mv -f -- "$temp/patch.diff" "$temp/changed-paths.txt" "$out/"
cat -- "$out/changed-paths.txt"
printf 'Patch bytes: %s\n' "$(wc -c < "$out/patch.diff")"
