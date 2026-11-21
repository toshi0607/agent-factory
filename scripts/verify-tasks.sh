#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")/.."
shopt -s nullglob
patches=(poc/reference/*.patch)
if [[ ! -f ${patches[0]:-} ]]; then
    printf 'No reference patches found in poc/reference.\n' >&2
    exit 1
fi

verify_case() {
    local task=$1 case_name=$2 expected_code=$3 result code=0 flag expected matched=true
    shift 3
    local work=".work/verify/$task-$case_name"
    if ! rm -rf -- "$work"; then
        printf '%s %s FAIL (could not remove %s)\n' "$task" "$case_name" "$work"
        return 1
    fi
    result=$(bin/checkpatch -runner direct -product .work/product -task "$task" -p0check bin/p0check -work "$work" "$@") || code=$?
    if [[ $code == "$expected_code" && $result == *'"error":""'* ]]; then
        # checkpatch emits compact JSON with these top-level boolean fields.
        local -a flags
        if [[ $case_name == base ]]; then
            flags=(build_ok:true check_passed:false)
        else
            flags=(paths_ok:true apply_ok:true gen_ok:true build_ok:true check_passed:true)
        fi
        for expected in "${flags[@]}"; do
            flag="\"${expected%:*}\":${expected#*:}"
            if [[ $result != *"$flag"* ]]; then
                matched=false
                break
            fi
        done
        if [[ $matched == true ]]; then
            printf '%s %s PASS\n' "$task" "$case_name"
            return 0
        fi
    fi
    printf '%s %s FAIL (exit %s, expected %s) %s\n' "$task" "$case_name" "$code" "$expected_code" "$result"
    return 1
}

status=0
for patch in "${patches[@]}"; do
    task=${patch##*/}
    task=${task%.patch}
    verify_case "$task" base 1 -no-patch || status=1
    verify_case "$task" ref 0 -patch "$patch" || status=1
done
exit "$status"
