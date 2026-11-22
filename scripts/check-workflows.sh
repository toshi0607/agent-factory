#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")/.."
if python3 -c 'import yaml' >/dev/null 2>&1; then
  parser=python
elif ruby -ryaml -e '' >/dev/null 2>&1; then
  parser=ruby
else
  printf 'Workflow validation requires PyYAML (python3) or YAML (ruby).\n' >&2
  exit 3
fi

# Emit NUL-delimited fields to preserve multiline run blocks.
parse_workflow() {
  local -a args=("$1")
  if [[ $1 == .github/workflows/* ]]; then
    args+=("$lockfile")
  fi
  if [[ $parser == python ]]; then
    python3 - "${args[@]}" <<'PY'
import re
import sys
import yaml

def emit(*values):
    sys.stdout.write("\0".join(values) + "\0")

def mapping_value(node, key):
    return next((value for name, value in node.value if name.value == key), None)

references = None
if len(sys.argv) > 2:
    try:
        with open(sys.argv[2], encoding="utf-8") as stream:
            lock = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError):
        lock = None
    if not isinstance(lock, dict):
        emit("lock", "invalid")
        sys.exit()
    workflows = lock.get("workflows")
    references = workflows.get(sys.argv[1]) if isinstance(workflows, dict) else None
    if not isinstance(references, list):
        emit("lock", "missing-workflow")
        sys.exit()
    dependencies = lock.get("dependencies")

with open(sys.argv[1], encoding="utf-8") as stream:
    loader = yaml.SafeLoader(stream)
    root = loader.get_single_node()
    workflow = loader.construct_document(root)
jobs_node = mapping_value(root, "jobs")
emit("workflow", str(int(workflow.get("permissions") == {})))
default_dir = workflow.get("defaults", {}).get("run", {}).get("working-directory", "")
for name, job in workflow["jobs"].items():
    permissions = job.get("permissions")
    oidc = permissions == "write-all" or isinstance(permissions, dict) and permissions.get("id-token") == "write"
    actions = permissions in ("read-all", "write-all") or isinstance(permissions, dict) and permissions.get("actions") in ("read", "write")
    recovery_permissions = permissions == {"id-token": "write", "contents": "read", "actions": "read"}
    emit("job", name, str(int(oidc)), str(int(permissions == {})),
         str(int(permissions == {"contents": "read"})), str(int(actions)), str(int(recovery_permissions)),
         job.get("uses", ""))
    job_dir = job.get("defaults", {}).get("run", {}).get("working-directory", default_dir)
    steps_node = mapping_value(mapping_value(jobs_node, name), "steps")
    for index, step in enumerate(job.get("steps", [])):
        run_node = mapping_value(steps_node.value[index], "run")
        run_line = 0 if run_node is None else run_node.start_mark.line + 1 + int(run_node.style in ("|", ">"))
        inputs = step.get("with", {})
        uses = step.get("uses", "")
        locked = ""
        if references is not None and "uses" in step:
            uses = uses if isinstance(uses, str) else "<non-string>"
            dependency = dependencies.get(uses) if isinstance(dependencies, dict) else None
            commit = dependency.get("commit") if isinstance(dependency, dict) else None
            locked = str(int(uses in references and isinstance(commit, str) and
                             re.fullmatch(r"sha1-[0-9a-f]{40}", commit) is not None and
                             dependency.get("ref") == uses.rpartition("@")[2]))
        persist = inputs.get("persist-credentials") is False
        factory = inputs.get("repository") == "toshi0607/agent-factory"
        factory_ref = inputs.get("ref") == "${{ inputs.factory_ref }}"
        ref_guard = (step.get("shell") == "bash" and "if" not in step and
                     step.get("continue-on-error", False) is False and
                     step.get("env", {}).get("FACTORY_REF") == "${{ inputs.factory_ref }}")
        pinned_go = inputs.get("go-version") == "1.26.11" and inputs.get("check-latest") is False
        artifact_path = inputs.get("path") if uses.startswith("actions/download-artifact@") else ""
        emit("step", uses, locked, str(int(persist)), str(int("repository" in inputs)),
             str(int(factory)), str(int(pinned_go)), str(int(factory_ref)), str(int(ref_guard)),
             step.get("run", ""), str(run_line), step.get("working-directory", job_dir),
             artifact_path if isinstance(artifact_path, str) else "")
PY
  else
    ruby -ryaml - "${args[@]}" <<'RUBY'
def emit(*values)
  print values.join("\0"), "\0"
end

def mapping_value(node, key)
  pair = node.children.each_slice(2).find { |name, _| name.value == key }
  pair && pair.last
end

references = nil
if ARGV.length > 1
  begin
    lock_source = File.read(ARGV.fetch(1), encoding: "UTF-8")
    # Psych's safe_load reads only the first document.
    lock = YAML.safe_load(lock_source, aliases: true) if YAML.parse_stream(lock_source).children.length == 1
  rescue SystemCallError, Psych::Exception, ArgumentError
    lock = nil
  end
  unless lock.is_a?(Hash)
    emit("lock", "invalid")
    exit
  end
  workflows = lock["workflows"]
  references = workflows[ARGV.fetch(0)] if workflows.is_a?(Hash)
  unless references.is_a?(Array)
    emit("lock", "missing-workflow")
    exit
  end
  dependencies = lock["dependencies"]
end

source = File.read(ARGV.fetch(0))
workflow = YAML.safe_load(source)
jobs_node = mapping_value(YAML.parse(source).root, "jobs")
emit("workflow", workflow["permissions"] == {} ? "1" : "0")
default_dir = workflow.dig("defaults", "run", "working-directory") || ""
workflow.fetch("jobs").each do |name, job|
  permissions = job["permissions"]
  oidc = permissions == "write-all" || permissions.is_a?(Hash) && permissions["id-token"] == "write"
  actions = ["read-all", "write-all"].include?(permissions) || permissions.is_a?(Hash) && ["read", "write"].include?(permissions["actions"])
  recovery_permissions = permissions == {"id-token" => "write", "contents" => "read", "actions" => "read"}
  emit("job", name, oidc ? "1" : "0", permissions == {} ? "1" : "0",
       permissions == {"contents" => "read"} ? "1" : "0", actions ? "1" : "0",
       recovery_permissions ? "1" : "0", job.fetch("uses", ""))
  job_dir = job.dig("defaults", "run", "working-directory") || default_dir
  steps_node = mapping_value(mapping_value(jobs_node, name), "steps")
  job.fetch("steps", []).each_with_index do |step, index|
    run_node = mapping_value(steps_node.children[index], "run")
    run_line = run_node ? run_node.start_line + 1 : 0
    run_line += 1 if run_node && [Psych::Nodes::Scalar::LITERAL, Psych::Nodes::Scalar::FOLDED].include?(run_node.style)
    uses = step.fetch("uses", "")
    locked = ""
    if references && step.key?("uses")
      uses = "<non-string>" unless uses.is_a?(String)
      dependency = dependencies.is_a?(Hash) ? dependencies[uses] : nil
      commit = dependency.is_a?(Hash) ? dependency["commit"] : nil
      locked = references.include?(uses) && commit.is_a?(String) &&
               commit.match?(/\Asha1-[0-9a-f]{40}\z/) && dependency["ref"] == uses.rpartition("@").last ? "1" : "0"
    end
    persist = step.dig("with", "persist-credentials") == false
    has_repository = (step["with"] || {}).key?("repository")
    factory = step.dig("with", "repository") == "toshi0607/agent-factory"
    factory_ref = step.dig("with", "ref") == "${{ inputs.factory_ref }}"
    ref_guard = step["shell"] == "bash" && !step.key?("if") && step.fetch("continue-on-error", false) == false &&
                step.dig("env", "FACTORY_REF") == "${{ inputs.factory_ref }}"
    pinned_go = step.dig("with", "go-version") == "1.26.11" && step.dig("with", "check-latest") == false
    artifact_path = uses.start_with?("actions/download-artifact@") && step.dig("with", "path")
    emit("step", uses, locked, persist ? "1" : "0", has_repository ? "1" : "0",
         factory ? "1" : "0", pinned_go ? "1" : "0",
         factory_ref ? "1" : "0", ref_guard ? "1" : "0",
         step.fetch("run", ""), run_line, step.fetch("working-directory", job_dir),
         artifact_path.is_a?(String) ? artifact_path : "")
  end
end
RUBY
  fi
}

fail() {
  printf '%s: %s\n' "$file" "$*" >&2
  exit 1
}

pinned='@([[:xdigit:]]{40})$'
action_version='^[a-zA-Z0-9-]+/[a-zA-Z0-9_.-]+(/[^/@[:space:]]+)*@v[0-9]+\.[0-9]+\.[0-9]+$'
lockfile=.github/workflows/actions.lock
verify_lockfile=.github/workflows/verify-lockfile.yml
forbidden='(^|[^[:alnum:]_.-])(docker|make|go[[:space:]]+(test|run|generate))([^[:alnum:]_.-]|$)'
build='(^|[^[:alnum:]_.-])go[[:space:]]+build([^[:alnum:]_.-]|$)'
# Match literal -o arguments in run blocks, including quoted paths and -o=path.
build_output=$'(^|[^[:alnum:]_.-])go[[:blank:]]+build[[:blank:]]+([^;&|[:cntrl:]]*[[:blank:]])?-o([[:blank:]]+|=)("[^"]+"|\'[^\']+\'|[^[:space:];&|]+)'
change_dir='(^|[^[:alnum:]_.-])(cd|pushd|popd)([^[:alnum:]_.-]|$)'
session_path='\$(RUNNER_TEMP|\{RUNNER_TEMP\})(/bin)?/session'
session_command="(^|[;&|])[[:blank:]]*((if|elif|then|else|do|!|exec)[[:blank:]]+)*(\"$session_path\"|$session_path)([[:blank:];&|<>]|$)"
factory_ref_guard=$(cat <<'BASH'
if [[ ! "$FACTORY_REF" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'factory_ref must be a full lowercase commit SHA\n' >&2
  exit 1
fi
BASH
)

workflow_path() {
  local value=$1 directory=$2 part result=
  local -a parts
  local temp_expression='^\$\{\{[[:blank:]]*runner\.temp[[:blank:]]*\}\}'
  local workspace_expression='^\$\{\{[[:blank:]]*github\.workspace[[:blank:]]*\}\}'
  if [[ $value =~ $temp_expression ]]; then
    value=/@runner-temp${value#"${BASH_REMATCH[0]}"}
  elif [[ $value =~ $workspace_expression ]]; then
    value=/@workspace${value#"${BASH_REMATCH[0]}"}
  else
    case $value in
      '$RUNNER_TEMP'|'$RUNNER_TEMP/'*) value=/@runner-temp${value#'$RUNNER_TEMP'} ;;
      '${RUNNER_TEMP}'|'${RUNNER_TEMP}/'*) value=/@runner-temp${value#'${RUNNER_TEMP}'} ;;
      '$GITHUB_WORKSPACE'|'$GITHUB_WORKSPACE/'*) value=/@workspace${value#'$GITHUB_WORKSPACE'} ;;
      '${GITHUB_WORKSPACE}'|'${GITHUB_WORKSPACE}/'*) value=/@workspace${value#'${GITHUB_WORKSPACE}'} ;;
      /*) ;;
      *) value=$directory/$value ;;
    esac
  fi
  IFS=/ read -r -a parts <<< "$value"
  for part in "${parts[@]}"; do
    case $part in
      ''|.) ;;
      ..) result=${result%/*} ;;
      *) result+=/$part ;;
    esac
  done
  printf '%s\n' "${result:-/}"
}

validate_artifact_paths() {
  local name=$1 downloads=$2 outputs=$3 download output
  while IFS= read -r download; do
    [[ -n $download ]] || continue
    [[ $download != /@runner-temp ]] || fail "download artifacts into a dedicated subdirectory of runner.temp in job $name"
    while IFS= read -r output; do
      # The -o argument may name a file or a directory.
      if [[ $output == "$download" || $output == "${download%/}/"* ]]; then
        fail "use separate directories for artifact downloads and go build -o outputs in job $name"
      fi
    done <<< "$outputs"
  done <<< "$downloads"
}

validate_session_invocations() {
  local script=$1 line_number=$2 line
  while IFS= read -r line; do
    if [[ ! $line =~ ^[[:blank:]]*(exec[[:blank:]]|#) && $line =~ $session_command ]]; then
      printf '%s:%s: start the session invocation with exec\n' "$file" "$line_number" >&2
      exit 1
    fi
    ((++line_number))
  done <<< "$script"
}

validate_workflow() {
  local record name= oidc empty contents_read actions recovery_permissions uses locked persist repository factory pinned_go
  local factory_ref ref_guard checked_ref step_number script run_line directory artifact_path
  local downloads= outputs= commands output match
  local lock_status verify_job=0 verify_checkout=0 verify_runs=0
  while IFS= read -r -d '' record; do
    case $record in
      lock)
        IFS= read -r -d '' lock_status
        if [[ $lock_status == invalid ]]; then
          fail "could not read or parse $lockfile"
        fi
        fail "list this workflow under workflows in $lockfile"
        ;;
      workflow)
        IFS= read -r -d '' empty
        [[ $empty == 1 ]] || fail 'set top-level permissions to {}'
        ;;
      job)
        validate_artifact_paths "$name" "$downloads" "$outputs"
        downloads=
        outputs=
        IFS= read -r -d '' name
        IFS= read -r -d '' oidc
        IFS= read -r -d '' empty
        IFS= read -r -d '' contents_read
        IFS= read -r -d '' actions
        IFS= read -r -d '' recovery_permissions
        IFS= read -r -d '' uses
        if [[ $file == "$verify_lockfile" ]]; then
          [[ $verify_job == 0 ]] || fail 'define exactly one job'
          verify_job=1
          [[ $contents_read == 1 ]] || fail "set permissions for job $name to contents: read"
        fi
        step_number=0
        checked_ref=0
        if [[ $file == .github/workflows/p0-recover.yml || $file == poc/caller/factory-p0-recover.yml ]]; then
          [[ $recovery_permissions == 1 ]] || fail "set recovery job permissions to id-token: write, contents: read, and actions: read"
        elif [[ $actions == 1 ]]; then
          fail "grant actions access only to the recovery workflow and its caller"
        fi
        if [[ $file == .github/workflows/p0-check-only.yml || $file == poc/caller/factory-p0-check.yml ]]; then
          [[ $contents_read == 1 ]] || fail "set check-only job permissions to contents: read"
        elif [[ $name == check && $empty != 1 ]]; then
          fail 'set the check job permissions to {}'
        fi
        if [[ -n $uses && ! $uses =~ $pinned ]]; then
          # The caller templates are pinned when installed in the product repository.
          if [[ $file != poc/caller/* || ! $uses =~ ^toshi0607/agent-factory/\.github/workflows/p0-(run|auth-check|check-only|recover)\.yml@FACTORY_SHA$ ]]; then
            fail "pin the reusable workflow for job $name to a full commit SHA"
          fi
        fi
        ;;
      step)
        IFS= read -r -d '' uses
        IFS= read -r -d '' locked
        IFS= read -r -d '' persist
        IFS= read -r -d '' repository
        IFS= read -r -d '' factory
        IFS= read -r -d '' pinned_go
        IFS= read -r -d '' factory_ref
        IFS= read -r -d '' ref_guard
        IFS= read -r -d '' script
        IFS= read -r -d '' run_line
        IFS= read -r -d '' directory
        IFS= read -r -d '' artifact_path
        ((++step_number))
        if [[ $file == .github/workflows/* && $run_line != 0 ]]; then
          validate_session_invocations "$script" "$run_line"
        fi
        if [[ $step_number == 1 && $ref_guard == 1 && ${script%$'\n'} == "$factory_ref_guard" ]]; then
          checked_ref=1
        fi
        if [[ -n $locked ]]; then
          [[ $uses =~ $action_version ]] || fail "use a full version tag for action '$uses' in job $name"
          [[ $locked == 1 ]] || fail "lock action '$uses' in job $name in $lockfile with a matching ref and sha1 commit"
        elif [[ -n $uses && ! $uses =~ $pinned ]]; then
          fail "pin each action in job $name to a full commit SHA"
        fi
        if [[ $uses == actions/checkout@* && $persist != 1 ]]; then
          fail "set persist-credentials: false on checkout in job $name"
        fi
        if [[ $file == "$verify_lockfile" ]]; then
          if [[ -n $uses ]]; then
            [[ $verify_checkout == 0 && $uses == actions/checkout@* && $repository == 0 ]] ||
              fail "use a single actions/checkout step without a repository input in job $name"
            verify_checkout=1
          fi
          if [[ $run_line != 0 ]]; then
            case "$verify_runs:$script" in
              '0:gh extension install github/gh-actions-lock --pin v0.4.0'|'1:gh actions-lock --verify') ((++verify_runs)) ;;
              *) fail "run only the pinned gh actions-lock extension install and then gh actions-lock --verify in job $name" ;;
            esac
          fi
        fi
        if [[ $oidc == 1 && $uses == actions/checkout@* && $factory != 1 ]]; then
          fail "only check out toshi0607/agent-factory in OIDC job $name"
        fi
        if [[ $file == .github/workflows/* && $uses == actions/checkout@* && $factory == 1 ]]; then
          [[ $factory_ref == 1 ]] || fail "use inputs.factory_ref for the factory checkout in job $name"
          [[ $checked_ref == 1 ]] || fail "make the unconditional bash factory_ref validation the first step in job $name"
        fi
        if [[ $uses == actions/setup-go@* && $pinned_go != 1 ]]; then
          fail "set go-version to '1.26.11' and check-latest to false in job $name"
        fi
        if [[ $uses == actions/download-artifact@* ]]; then
          artifact_path=${artifact_path#"${artifact_path%%[![:space:]]*}"}
          artifact_path=${artifact_path%"${artifact_path##*[![:space:]]}"}
          [[ -n $artifact_path ]] || fail "set an explicit artifact download path in job $name"
          downloads+=$(workflow_path "$artifact_path" /@workspace)$'\n'
        fi
        commands=${script//$'\\\n'/}
        while [[ $commands =~ $build_output ]]; do
          match=${BASH_REMATCH[0]}
          output=${BASH_REMATCH[4]}
          case $output in
            \"*\"|\'*\') output=${output:1:${#output}-2} ;;
          esac
          outputs+=$(workflow_path "$output" "$(workflow_path "$directory" /@workspace)")$'\n'
          commands=${commands#*"$match"}
        done
        if [[ $script == *'${{'* ]]; then
          fail "pass expressions into run steps of job $name through env"
        fi
        if [[ $oidc == 1 ]]; then
          script=${script//$'\\\n'/}
          if [[ $script =~ $forbidden || $script =~ (^|[^[:alnum:]_.-])go[[:space:]]+-C ]]; then
            fail "move product build and execution commands out of OIDC job $name"
          fi
          if [[ $script =~ $build ]]; then
            directory=${directory#./}
            case $directory in
              factory|factory/*) ;;
              *) fail "run factory builds in the factory directory in OIDC job $name" ;;
            esac
            if [[ /$directory/ == */../* || $script =~ $change_dir || $script == *../product* ]]; then
              fail "keep the build inside the factory directory in OIDC job $name"
            fi
          fi
        fi
        ;;
    esac
  done
  validate_artifact_paths "$name" "$downloads" "$outputs"
  if [[ $file == "$verify_lockfile" ]]; then
    [[ $verify_job == 1 ]] || fail 'define exactly one job'
    [[ $verify_checkout == 1 ]] || fail "use a single actions/checkout step in job $name"
    [[ $verify_runs == 2 ]] || fail "install the pinned gh actions-lock extension and then run gh actions-lock --verify in job $name"
  fi
}

shopt -s nullglob
for file in .github/workflows/*.yml .github/workflows/*.yaml poc/caller/*.yml poc/caller/*.yaml; do
  if grep -Fq 'secrets.' "$file"; then
    fail 'remove secrets references from the workflow'
  fi
  {
    parse_workflow "$file" 2>/dev/null || fail 'could not parse workflow YAML'
  } | validate_workflow
done
