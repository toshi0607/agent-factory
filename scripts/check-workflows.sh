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
  local -a args=("$1" "$verify_lockfile")
  if [[ $1 == .github/workflows/* ]]; then
    args+=("$lockfile" "${workflows[@]}")
  fi
  if [[ $parser == python ]]; then
    python3 - "${args[@]}" <<'PY'
import re
import sys
import yaml

workflow_file, verify_file = sys.argv[1:3]

def fail(file, message):
    sys.exit(f"{file}: {message}")

def emit(*values):
    if not all(isinstance(value, str) for value in values):
        fail(workflow_file, "expected string workflow fields")
    if any("\0" in value for value in values):
        fail(workflow_file, "NUL in a workflow field")
    sys.stdout.write("\0".join(values) + "\0")

def mapping_value(node, key):
    return next((value for name, value in node.value if name.value == key), None)

class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.peek_event().anchor is not None:
            raise yaml.YAMLError("aliases and anchors are not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        names = [key.value for key, _ in node.value if isinstance(key, yaml.ScalarNode)]
        if len(names) != len(set(names)):
            raise yaml.YAMLError("duplicate mapping key")
        keys = set()
        for key, _ in node.value:
            if key.value == "<<" or key.tag == "tag:yaml.org,2002:merge":
                raise yaml.YAMLError("merge keys are not allowed")
            value = self.construct_object(key, deep=True)
            if value in keys:
                raise yaml.YAMLError("duplicate mapping key")
            keys.add(value)
        return super().construct_mapping(node, deep)

def has_commit(dependency):
    return (isinstance(dependency, dict) and isinstance(dependency.get("commit"), str) and
            re.fullmatch(r"sha1-[0-9a-f]{40}", dependency["commit"]) is not None)

def is_locked(uses):
    dependency = dependencies.get(uses)
    return (uses in references and has_commit(dependency) and
            dependency.get("ref") == uses.rpartition("@")[2])

references = None
used = set()
if len(sys.argv) > 3:
    lock_file = sys.argv[3]
    try:
        with open(lock_file, encoding="utf-8") as stream:
            lock = yaml.load(stream, Loader=StrictLoader)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as error:
        fail(lock_file, f"could not parse lockfile: {error}")
    if not isinstance(lock, dict) or lock.get("version") != "v0.0.3":
        fail(lock_file, "set lockfile version to v0.0.3")
    workflows, dependencies = lock.get("workflows"), lock.get("dependencies")
    if not isinstance(workflows, dict) or not isinstance(dependencies, dict):
        fail(lock_file, "define workflows and dependencies as mappings")
    for path in workflows:
        if path not in sys.argv[4:]:
            fail(lock_file, f"remove the entry for unknown workflow {path!r}")
    references = workflows.get(workflow_file)
    if not isinstance(references, list) or not all(isinstance(ref, str) for ref in references):
        fail(workflow_file, f"list this workflow and its references under workflows in {lock_file}")
    for reference, dependency in dependencies.items():
        if not isinstance(dependency, dict):
            fail(lock_file, f"define dependency {reference!r} as a mapping")
        if any(type(dependency.get(key)) is not int for key in ("owner_id", "repo_id")):
            fail(lock_file, f"set owner_id and repo_id to integer IDs for dependency {reference!r}")
        children = dependency.get("uses", [])
        if not isinstance(children, list) or not all(
                isinstance(child, str) and has_commit(dependencies.get(child)) for child in children):
            fail(lock_file, f"lock each entry in uses for {reference!r} with a sha1 commit")

try:
    with open(workflow_file, encoding="utf-8") as stream:
        loader = (StrictLoader if workflow_file == verify_file else yaml.SafeLoader)(stream)
        root = loader.get_single_node()
        workflow = loader.construct_document(root) if root is not None else None
except (OSError, TypeError, ValueError, yaml.YAMLError):
    fail(workflow_file, "could not parse workflow YAML")
if not isinstance(workflow, dict):
    fail(workflow_file, "define the workflow as a mapping")
if workflow_file == verify_file:
    # Look up the literal key because YAML 1.1 resolves unquoted 'on' as a boolean.
    events_node = mapping_value(root, "on")
    events = loader.construct_object(events_node, deep=True) if events_node is not None else None
    if (not isinstance(events, dict) or set(events) != {"pull_request", "push"} or
            events["pull_request"] not in (None, {}) or events["push"] != {"branches": ["main"]}):
        fail(workflow_file, "trigger on pull_request without filters and pushes to main only")
    if "defaults" in workflow or "env" in workflow:
        fail(workflow_file, "remove top-level defaults and env")
jobs_node = mapping_value(root, "jobs")
emit("workflow", str(int(workflow.get("permissions") == {})))
default_dir = workflow.get("defaults", {}).get("run", {}).get("working-directory", "")
for name, job in workflow["jobs"].items():
    if workflow_file == verify_file:
        if set(job) != {"runs-on", "timeout-minutes", "permissions", "env", "steps"}:
            fail(workflow_file, f"set only runs-on, timeout-minutes, permissions, env, and steps in job {name}")
        if job["runs-on"] != "ubuntu-24.04" or job["env"] != {"GH_TOKEN": "${{ github.token }}"}:
            fail(workflow_file, f"use ubuntu-24.04 and set only GH_TOKEN to github.token in job {name}")
    permissions = job.get("permissions")
    oidc = permissions == "write-all" or isinstance(permissions, dict) and permissions.get("id-token") == "write"
    actions = permissions in ("read-all", "write-all") or isinstance(permissions, dict) and permissions.get("actions") in ("read", "write")
    recovery_permissions = permissions == {"id-token": "write", "contents": "read", "actions": "read"}
    emit("job", name, str(int(oidc)), str(int(permissions == {})),
         str(int(permissions == {"contents": "read"})), str(int(actions)), str(int(recovery_permissions)),
         job.get("uses", ""))
    if references is not None and job.get("uses") in references:
        uses = job["uses"]
        if not is_locked(uses):
            fail(workflow_file, f"lock reusable workflow {uses!r} in {lock_file} with a matching ref and sha1 commit")
        used.add(uses)
    job_dir = job.get("defaults", {}).get("run", {}).get("working-directory", default_dir)
    steps_node = mapping_value(mapping_value(jobs_node, name), "steps")
    for index, step in enumerate(job.get("steps", [])):
        run_node = mapping_value(steps_node.value[index], "run")
        run_line = 0 if run_node is None else run_node.start_mark.line + 1 + int(run_node.style in ("|", ">"))
        inputs = step.get("with", {})
        uses = step.get("uses", "")
        if workflow_file == verify_file:
            if set(step) - {"uses", "with", "run"}:
                fail(workflow_file, f"set only uses, with, or run on steps in job {name}")
            if isinstance(uses, str) and uses.startswith("actions/checkout@") and inputs != {"persist-credentials": False}:
                fail(workflow_file, f"set only persist-credentials: false on checkout in job {name}")
        locked = ""
        if references is not None and "uses" in step:
            uses = uses if isinstance(uses, str) else "<non-string>"
            locked = str(int(is_locked(uses)))
            used.add(uses)
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
if references is not None:
    for reference in references:
        if reference not in used:
            fail(workflow_file, f"remove unused reference {reference!r} from {lock_file}")
PY
  else
    ruby -ryaml - "${args[@]}" <<'RUBY'
workflow_file, verify_file, lock_file, *workflow_files = ARGV

def emit(*values)
  abort "#{ARGV.fetch(0)}: expected string workflow fields" unless values.all? { |value| value.is_a?(String) }
  abort "#{ARGV.fetch(0)}: NUL in a workflow field" if values.any? { |value| value.include?("\0") }
  print values.join("\0"), "\0"
end

def mapping_value(node, key)
  pair = node.children.each_slice(2).find { |name, _| name.value == key }
  pair && pair.last
end

def validate_node(node, loader)
  if node.is_a?(Psych::Nodes::Alias) || node.respond_to?(:anchor) && node.anchor
    raise ArgumentError, "aliases and anchors are not allowed"
  end
  (node.children || []).each { |child| validate_node(child, loader) }
  return unless node.is_a?(Psych::Nodes::Mapping)

  names = node.children.each_slice(2).map(&:first).grep(Psych::Nodes::Scalar).map(&:value)
  raise ArgumentError, "duplicate mapping key" if names.size != names.uniq.size
  keys = {}
  node.children.each_slice(2) do |key, _|
    if key.is_a?(Psych::Nodes::Scalar) && (key.value == "<<" || key.tag == "tag:yaml.org,2002:merge")
      raise ArgumentError, "merge keys are not allowed"
    end
    value = loader.accept(key)
    raise ArgumentError, "duplicate mapping key" if keys.key?(value)
    keys[value] = true
  end
end

def strict_yaml(source)
  documents = YAML.parse_stream(source).children
  raise ArgumentError, "expected exactly one YAML document" unless documents.length == 1
  root = documents.first.root
  classes = Psych::ClassLoader::Restricted.new([], [])
  loader = Psych::Visitors::NoAliasRuby.new(Psych::ScalarScanner.new(classes), classes)
  validate_node(root, loader)
  [root, loader]
end

def has_commit?(dependency)
  dependency.is_a?(Hash) && dependency["commit"].is_a?(String) &&
    dependency["commit"].match?(/\Asha1-[0-9a-f]{40}\z/)
end

def locked?(uses, references, dependencies)
  dependency = dependencies[uses]
  references.include?(uses) && has_commit?(dependency) &&
    dependency["ref"] == uses.rpartition("@").last
end

references = nil
used = {}
if lock_file
  begin
    lock_root, lock_loader = strict_yaml(File.read(lock_file, encoding: "UTF-8"))
    lock = lock_loader.accept(lock_root)
  rescue SystemCallError, Psych::Exception, ArgumentError => error
    abort "#{lock_file}: could not parse lockfile: #{error}"
  end
  unless lock.is_a?(Hash) && lock["version"] == "v0.0.3"
    abort "#{lock_file}: set lockfile version to v0.0.3"
  end
  workflows, dependencies = lock.values_at("workflows", "dependencies")
  unless workflows.is_a?(Hash) && dependencies.is_a?(Hash)
    abort "#{lock_file}: define workflows and dependencies as mappings"
  end
  workflows.each_key do |path|
    abort "#{lock_file}: remove the entry for unknown workflow #{path.inspect}" unless workflow_files.include?(path)
  end
  references = workflows[workflow_file]
  unless references.is_a?(Array) && references.all? { |ref| ref.is_a?(String) }
    abort "#{workflow_file}: list this workflow and its references under workflows in #{lock_file}"
  end
  dependencies.each do |reference, dependency|
    abort "#{lock_file}: define dependency #{reference.inspect} as a mapping" unless dependency.is_a?(Hash)
    unless dependency["owner_id"].is_a?(Integer) && dependency["repo_id"].is_a?(Integer)
      abort "#{lock_file}: set owner_id and repo_id to integer IDs for dependency #{reference.inspect}"
    end
    children = dependency.fetch("uses", [])
    unless children.is_a?(Array) && children.all? { |child| child.is_a?(String) && has_commit?(dependencies[child]) }
      abort "#{lock_file}: lock each entry in uses for #{reference.inspect} with a sha1 commit"
    end
  end
end

begin
  source = File.read(workflow_file, encoding: "UTF-8")
  if workflow_file == verify_file
    root, loader = strict_yaml(source)
    workflow = loader.accept(root)
  else
    root = YAML.parse(source).root
    workflow = YAML.safe_load(source)
  end
rescue SystemCallError, Psych::Exception, ArgumentError
  abort "#{workflow_file}: could not parse workflow YAML"
end
abort "#{workflow_file}: define the workflow as a mapping" unless workflow.is_a?(Hash)
if workflow_file == verify_file
  # Look up the literal key because YAML 1.1 resolves unquoted 'on' as a boolean.
  events_node = mapping_value(root, "on")
  events = loader.accept(events_node) if events_node
  unless events.is_a?(Hash) && events.size == 2 && events.key?("pull_request") &&
         [nil, {}].include?(events["pull_request"]) && events["push"] == {"branches" => ["main"]}
    abort "#{workflow_file}: trigger on pull_request without filters and pushes to main only"
  end
  if workflow.key?("defaults") || workflow.key?("env")
    abort "#{workflow_file}: remove top-level defaults and env"
  end
end
jobs_node = mapping_value(root, "jobs")
emit("workflow", workflow["permissions"] == {} ? "1" : "0")
default_dir = workflow.dig("defaults", "run", "working-directory") || ""
workflow.fetch("jobs").each do |name, job|
  if workflow_file == verify_file
    unless job.size == 5 && (%w[runs-on timeout-minutes permissions env steps] - job.keys).empty?
      abort "#{workflow_file}: set only runs-on, timeout-minutes, permissions, env, and steps in job #{name}"
    end
    unless job["runs-on"] == "ubuntu-24.04" && job["env"] == {"GH_TOKEN" => "${{ github.token }}"}
      abort "#{workflow_file}: use ubuntu-24.04 and set only GH_TOKEN to github.token in job #{name}"
    end
  end
  permissions = job["permissions"]
  oidc = permissions == "write-all" || permissions.is_a?(Hash) && permissions["id-token"] == "write"
  actions = ["read-all", "write-all"].include?(permissions) || permissions.is_a?(Hash) && ["read", "write"].include?(permissions["actions"])
  recovery_permissions = permissions == {"id-token" => "write", "contents" => "read", "actions" => "read"}
  emit("job", name, oidc ? "1" : "0", permissions == {} ? "1" : "0",
       permissions == {"contents" => "read"} ? "1" : "0", actions ? "1" : "0",
       recovery_permissions ? "1" : "0", job.fetch("uses", ""))
  if references && references.include?(job["uses"])
    uses = job["uses"]
    unless locked?(uses, references, dependencies)
      abort "#{workflow_file}: lock reusable workflow #{uses.inspect} in #{lock_file} with a matching ref and sha1 commit"
    end
    used[uses] = true
  end
  job_dir = job.dig("defaults", "run", "working-directory") || default_dir
  steps_node = mapping_value(mapping_value(jobs_node, name), "steps")
  job.fetch("steps", []).each_with_index do |step, index|
    run_node = mapping_value(steps_node.children[index], "run")
    run_line = run_node ? run_node.start_line + 1 : 0
    run_line += 1 if run_node && [Psych::Nodes::Scalar::LITERAL, Psych::Nodes::Scalar::FOLDED].include?(run_node.style)
    uses = step.fetch("uses", "")
    if workflow_file == verify_file
      unless (step.keys - %w[uses with run]).empty?
        abort "#{workflow_file}: set only uses, with, or run on steps in job #{name}"
      end
      if uses.is_a?(String) && uses.start_with?("actions/checkout@") && step["with"] != {"persist-credentials" => false}
        abort "#{workflow_file}: set only persist-credentials: false on checkout in job #{name}"
      end
    end
    locked = ""
    if references && step.key?("uses")
      uses = "<non-string>" unless uses.is_a?(String)
      locked = locked?(uses, references, dependencies) ? "1" : "0"
      used[uses] = true
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
         step.fetch("run", ""), run_line.to_s, step.fetch("working-directory", job_dir),
         artifact_path.is_a?(String) ? artifact_path : "")
  end
end
if references
  references.each do |reference|
    abort "#{workflow_file}: remove unused reference #{reference.inspect} from #{lock_file}" unless used.key?(reference)
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
  local verify_job=0 verify_checkout=0 verify_runs=0
  while IFS= read -r -d '' record; do
    case $record in
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
        [[ ${uses%%@*} != *[[:upper:]]* ]] || fail "use a lowercase reusable workflow name in job $name"
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
        [[ ${uses%%@*} != *[[:upper:]]* ]] || fail "use a lowercase action name in job $name"
        ((++step_number))
        if [[ $file == .github/workflows/* && $run_line != 0 ]]; then
          validate_session_invocations "$script" "$run_line"
        fi
        if [[ $step_number == 1 && $ref_guard == 1 ]]; then
          if [[ ${script%$'\n'} == "$factory_ref_guard" ]]; then
            checked_ref=1
          elif [[ $script == "$factory_ref_guard"$'\n'* ]]; then
            case "$file:$name" in
              .github/workflows/p0-run.yml:start|.github/workflows/p0-run.yml:collect|.github/workflows/p0-recover.yml:recover)
                checked_ref=1 ;;
            esac
          fi
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
      *) fail "unknown workflow record type" ;;
    esac
  done
  validate_artifact_paths "$name" "$downloads" "$outputs"
  if [[ $file == "$verify_lockfile" ]]; then
    [[ $verify_job == 1 ]] || fail 'define exactly one job'
    [[ $verify_checkout == 1 ]] || fail "use a single actions/checkout step in job $name"
    [[ $verify_runs == 2 ]] || fail "install the pinned gh actions-lock extension and then run gh actions-lock --verify in job $name"
  fi
}

file=$verify_lockfile
[[ -f $file ]] || fail 'missing required workflow'
shopt -s nullglob
workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
for file in "${workflows[@]}" poc/caller/*.yml poc/caller/*.yaml; do
  if grep -Fq 'secrets.' "$file"; then
    fail 'remove secrets references from the workflow'
  fi
  parse_workflow "$file" | validate_workflow
done

if gh actions-lock --version >/dev/null 2>&1; then
  file=$lockfile
  gh actions-lock --verify-local || fail 'gh actions-lock --verify-local failed'
else
  printf '%s: skipped offline gh actions-lock check (extension unavailable)\n' "$lockfile" >&2
fi
