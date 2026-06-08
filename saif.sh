#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
SAIF_PY="${VENV_DIR}/bin/python"
SAIF_PIP="${VENV_DIR}/bin/pip"
PROJECT_HASH_FILE="${VENV_DIR}/.saif-pyproject.sha256"

ensure_go_bin_path() {
  local go_bin="${HOME}/go/bin"
  case ":${PATH}:" in
    *":${go_bin}:"*) ;;
    *) export PATH="${go_bin}:${PATH}" ;;
  esac
}

load_env() {
  local existing_target_marker="__SAIF_TARGET_UNSET__"
  local existing_target="${TARGET_URL:-$existing_target_marker}"
  if [[ -f ".env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
  fi
  if [[ "$existing_target" == "$existing_target_marker" ]]; then
    unset TARGET_URL || true
  else
    export TARGET_URL="$existing_target"
  fi
}

print_tool_status() {
  ensure_go_bin_path
  if [[ -x "$SAIF_PY" ]] && "$SAIF_PY" -c "import saif.services.tool_manager" >/dev/null 2>&1; then
    "$SAIF_PY" - <<'PY'
import importlib.metadata
import shutil
from pathlib import Path

from saif.services.tool_manager import check_runtime_tools

status = check_runtime_tools()
for tool in sorted(status):
    installed = status[tool]
    detail = None
    if tool == "httpx" and installed:
        detail = f"Python package in venv ({importlib.metadata.version('httpx')})"
    elif tool == "seclists" and installed:
        detail = "/usr/share/seclists"
    elif tool == "dirb" and installed:
        detail = "/usr/share/wordlists/dirb" if Path("/usr/share/wordlists/dirb").exists() else shutil.which("dirb")
    elif installed:
        detail = shutil.which(tool)
    print(f"tool {tool}: installed ({detail})" if installed else f"tool {tool}: missing")
PY
  else
    for tool in python3 psql nmap katana; do
      if command -v "$tool" >/dev/null 2>&1; then
        echo "tool ${tool}: installed ($(command -v "$tool"))"
      else
        echo "tool ${tool}: missing"
      fi
    done
  fi
}

ensure_env_file() {
  if [[ ! -f ".env" && -f ".env.example" ]]; then
    cp ".env.example" ".env"
    echo "created .env from .env.example"
  fi
}

ensure_venv() {
  if [[ ! -x "$SAIF_PY" ]]; then
    echo "creating virtual environment: ${VENV_DIR}"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  else
    echo "virtual environment: present"
  fi
}

pyproject_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum pyproject.toml | awk '{print $1}'
  else
    "$PYTHON_BIN" - <<'PY'
import hashlib
print(hashlib.sha256(open("pyproject.toml","rb").read()).hexdigest())
PY
  fi
}

package_installed() {
  "$SAIF_PY" -c "import importlib.metadata; importlib.metadata.version('saif')" >/dev/null 2>&1
}

install_if_needed() {
  local current_hash stored_hash
  current_hash="$(pyproject_hash)"
  stored_hash=""
  [[ -f "$PROJECT_HASH_FILE" ]] && stored_hash="$(cat "$PROJECT_HASH_FILE")"
  if package_installed && [[ "$current_hash" == "$stored_hash" ]]; then
    echo "SAIF package: installed and current"
    return
  fi
  echo "SAIF package: installing/updating"
  "$SAIF_PY" -m pip install --upgrade pip
  "$SAIF_PIP" install -e .
  echo "$current_hash" > "$PROJECT_HASH_FILE"
}

run_saif() {
  ensure_venv >/dev/null
  "$SAIF_PY" -m saif.cli "$@"
}

arg_value() {
  local key="$1"
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      "$key")
        if [[ $# -lt 2 ]]; then
          echo ""
          return
        fi
        echo "$2"
        return
        ;;
      "$key="*)
        echo "${1#*=}"
        return
        ;;
    esac
    shift
  done
}

has_flag() {
  local key="$1"
  shift
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "$key" ]]; then
      return 0
    fi
    shift
  done
  return 1
}

resolve_target_for_shell() {
  local cli_target="${1:-}"
  local selected=""
  local source=""
  if [[ -n "$cli_target" ]]; then
    selected="$cli_target"
    source="cli-arg"
  elif [[ -n "${TARGET_URL:-}" ]]; then
    selected="$TARGET_URL"
    source="env"
  fi
  if [[ -z "$selected" && -t 0 ]]; then
    read -r -p "Target URL (authorized staging target): " selected
    source="interactive"
  fi
  if [[ -z "$selected" ]]; then
    echo "ERROR: no target provided. Use --target, include a target URL in prompt text, or set TARGET_URL for this shell." >&2
    exit 2
  fi
  echo "${source}|${selected}"
}

ensure_env_file
load_env

COMMAND="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$COMMAND" in
  setup)
    ensure_venv
    install_if_needed
    print_tool_status
    run_saif init
    ;;
  doctor)
    cli_target="$(arg_value --target "$@")"
    if [[ -n "${cli_target:-}" || -n "${TARGET_URL:-}" ]]; then
      resolved_target="$(resolve_target_for_shell "${cli_target:-}")"
      selected_source="${resolved_target%%|*}"
      selected_target="${resolved_target#*|}"
      run_saif doctor --target "$selected_target"
    else
      run_saif doctor
    fi
    ;;
  init-db)
    run_saif db init
    ;;
  list-testcases)
    run_saif testcases list --profile "${SAIF_PROFILE:-web-api}"
    ;;
  install-tools)
    run_saif install-tools "$@"
    ;;
  install-tool)
    run_saif install-tool "$@"
    ;;
  debug-export)
    run_saif debug-export "$@"
    ;;
  tools)
    subcommand="${1:-status}"
    shift || true
    case "$subcommand" in
      status)
        run_saif tools status "$@"
        ;;
      refresh)
        run_saif tools refresh "$@"
        ;;
      check)
        run_saif tools check "$@"
        ;;
      list)
        run_saif tools list "$@"
        ;;
      *)
        echo "ERROR: unknown tools command: ${subcommand}" >&2
        exit 2
        ;;
    esac
    ;;
  create-project)
    cli_target="$(arg_value --target "$@")"
    cli_profile="$(arg_value --profile "$@")"
    cli_mode="$(arg_value --mode "$@")"
    cli_credentials="$(arg_value --credentials "$@")"
    cli_source_path="$(arg_value --source-path "$@")"
    resolved_target="$(resolve_target_for_shell "${cli_target:-}")"
    selected_source="${resolved_target%%|*}"
    selected_target="${resolved_target#*|}"
    run_saif project create --name "${SAIF_PROJECT_NAME:-saif-demo}" --target "$selected_target" --target-source "$selected_source"
    ;;
  scan)
    subcommand="${1:-start}"
    case "$subcommand" in
      start)
        shift || true
        ;;
      pause|resume|stop|status|watch|list|show|continue|run-existing|report|retest)
        shift || true
        run_saif scan "$subcommand" "$@"
        exit 0
        ;;
      *)
        subcommand="start"
        ;;
    esac
    cli_target="$(arg_value --target "$@")"
    cli_profile="$(arg_value --profile "$@")"
    cli_mode="$(arg_value --mode "$@")"
    cli_credentials="$(arg_value --credentials "$@")"
    cli_source_path="$(arg_value --source-path "$@")"
    resolved_target="$(resolve_target_for_shell "${cli_target:-}")"
    selected_source="${resolved_target%%|*}"
    selected_target="${resolved_target#*|}"
    debug_args=()
    if has_flag --debug "$@"; then
      debug_args=(--debug)
    fi
    extra_args=()
    for flag in --enumeration-only --full --auth --vuln-test --no-destructive-methods --enable-destructive-tests --allow-test-owned-object-creation --confirm-destructive-testing --allow-account-generation --allow-authenticated-testing --allow-authorization-testing --allow-payload-testing --allow-rate-limit-testing; do
      if has_flag "$flag" "$@"; then
        extra_args+=("$flag")
      fi
    done
    for value_flag in --destructive-policy --destructive-method-policy --auth-mode --selected-test-categories; do
      value="$(arg_value "$value_flag" "$@")"
      [[ -n "${value:-}" ]] && extra_args+=("$value_flag" "$value")
    done
    scan_args=(scan start --project "${SAIF_PROJECT_NAME:-saif-demo}" --target "$selected_target" --target-source "$selected_source" --profile "${cli_profile:-${SAIF_PROFILE:-auto}}")
    [[ -n "${cli_mode:-}" ]] && scan_args+=(--mode "$cli_mode")
    [[ -n "${cli_credentials:-}" ]] && scan_args+=(--credentials "$cli_credentials")
    [[ -n "${cli_source_path:-}" ]] && scan_args+=(--source-path "$cli_source_path")
    scan_args+=(--ai "${SAIF_AI_PROVIDER:-ollama}")
    scan_args+=("${debug_args[@]}" "${extra_args[@]}")
    run_saif "${scan_args[@]}"
    ;;
  report)
    scan_id="$(arg_value --scan-id "$@")"
    format="$(arg_value --format "$@")"
    if [[ -n "${scan_id:-}" ]]; then
      if [[ -n "${format:-}" ]]; then
        run_saif report generate --scan-id "$scan_id" --format "$format"
      else
        run_saif report generate --scan-id "$scan_id" --format json
        run_saif report generate --scan-id "$scan_id" --format html
      fi
    elif [[ -n "${format:-}" ]]; then
      run_saif report generate --project "${SAIF_PROJECT_NAME:-saif-demo}" --format "$format"
    else
      run_saif report generate --project "${SAIF_PROJECT_NAME:-saif-demo}" --format json
      run_saif report generate --project "${SAIF_PROJECT_NAME:-saif-demo}" --format html
    fi
    ;;
  dashboard)
    subcommand="${1:-start}"
    shift || true
    run_saif dashboard "$subcommand" "$@"
    ;;
  logs)
    subcommand="${1:-tail}"
    shift || true
    run_saif logs "$subcommand" "$@"
    ;;
  run-demo)
    cli_target="$(arg_value --target "$@")"
    cli_profile="$(arg_value --profile "$@")"
    cli_mode="$(arg_value --mode "$@")"
    cli_credentials="$(arg_value --credentials "$@")"
    cli_source_path="$(arg_value --source-path "$@")"
    resolved_target="$(resolve_target_for_shell "${cli_target:-}")"
    selected_source="${resolved_target%%|*}"
    selected_target="${resolved_target#*|}"
    debug_args=()
    if has_flag --debug "$@"; then
      debug_args=(--debug)
    fi
    extra_args=()
    for flag in --enumeration-only --full --auth --vuln-test --no-destructive-methods; do
      if has_flag "$flag" "$@"; then
        extra_args+=("$flag")
      fi
    done
    demo_args=(run-demo --target "$selected_target" --target-source "$selected_source" --profile "${cli_profile:-${SAIF_PROFILE:-auto}}")
    [[ -n "${cli_mode:-}" ]] && demo_args+=(--mode "$cli_mode")
    [[ -n "${cli_credentials:-}" ]] && demo_args+=(--credentials "$cli_credentials")
    [[ -n "${cli_source_path:-}" ]] && demo_args+=(--source-path "$cli_source_path")
    demo_args+=(--ai "${SAIF_AI_PROVIDER:-ollama}")
    demo_args+=("${debug_args[@]}" "${extra_args[@]}")
    run_saif "${demo_args[@]}"
    ;;
  finding)
    subcommand="${1:-}"
    shift || true
    run_saif finding "$subcommand" "$@"
    ;;
  fix)
    subcommand="${1:-}"
    shift || true
    run_saif fix "$subcommand" "$@"
    ;;
  prompt)
    if [[ $# -lt 1 ]]; then
      echo "ERROR: prompt text is required." >&2
      exit 2
    fi
    prompt_text="$1"
    shift || true
    cli_target="$(arg_value --target "$@")"
    debug_args=()
    if has_flag --debug "$@"; then
      debug_args=(--debug)
    fi
    if [[ -n "${cli_target:-}" ]]; then
      run_saif prompt "$prompt_text" --target "$cli_target" --target-source "cli-arg" "${debug_args[@]}"
    else
      run_saif prompt "$prompt_text" "${debug_args[@]}"
    fi
    ;;
  *)
    cat <<'USAGE'
Usage: ./saif.sh <command> [options]

Commands:
  setup
  doctor [--target http://host:port]
  init-db
  list-testcases
  install-tools
  install-tool <tool>
  debug-export --scan-id 1
  create-project [--target http://host:port]
  scan --target http://host:port
  report
  run-demo --target http://host:port
  prompt "default enumeration. here is the target: http://host:port"
  prompt "search shodan, find build technology, do nmap enumeration and here is the target: http://host:port"
  tools status
  tools refresh [--install-missing]
  scan start --target http://host:port
  scan start --target http://host:port --profile crapi --full --debug
  scan start --target http://host:port --mode black-box
  scan start --target http://host:port --mode gray-box --credentials configs/credentials.yaml --full
  scan start --target http://host:port --mode white-box --source-path /path/to/repo --full
  scan pause --scan-id 1
  scan resume --scan-id 1
  scan stop --scan-id 1
  scan status --scan-id 1
  scan watch --scan-id 1
  scan list
  scan show --scan-id 1
  scan continue --scan-id 1 --phase authenticated_crawling
  scan continue --scan-id 1 --phase account_provisioning --full
  scan report --scan-id 1 --format html
  scan retest --scan-id 1
  scan retest --scan-id 1 --only-open-findings
  finding retest --finding-id 1
  finding close --finding-id 1
  fix suggest --finding-id 1 --source-path /path/to/repo
  fix patch --finding-id 1 --source-path /path/to/repo --dry-run
  dashboard start
  dashboard start --host 0.0.0.0 --port 8787
  dashboard status
  dashboard stop
  logs tail --scan-id 1
  logs tail --scan-id 1 --follow

Target priority:
  1. --target
  2. target URL extracted from prompt text
  3. TARGET_URL environment variable for temporary one-time shell use
  4. interactive prompt
  5. clear failure

Caution:
  Use only on authorized testing/staging environments.
  Tester is responsible for confirming scope and approval.
USAGE
    exit 1
    ;;
esac
