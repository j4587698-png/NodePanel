#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMON_CANDIDATES=(
    "$SCRIPT_DIR/lib/nodepanel-common.sh"
    "$SCRIPT_DIR/nodepanel-common.sh"
    "/usr/local/lib/nodepanel/nodepanel-common.sh"
)

for candidate in "${COMMON_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
        # shellcheck source=/dev/null
        source "$candidate"
        break
    fi
done

if [[ "${NODEPANEL_COMMON_LOADED:-0}" != "1" ]]; then
    printf 'Failed to load nodepanel-common.sh\n' >&2
    exit 1
fi

readonly DISPLAY_NAME="NodePanel"
readonly PANEL_COMPONENT="panel"
readonly SERVICE_COMPONENT="service"
readonly PANEL_COMMAND_NAME="nodepanel-panel"
readonly SERVICE_COMMAND_NAME="nodepanel-service"
readonly PANEL_SYSTEMD_NAME="nodepanel-panel"
readonly SERVICE_SYSTEMD_NAME="nodepanel-service"
readonly PANEL_INSTALL_ROOT="/usr/local/nodepanel-panel"
readonly SERVICE_INSTALL_ROOT="/usr/local/nodepanel-service"
readonly PANEL_ENV_FILE="/etc/nodepanel/panel.env"
readonly SERVICE_ENV_FILE="/etc/nodepanel/service.env"
readonly COLOR_RED=$'\033[0;31m'
readonly COLOR_GREEN=$'\033[0;32m'
readonly COLOR_YELLOW=$'\033[0;33m'
readonly COLOR_CYAN=$'\033[0;36m'
readonly COLOR_PLAIN=$'\033[0m'

usage() {
    cat <<'EOF'
Usage:
  nodepanel                         (interactive menu)
  nodepanel status
  nodepanel panel <command> [args...]
  nodepanel service <command> [args...]
  nodepanel log panel|service [-f] [lines]
  nodepanel update [panel|service|all] [source] [options]
  nodepanel restart [panel|service|all]
  nodepanel start panel|service|all
  nodepanel stop panel|service|all
  nodepanel enable panel|service|all
  nodepanel disable panel|service|all

Examples:
  sudo nodepanel
  nodepanel status
  sudo nodepanel update all
  sudo nodepanel service configure
  sudo nodepanel log service -f 200
EOF
}

trim_value() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}

is_interactive_session() {
    [[ -t 0 && -t 1 ]]
}

pause_for_menu() {
    printf '\nPress Enter to continue...' >&2
    IFS= read -r _ || true
}

component_label() {
    case "${1:-}" in
        "$PANEL_COMPONENT")
            printf 'Panel\n'
            ;;
        "$SERVICE_COMPONENT")
            printf 'Service\n'
            ;;
        *)
            printf '%s\n' "${1:-unknown}"
            ;;
    esac
}

component_command_name() {
    case "${1:-}" in
        "$PANEL_COMPONENT")
            printf '%s\n' "$PANEL_COMMAND_NAME"
            ;;
        "$SERVICE_COMPONENT")
            printf '%s\n' "$SERVICE_COMMAND_NAME"
            ;;
        *)
            return 1
            ;;
    esac
}

component_systemd_name() {
    case "${1:-}" in
        "$PANEL_COMPONENT")
            printf '%s\n' "$PANEL_SYSTEMD_NAME"
            ;;
        "$SERVICE_COMPONENT")
            printf '%s\n' "$SERVICE_SYSTEMD_NAME"
            ;;
        *)
            return 1
            ;;
    esac
}

component_install_root() {
    case "${1:-}" in
        "$PANEL_COMPONENT")
            printf '%s\n' "$PANEL_INSTALL_ROOT"
            ;;
        "$SERVICE_COMPONENT")
            printf '%s\n' "$SERVICE_INSTALL_ROOT"
            ;;
        *)
            return 1
            ;;
    esac
}

component_env_file() {
    case "${1:-}" in
        "$PANEL_COMPONENT")
            printf '%s\n' "$PANEL_ENV_FILE"
            ;;
        "$SERVICE_COMPONENT")
            printf '%s\n' "$SERVICE_ENV_FILE"
            ;;
        *)
            return 1
            ;;
    esac
}

component_command_path() {
    local component="$1"
    local command_name
    command_name="$(component_command_name "$component")"

    if command -v "$command_name" >/dev/null 2>&1; then
        command -v "$command_name"
        return 0
    fi

    local default_path="/usr/local/bin/${command_name}"
    if [[ -x "$default_path" ]]; then
        printf '%s\n' "$default_path"
        return 0
    fi

    return 1
}

component_is_installed() {
    local component="$1"
    local systemd_name
    local install_root
    systemd_name="$(component_systemd_name "$component")"
    install_root="$(component_install_root "$component")"

    [[ -f "/etc/systemd/system/${systemd_name}.service" || -d "$install_root" ]] && return 0
    component_command_path "$component" >/dev/null 2>&1
}

component_active_state() {
    local component="$1"
    local systemd_name

    if ! component_is_installed "$component"; then
        printf 'not-installed\n'
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'unknown\n'
        return 0
    fi

    systemd_name="$(component_systemd_name "$component")"
    systemctl is-active "${systemd_name}.service" 2>/dev/null || true
}

component_enabled_state() {
    local component="$1"
    local systemd_name

    if ! component_is_installed "$component"; then
        printf 'not-installed\n'
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'unknown\n'
        return 0
    fi

    systemd_name="$(component_systemd_name "$component")"
    systemctl is-enabled "${systemd_name}.service" 2>/dev/null || true
}

render_state_label() {
    local state="${1:-unknown}"
    case "$state" in
        active|enabled)
            printf '%s%s%s\n' "$COLOR_GREEN" "$state" "$COLOR_PLAIN"
            ;;
        activating|reloading)
            printf '%s%s%s\n' "$COLOR_YELLOW" "$state" "$COLOR_PLAIN"
            ;;
        inactive|failed|deactivating|disabled)
            printf '%s%s%s\n' "$COLOR_RED" "$state" "$COLOR_PLAIN"
            ;;
        not-installed)
            printf '%snot installed%s\n' "$COLOR_RED" "$COLOR_PLAIN"
            ;;
        *)
            printf '%s\n' "$state"
            ;;
    esac
}

component_version() {
    local env_file
    env_file="$(component_env_file "$1")"
    np_read_key_value_file_value "$env_file" "NODEPANEL_PACKAGE_VERSION"
}

show_component_row() {
    local component="$1"
    local label
    local active_state
    local enabled_state
    local version

    label="$(component_label "$component")"
    active_state="$(component_active_state "$component")"
    enabled_state="$(component_enabled_state "$component")"
    version="$(component_version "$component")"

    printf '%-7s : %s / %s / version %s\n' \
        "$label" \
        "$(render_state_label "$active_state")" \
        "$(render_state_label "$enabled_state")" \
        "${version:-unknown}"
}

show_status_overview() {
    printf '\n%sNodePanel Status%s\n' "$COLOR_CYAN" "$COLOR_PLAIN"
    printf '%s\n' '----------------------------------------'
    show_component_row "$PANEL_COMPONENT"
    show_component_row "$SERVICE_COMPONENT"
}

confirm_choice() {
    local prompt_text="$1"
    local default_value="${2:-n}"
    local input_value
    local hint='y/N'

    if [[ "$default_value" == "y" ]]; then
        hint='Y/n'
    fi

    printf '%s [%s]: ' "$prompt_text" "$hint" >&2
    if ! IFS= read -r input_value; then
        printf '\n' >&2
        return 1
    fi

    input_value="$(trim_value "$input_value")"
    if [[ -z "$input_value" ]]; then
        input_value="$default_value"
    fi

    case "$input_value" in
        y|Y|yes|YES|Yes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

prompt_optional_value() {
    local label="$1"
    local default_value="${2:-}"
    local input_value

    if [[ -n "$default_value" ]]; then
        printf '%s [%s]: ' "$label" "$default_value" >&2
    else
        printf '%s: ' "$label" >&2
    fi

    if ! IFS= read -r input_value; then
        printf '\n' >&2
        return 1
    fi

    input_value="$(trim_value "$input_value")"
    if [[ -z "$input_value" ]]; then
        input_value="$default_value"
    fi

    printf '%s\n' "$input_value"
}

prompt_component_target() {
    local include_all="${1:-0}"
    local require_all_installed="${2:-0}"
    local prompt_text="Choose component"
    local choice

    printf '%s\n' '  1. Panel' >&2
    printf '%s\n' '  2. Service' >&2
    if [[ "$include_all" == "1" ]]; then
        printf '%s\n' '  3. All installed components' >&2
        prompt_text="Choose component [1-3]"
    else
        prompt_text="Choose component [1-2]"
    fi

    printf '%s: ' "$prompt_text" >&2
    if ! IFS= read -r choice; then
        printf '\n' >&2
        return 1
    fi

    case "$(trim_value "$choice")" in
        1)
            printf '%s\n' "$PANEL_COMPONENT"
            ;;
        2)
            printf '%s\n' "$SERVICE_COMPONENT"
            ;;
        3)
            if [[ "$include_all" != "1" ]]; then
                return 1
            fi
            if [[ "$require_all_installed" == "1" ]] && ! any_component_installed; then
                np_warn "No installed components were found."
                return 1
            fi
            printf 'all\n'
            ;;
        *)
            np_warn "Invalid component selection."
            return 1
            ;;
    esac
}

any_component_installed() {
    component_is_installed "$PANEL_COMPONENT" || component_is_installed "$SERVICE_COMPONENT"
}

run_component_command() {
    local component="$1"
    shift || true

    local command_path
    if ! command_path="$(component_command_path "$component")"; then
        np_warn "$(component_label "$component") command is not installed yet."
        return 1
    fi

    "$command_path" "$@"
}

run_component_command_allow_failure() {
    set +e
    run_component_command "$@"
    local status=$?
    set -e
    return "$status"
}

run_target_command_allow_failure() {
    local target="$1"
    shift || true

    if [[ "$target" == "all" ]]; then
        local ran="0"
        local component
        for component in "$PANEL_COMPONENT" "$SERVICE_COMPONENT"; do
            if component_is_installed "$component"; then
                ran="1"
                printf '\n[%s]\n' "$(component_label "$component")" >&2
                run_component_command_allow_failure "$component" "$@" || true
            fi
        done
        if [[ "$ran" != "1" ]]; then
            np_warn "No installed components were found."
            return 1
        fi
        return 0
    fi

    run_component_command_allow_failure "$target" "$@"
}

prompt_package_source() {
    printf '%s\n' "Package source: leave blank to use saved/latest GitHub release." >&2
    prompt_optional_value "Package source" ""
}

menu_update_components() {
    local target
    if ! target="$(prompt_component_target 1 1)"; then
        return 0
    fi

    np_require_root

    if [[ "$target" == "all" ]]; then
        run_target_command_allow_failure "$target" update
        return 0
    fi

    local source_arg
    source_arg="$(prompt_package_source)"
    if [[ -n "$source_arg" ]]; then
        run_component_command_allow_failure "$target" update "$source_arg" || true
    else
        run_component_command_allow_failure "$target" update || true
    fi
}

menu_restart_components() {
    local target
    if ! target="$(prompt_component_target 1 1)"; then
        return 0
    fi

    np_require_root
    run_target_command_allow_failure "$target" restart
}

menu_start_stop_components() {
    local action
    printf '%s\n' '  1. Start' >&2
    printf '%s\n' '  2. Stop' >&2
    printf 'Choose action [1-2]: ' >&2
    if ! IFS= read -r action; then
        printf '\n' >&2
        return 0
    fi

    case "$(trim_value "$action")" in
        1)
            action="start"
            ;;
        2)
            action="stop"
            ;;
        *)
            np_warn "Invalid action selection."
            return 0
            ;;
    esac

    local target
    if ! target="$(prompt_component_target 1 1)"; then
        return 0
    fi

    np_require_root
    run_target_command_allow_failure "$target" "$action"
}

menu_enable_disable_components() {
    local action
    printf '%s\n' '  1. Enable auto start' >&2
    printf '%s\n' '  2. Disable auto start' >&2
    printf 'Choose action [1-2]: ' >&2
    if ! IFS= read -r action; then
        printf '\n' >&2
        return 0
    fi

    case "$(trim_value "$action")" in
        1)
            action="enable"
            ;;
        2)
            action="disable"
            ;;
        *)
            np_warn "Invalid action selection."
            return 0
            ;;
    esac

    local target
    if ! target="$(prompt_component_target 1 1)"; then
        return 0
    fi

    np_require_root
    run_target_command_allow_failure "$target" "$action"
}

menu_show_logs() {
    local target
    if ! target="$(prompt_component_target 0 0)"; then
        return 0
    fi

    local lines
    lines="$(prompt_optional_value "Log lines" "200")"

    if confirm_choice "Follow logs" "y"; then
        printf 'Press Ctrl+C to stop following logs.\n' >&2
        run_component_command_allow_failure "$target" log -f "${lines:-200}" || true
        return 0
    fi

    run_component_command_allow_failure "$target" log "${lines:-200}" || true
}

menu_configure_service() {
    if ! component_is_installed "$SERVICE_COMPONENT"; then
        np_warn "NodePanel Service is not installed yet."
        return 0
    fi

    np_require_root
    run_component_command_allow_failure "$SERVICE_COMPONENT" configure || true
}

menu_open_service_menu() {
    if ! component_is_installed "$SERVICE_COMPONENT"; then
        np_warn "NodePanel Service is not installed yet."
        return 0
    fi

    run_component_command_allow_failure "$SERVICE_COMPONENT" || true
}

menu_uninstall_components() {
    local target
    if ! target="$(prompt_component_target 1 1)"; then
        return 0
    fi

    if [[ "$target" == "all" ]]; then
        if ! confirm_choice "Uninstall all installed NodePanel components?" "n"; then
            return 0
        fi
    elif ! confirm_choice "Uninstall NodePanel $(component_label "$target")?" "n"; then
        return 0
    fi

    local purge_flag="0"
    if confirm_choice "Delete data and environment files as well" "n"; then
        purge_flag="1"
    fi

    np_require_root

    if [[ "$purge_flag" == "1" ]]; then
        run_target_command_allow_failure "$target" uninstall --purge
    else
        run_target_command_allow_failure "$target" uninstall
    fi
}

show_menu() {
    while true; do
        clear 2>/dev/null || true
        printf '\n%sNodePanel Manager%s\n' "$COLOR_CYAN" "$COLOR_PLAIN"
        printf '%s\n' '----------------------------------------'
        show_component_row "$PANEL_COMPONENT"
        show_component_row "$SERVICE_COMPONENT"
        printf '%s\n' '----------------------------------------'
        cat <<'EOF'
  1. Show Status Overview
  2. Update Components
  3. Restart Components
  4. View Logs
  5. Reconfigure Service Node Info
  6. Start / Stop Components
  7. Enable / Disable Auto Start
  8. Open Service Advanced Menu
  9. Uninstall Components
  0. Exit
EOF

        printf 'Choose [0-9]: ' >&2
        local choice
        if ! IFS= read -r choice; then
            printf '\n' >&2
            return 0
        fi

        case "$(trim_value "$choice")" in
            1)
                show_status_overview
                pause_for_menu
                ;;
            2)
                menu_update_components
                pause_for_menu
                ;;
            3)
                menu_restart_components
                pause_for_menu
                ;;
            4)
                menu_show_logs
                pause_for_menu
                ;;
            5)
                menu_configure_service
                pause_for_menu
                ;;
            6)
                menu_start_stop_components
                pause_for_menu
                ;;
            7)
                menu_enable_disable_components
                pause_for_menu
                ;;
            8)
                menu_open_service_menu
                pause_for_menu
                ;;
            9)
                menu_uninstall_components
                pause_for_menu
                ;;
            0|q|quit|exit)
                return 0
                ;;
            *)
                np_warn "Please enter a valid number between 0 and 9."
                sleep 1
                ;;
        esac
    done
}

normalize_target_arg() {
    local value="${1:-all}"
    case "$value" in
        "$PANEL_COMPONENT"|"$SERVICE_COMPONENT"|all)
            printf '%s\n' "$value"
            ;;
        *)
            return 1
            ;;
    esac
}

run_root_target_command() {
    local command_name="$1"
    local target="${2:-all}"
    shift 2 || true

    np_require_root
    run_target_command_allow_failure "$target" "$command_name" "$@"
}

main() {
    local command="${1:-}"

    case "$command" in
        ""|menu)
            if is_interactive_session; then
                show_menu
            else
                usage
            fi
            ;;
        status)
            show_status_overview
            ;;
        "$PANEL_COMPONENT"|"$SERVICE_COMPONENT")
            shift || true
            run_component_command "$command" "$@"
            ;;
        log|logs)
            shift || true
            local target="${1:-}"
            if [[ "$target" != "$PANEL_COMPONENT" && "$target" != "$SERVICE_COMPONENT" ]]; then
                usage
                np_die "The log command requires panel or service."
            fi
            shift || true
            run_component_command "$target" log "$@"
            ;;
        update)
            shift || true
            local target="all"
            if [[ "$#" -gt 0 ]]; then
                if target="$(normalize_target_arg "${1:-}")"; then
                    shift || true
                fi
            fi
            run_root_target_command "$command" "$target" "$@"
            ;;
        restart|start|stop|enable|disable)
            shift || true
            local target="all"
            if [[ "$#" -gt 0 ]]; then
                if ! target="$(normalize_target_arg "${1:-}")"; then
                    usage
                    np_die "Invalid target: ${1:-}. Use panel, service or all."
                fi
                shift || true
            fi
            run_root_target_command "$command" "$target" "$@"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            np_die "Unknown command: ${command}"
            ;;
    esac
}

main "$@"
