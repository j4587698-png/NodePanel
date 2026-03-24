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

readonly DISPLAY_NAME="NodePanel Panel"
readonly SYSTEMD_NAME="nodepanel-panel"
readonly INSTALL_ROOT="/usr/local/nodepanel-panel"
readonly APP_DIR="${INSTALL_ROOT}/app"
readonly DATA_DIR="${INSTALL_ROOT}/data"
readonly BIN_PATH="/usr/local/bin/nodepanel-panel"
readonly COMMON_INSTALL_DIR="/usr/local/lib/nodepanel"
readonly ENV_DIR="/etc/nodepanel"
readonly ENV_FILE="${ENV_DIR}/panel.env"
readonly UNIT_FILE="/etc/systemd/system/${SYSTEMD_NAME}.service"
readonly SYSTEM_USER="nodepanel-panel"
readonly SYSTEM_GROUP="nodepanel-panel"
readonly EXECUTABLE_NAME="NodePanel.Panel"
readonly DLL_NAME="NodePanel.Panel.dll"
readonly LAUNCHER_PATH="${INSTALL_ROOT}/run.sh"
readonly SELF_SCRIPT_SOURCE="$(np_abs_path "${BASH_SOURCE[0]}")"
readonly COMMON_SCRIPT_SOURCE="$(np_abs_path "${NODEPANEL_COMMON_SOURCE}")"
readonly PACKAGE_PREFIX="nodepanel-panel"
readonly DEFAULT_GITHUB_REPO="${NODEPANEL_DEFAULT_GITHUB_REPO:-}"

PACKAGE_SOURCE_ARG=""
PACKAGE_GITHUB_REPO=""
PACKAGE_GITHUB_TAG=""
PACKAGE_RID=""
PACKAGE_VERSION=""
SAVED_PACKAGE_GITHUB_REPO=""
SAVED_PACKAGE_RID=""

usage() {
    cat <<'EOF'
Usage:
  nodepanel-panel.sh install [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-panel.sh update [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-panel.sh start
  nodepanel-panel.sh stop
  nodepanel-panel.sh restart
  nodepanel-panel.sh status
  nodepanel-panel.sh log [-f] [lines]
  nodepanel-panel.sh enable
  nodepanel-panel.sh disable
  nodepanel-panel.sh uninstall [--purge]

Options:
  --github-repo OWNER/REPO
  --version TAG
  --tag TAG
  --rid RID

Examples:
  bash install.sh install
  bash install.sh install owner/repo
  bash install.sh install v1.2.3 --github-repo owner/repo
  bash install.sh install https://downloads.example.com/nodepanel-panel-linux-x64.tar.gz
  nodepanel-panel update /tmp/nodepanel-panel-linux-x64.tar.gz
  nodepanel-panel update owner/repo@v1.2.3
  nodepanel-panel update
  nodepanel-panel log -f 200
EOF
}

require_option_value() {
    local option_name="$1"
    local option_value="${2:-}"
    if [[ -z "$option_value" ]]; then
        np_die "Missing value for ${option_name}"
    fi
}

parse_package_arguments() {
    local command_name="$1"
    shift || true

    PACKAGE_SOURCE_ARG=""
    PACKAGE_GITHUB_REPO=""
    PACKAGE_GITHUB_TAG=""
    PACKAGE_RID=""
    PACKAGE_VERSION=""

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --github-repo)
                require_option_value "$1" "${2:-}"
                PACKAGE_GITHUB_REPO="$2"
                shift 2
                ;;
            --version|--tag)
                require_option_value "$1" "${2:-}"
                PACKAGE_GITHUB_TAG="$2"
                shift 2
                ;;
            --rid)
                require_option_value "$1" "${2:-}"
                PACKAGE_RID="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            --*)
                np_die "Unknown option for ${command_name}: $1"
                ;;
            *)
                if [[ -n "$PACKAGE_SOURCE_ARG" ]]; then
                    np_die "Only one package source may be provided for ${command_name}."
                fi

                PACKAGE_SOURCE_ARG="$1"
                shift
                ;;
        esac
    done
}

load_saved_package_defaults() {
    SAVED_PACKAGE_GITHUB_REPO="$(np_first_non_empty \
        "$PACKAGE_GITHUB_REPO" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO")" \
        "${NODEPANEL_GITHUB_REPO:-}" \
        "$DEFAULT_GITHUB_REPO")"
    SAVED_PACKAGE_RID="$(np_first_non_empty \
        "$PACKAGE_RID" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID")")"
}

load_package_info_defaults() {
    local source_root="$1"
    local package_info_path="${source_root}/PACKAGE_INFO"

    local package_info_repo
    local package_info_rid
    package_info_repo="$(np_read_key_value_file_value "$package_info_path" "github_repo")"
    package_info_rid="$(np_read_key_value_file_value "$package_info_path" "rid")"
    PACKAGE_VERSION="$(np_resolve_package_version "$package_info_path" "$NODEPANEL_RESOLVED_GITHUB_TAG")"

    PACKAGE_GITHUB_REPO="$(np_first_non_empty \
        "$PACKAGE_GITHUB_REPO" \
        "$NODEPANEL_RESOLVED_GITHUB_REPO" \
        "$package_info_repo" \
        "$SAVED_PACKAGE_GITHUB_REPO")"
    PACKAGE_RID="$(np_first_non_empty \
        "$PACKAGE_RID" \
        "$NODEPANEL_RESOLVED_PACKAGE_RID" \
        "$package_info_rid" \
        "$SAVED_PACKAGE_RID")"
}

persist_package_defaults() {
    if [[ -n "$PACKAGE_GITHUB_REPO" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO" "$PACKAGE_GITHUB_REPO"
    fi

    if [[ -n "$PACKAGE_RID" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID" "$PACKAGE_RID"
    fi
}

persist_package_version() {
    np_upsert_env_value "$ENV_FILE" "NODEPANEL_PACKAGE_VERSION" "$PACKAGE_VERSION"
}

write_launcher_file() {
    cat >"$1" <<EOF
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR}"

if [[ -x "\${APP_DIR}/${EXECUTABLE_NAME}" ]]; then
    exec "\${APP_DIR}/${EXECUTABLE_NAME}"
fi

if command -v dotnet >/dev/null 2>&1 && [[ -f "\${APP_DIR}/${DLL_NAME}" ]]; then
    exec dotnet "\${APP_DIR}/${DLL_NAME}"
fi

echo "Unable to locate ${EXECUTABLE_NAME} or ${DLL_NAME} in \${APP_DIR}" >&2
exit 1
EOF
}

write_unit_file() {
    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=${DISPLAY_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=${LAUNCHER_PATH}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

write_default_env_file() {
    mkdir -p "$ENV_DIR"

    cat >"$ENV_FILE" <<EOF
DOTNET_ENVIRONMENT=Production
# Keep HTTP on 80 for first-time install, ACME http-01 and local ws control-plane access.
ASPNETCORE_URLS=http://0.0.0.0:80
# When Panel HTTPS listener address/port changes from the web UI, restart automatically under systemd.
Panel__AutoRestartOnHttpsChange=true
Panel__DataFilePath=${DATA_DIR}/panel-state.json
EOF

    chmod 640 "$ENV_FILE"
}

write_fresh_appsettings() {
    cat >"$1" <<'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Panel": {
    "AppName": "NodePanel",
    "DataFilePath": "../data/panel-state.json",
    "AutoRegisterUnknownNodes": true,
    "AdminToken": "",
    "PublicBaseUrl": "",
    "SubscribeUrls": [],
    "DbType": "",
    "DbConnectionString": ""
  }
}
EOF
}

preserve_existing_files() {
    local old_app_dir="$1"
    local new_app_dir="$2"

    mkdir -p "$DATA_DIR"

    if [[ -e "${old_app_dir}/server.db" && ! -L "${old_app_dir}/server.db" && ! -f "${DATA_DIR}/server.db" ]]; then
        mv "${old_app_dir}/server.db" "${DATA_DIR}/server.db"
    fi

    if [[ -e "${old_app_dir}/panel-state.json" && ! -L "${old_app_dir}/panel-state.json" && ! -f "${DATA_DIR}/panel-state.json" ]]; then
        mv "${old_app_dir}/panel-state.json" "${DATA_DIR}/panel-state.json"
    fi

    if [[ -f "${old_app_dir}/appsettings.json" ]]; then
        cp -a "${old_app_dir}/appsettings.json" "${new_app_dir}/appsettings.json"
    else
        write_fresh_appsettings "${new_app_dir}/appsettings.json"
    fi

    np_remove_path_if_exists "${new_app_dir}/server.db"
    np_remove_path_if_exists "${new_app_dir}/panel-state.json"
    ln -sfn "../data/server.db" "${new_app_dir}/server.db"
    ln -sfn "../data/panel-state.json" "${new_app_dir}/panel-state.json"
}

install_or_update() {
    local operation_name="$1"
    shift || true

    np_require_linux
    np_require_root
    np_require_cmd tar
    np_require_cmd systemctl

    parse_package_arguments "$operation_name" "$@"
    load_saved_package_defaults

    local temp_root
    temp_root="$(mktemp -d)"
    trap 'temp_root_path="${temp_root:-}"; if [[ -n "$temp_root_path" ]]; then rm -rf -- "$temp_root_path"; fi' EXIT

    local source_root
    source_root="$(np_prepare_source_dir "$SCRIPT_DIR" "$PACKAGE_SOURCE_ARG" "$temp_root" "$PACKAGE_PREFIX" "$SAVED_PACKAGE_GITHUB_REPO" "$PACKAGE_GITHUB_TAG" "$SAVED_PACKAGE_RID")"
    load_package_info_defaults "$source_root"

    local source_app_dir="${source_root}/app"
    local staged_app_dir="${temp_root}/staged-app"
    local staged_launcher="${temp_root}/run.sh"

    if [[ ! -d "$source_app_dir" ]]; then
        np_die "Package source does not contain an app/ directory."
    fi

    np_ensure_service_account "$SYSTEM_GROUP" "$SYSTEM_USER" "$INSTALL_ROOT"
    mkdir -p "$INSTALL_ROOT" "$DATA_DIR" "$ENV_DIR"

    np_copy_dir_contents "$source_app_dir" "$staged_app_dir"
    preserve_existing_files "$APP_DIR" "$staged_app_dir"
    write_launcher_file "$staged_launcher"

    np_install_runtime_scripts "$SELF_SCRIPT_SOURCE" "$COMMON_SCRIPT_SOURCE" "$BIN_PATH" "$COMMON_INSTALL_DIR"

    if [[ ! -f "$ENV_FILE" ]]; then
        write_default_env_file
    fi

    persist_package_defaults
    persist_package_version

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl stop "${SYSTEMD_NAME}.service" || true
    fi

    np_remove_path_if_exists "$APP_DIR"
    mv "$staged_app_dir" "$APP_DIR"
    mv "$staged_launcher" "$LAUNCHER_PATH"

    chmod 755 "$LAUNCHER_PATH"
    if [[ -f "${APP_DIR}/${EXECUTABLE_NAME}" ]]; then
        chmod 755 "${APP_DIR}/${EXECUTABLE_NAME}"
    fi

    chown -R "${SYSTEM_USER}:${SYSTEM_GROUP}" "$INSTALL_ROOT"
    chown "${SYSTEM_USER}:${SYSTEM_GROUP}" "$ENV_FILE"

    write_unit_file
    systemctl daemon-reload
    systemctl enable "${SYSTEMD_NAME}.service" >/dev/null
    systemctl restart "${SYSTEMD_NAME}.service"

    np_log "${DISPLAY_NAME} has been installed to ${INSTALL_ROOT}"
    np_log "Environment file: ${ENV_FILE}"
    np_log "Installed package version: ${PACKAGE_VERSION:-unknown}"
    np_log "Fresh installations should open http://<server>/install to finish database and admin setup."
    systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
}

uninstall_component() {
    local purge="${1:-0}"

    np_require_linux
    np_require_root
    np_require_cmd systemctl

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl disable --now "${SYSTEMD_NAME}.service" || true
        rm -f "$UNIT_FILE"
        systemctl daemon-reload
    fi

    rm -f "$BIN_PATH"
    rm -f "$LAUNCHER_PATH"
    rm -rf "$APP_DIR"

    if [[ "$purge" == "1" ]]; then
        rm -rf "$INSTALL_ROOT"
        rm -f "$ENV_FILE"
        np_log "${DISPLAY_NAME} has been fully removed."
        return 0
    fi

    np_log "${DISPLAY_NAME} executable files have been removed."
    np_warn "Data and configuration were kept:"
    np_warn "  ${DATA_DIR}"
    np_warn "  ${ENV_FILE}"
}

run_systemctl() {
    local action="$1"
    np_require_linux
    np_require_cmd systemctl
    systemctl "$action" "${SYSTEMD_NAME}.service"
}

show_logs() {
    local follow="0"
    local lines="200"

    if [[ "${1:-}" == "-f" ]]; then
        follow="1"
        shift || true
    fi

    if [[ -n "${1:-}" ]]; then
        lines="$1"
    fi

    np_require_linux
    np_require_cmd journalctl

    if [[ "$follow" == "1" ]]; then
        journalctl -u "${SYSTEMD_NAME}.service" -n "$lines" -f
        return 0
    fi

    journalctl -u "${SYSTEMD_NAME}.service" -n "$lines" --no-pager
}

panel_is_installed() {
    [[ -f "$UNIT_FILE" || -x "$BIN_PATH" || -d "$INSTALL_ROOT" ]]
}

show_installed_metadata() {
    local current_version
    local current_repo
    local current_rid

    current_version="$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_VERSION")"
    current_repo="$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO")"
    current_rid="$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID")"

    printf 'Installed Version : %s\n' "${current_version:-"(not set)"}"
    printf 'GitHub Repo       : %s\n' "${current_repo:-"${DEFAULT_GITHUB_REPO:-"(not set)"}"}"
    printf 'Package RID       : %s\n' "${current_rid:-"(auto)"}"
}

show_status_command() {
    show_installed_metadata

    if ! panel_is_installed; then
        np_warn "${DISPLAY_NAME} is not installed yet."
        return 0
    fi

    printf '%s\n' '----------------------------------------'
    systemctl status "${SYSTEMD_NAME}.service" --no-pager --full || true
}

main() {
    local command="${1:-}"
    shift || true

    case "$command" in
        install)
            install_or_update install "$@"
            ;;
        update)
            install_or_update update "$@"
            ;;
        start)
            np_require_root
            run_systemctl start
            ;;
        stop)
            np_require_root
            run_systemctl stop
            ;;
        restart)
            np_require_root
            run_systemctl restart
            ;;
        status)
            show_status_command
            ;;
        log|logs)
            show_logs "$@"
            ;;
        enable)
            np_require_root
            run_systemctl enable
            ;;
        disable)
            np_require_root
            run_systemctl disable
            ;;
        uninstall)
            if [[ "${1:-}" == "--purge" ]]; then
                uninstall_component 1
            else
                uninstall_component 0
            fi
            ;;
        ""|-h|--help|help)
            usage
            ;;
        *)
            usage
            np_die "Unknown command: ${command}"
            ;;
    esac
}

main "$@"
