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

readonly DISPLAY_NAME="NodePanel Service"
readonly SYSTEMD_NAME="nodepanel-service"
readonly INSTALL_ROOT="/usr/local/nodepanel-service"
readonly APP_DIR="${INSTALL_ROOT}/app"
readonly DATA_DIR="${INSTALL_ROOT}/data"
readonly CERT_DIR="${DATA_DIR}/certificates"
readonly BIN_PATH="/usr/local/bin/nodepanel-service"
readonly COMMON_INSTALL_DIR="/usr/local/lib/nodepanel"
readonly ENV_DIR="/etc/nodepanel"
readonly ENV_FILE="${ENV_DIR}/service.env"
readonly UNIT_FILE="/etc/systemd/system/${SYSTEMD_NAME}.service"
readonly SYSTEM_USER="nodepanel-service"
readonly SYSTEM_GROUP="nodepanel-service"
readonly EXECUTABLE_NAME="NodePanel.Service"
readonly DLL_NAME="NodePanel.Service.dll"
readonly LAUNCHER_PATH="${INSTALL_ROOT}/run.sh"
readonly SELF_SCRIPT_SOURCE="$(np_abs_path "${BASH_SOURCE[0]}")"
readonly COMMON_SCRIPT_SOURCE="$(np_abs_path "${NODEPANEL_COMMON_SOURCE}")"
readonly PACKAGE_PREFIX="nodepanel-service"
readonly DEFAULT_GITHUB_REPO="${NODEPANEL_DEFAULT_GITHUB_REPO:-}"

SERVICE_PANEL_URL=""
SERVICE_NODE_ID=""
SERVICE_ACCESS_TOKEN=""
SERVICE_ASPNETCORE_URLS=""
SERVICE_SOURCE_ARG=""
SERVICE_GITHUB_REPO=""
SERVICE_GITHUB_TAG=""
SERVICE_PACKAGE_RID=""
SAVED_PACKAGE_GITHUB_REPO=""
SAVED_PACKAGE_RID=""

usage() {
    cat <<'EOF'
Usage:
  nodepanel-service.sh install [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-service.sh update [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-service.sh configure [options]
  nodepanel-service.sh start
  nodepanel-service.sh stop
  nodepanel-service.sh restart
  nodepanel-service.sh status
  nodepanel-service.sh log [-f] [lines]
  nodepanel-service.sh enable
  nodepanel-service.sh disable
  nodepanel-service.sh uninstall [--purge]

Options:
  --panel-url URL
  --control-plane-url URL
  --node-id ID
  --access-token TOKEN
  --control-plane-access-token TOKEN
  --aspnetcore-urls URLS
  --service-urls URLS
  --github-repo OWNER/REPO
  --version TAG
  --tag TAG
  --rid RID

Examples:
  bash install.sh install --panel-url wss://panel.example.com/control/ws --node-id node-001
  bash install.sh install owner/repo --panel-url wss://panel.example.com/control/ws --node-id node-001
  bash install.sh install v1.2.3 --github-repo owner/repo --panel-url wss://panel.example.com/control/ws --node-id node-001
  bash install.sh install https://downloads.example.com/nodepanel-service-linux-x64.tar.gz --panel-url wss://panel.example.com/control/ws --node-id node-001
  nodepanel-service update /tmp/nodepanel-service-linux-x64.tar.gz --panel-url ws://127.0.0.1/control/ws
  nodepanel-service update owner/repo@v1.2.3
  nodepanel-service update
  nodepanel-service configure --access-token your-token
  nodepanel-service log -f 200
EOF
}

require_option_value() {
    local option_name="$1"
    local option_value="${2:-}"
    if [[ -z "$option_value" ]]; then
        np_die "Missing value for ${option_name}"
    fi
}

parse_config_arguments() {
    local command_name="$1"
    shift || true

    SERVICE_PANEL_URL=""
    SERVICE_NODE_ID=""
    SERVICE_ACCESS_TOKEN=""
    SERVICE_ASPNETCORE_URLS=""
    SERVICE_SOURCE_ARG=""
    SERVICE_GITHUB_REPO=""
    SERVICE_GITHUB_TAG=""
    SERVICE_PACKAGE_RID=""

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --panel-url|--control-plane-url)
                require_option_value "$1" "${2:-}"
                SERVICE_PANEL_URL="$2"
                shift 2
                ;;
            --node-id)
                require_option_value "$1" "${2:-}"
                SERVICE_NODE_ID="$2"
                shift 2
                ;;
            --access-token|--control-plane-access-token)
                require_option_value "$1" "${2:-}"
                SERVICE_ACCESS_TOKEN="$2"
                shift 2
                ;;
            --aspnetcore-urls|--service-urls)
                require_option_value "$1" "${2:-}"
                SERVICE_ASPNETCORE_URLS="$2"
                shift 2
                ;;
            --github-repo)
                require_option_value "$1" "${2:-}"
                SERVICE_GITHUB_REPO="$2"
                shift 2
                ;;
            --version|--tag)
                require_option_value "$1" "${2:-}"
                SERVICE_GITHUB_TAG="$2"
                shift 2
                ;;
            --rid)
                require_option_value "$1" "${2:-}"
                SERVICE_PACKAGE_RID="$2"
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
                if [[ -n "$SERVICE_SOURCE_ARG" ]]; then
                    np_die "Only one package source may be provided for ${command_name}."
                fi

                SERVICE_SOURCE_ARG="$1"
                shift
                ;;
        esac
    done
}

load_saved_package_defaults() {
    SAVED_PACKAGE_GITHUB_REPO="$(np_first_non_empty \
        "$SERVICE_GITHUB_REPO" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO")" \
        "${NODEPANEL_GITHUB_REPO:-}" \
        "$DEFAULT_GITHUB_REPO")"
    SAVED_PACKAGE_RID="$(np_first_non_empty \
        "$SERVICE_PACKAGE_RID" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID")")"
}

load_package_info_defaults() {
    local source_root="$1"
    local package_info_path="${source_root}/PACKAGE_INFO"

    local package_info_repo
    local package_info_rid
    package_info_repo="$(np_read_key_value_file_value "$package_info_path" "github_repo")"
    package_info_rid="$(np_read_key_value_file_value "$package_info_path" "rid")"

    SERVICE_GITHUB_REPO="$(np_first_non_empty \
        "$SERVICE_GITHUB_REPO" \
        "$NODEPANEL_RESOLVED_GITHUB_REPO" \
        "$package_info_repo" \
        "$SAVED_PACKAGE_GITHUB_REPO")"
    SERVICE_PACKAGE_RID="$(np_first_non_empty \
        "$SERVICE_PACKAGE_RID" \
        "$NODEPANEL_RESOLVED_PACKAGE_RID" \
        "$package_info_rid" \
        "$SAVED_PACKAGE_RID")"
}

persist_package_defaults() {
    if [[ -n "$SERVICE_GITHUB_REPO" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO" "$SERVICE_GITHUB_REPO"
    fi

    if [[ -n "$SERVICE_PACKAGE_RID" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID" "$SERVICE_PACKAGE_RID"
    fi
}

fix_env_file_owner() {
    if id -u "$SYSTEM_USER" >/dev/null 2>&1; then
        chown "${SYSTEM_USER}:${SYSTEM_GROUP}" "$ENV_FILE"
    fi
}

apply_env_overrides() {
    if [[ ! -f "$ENV_FILE" ]]; then
        write_default_env_file
    fi

    if [[ -n "$SERVICE_ASPNETCORE_URLS" ]]; then
        np_upsert_env_value "$ENV_FILE" "ASPNETCORE_URLS" "$SERVICE_ASPNETCORE_URLS"
    fi

    if [[ -n "$SERVICE_PANEL_URL" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__PanelUrl" "$SERVICE_PANEL_URL"
    fi

    if [[ -n "$SERVICE_NODE_ID" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__Identity__NodeId" "$SERVICE_NODE_ID"
    fi

    if [[ -n "$SERVICE_ACCESS_TOKEN" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__ControlPlane__AccessToken" "$SERVICE_ACCESS_TOKEN"
    fi

    chmod 640 "$ENV_FILE"
    fix_env_file_owner
}

has_env_overrides() {
    [[ -n "$SERVICE_PANEL_URL" || -n "$SERVICE_NODE_ID" || -n "$SERVICE_ACCESS_TOKEN" || -n "$SERVICE_ASPNETCORE_URLS" ]]
}

has_package_overrides() {
    [[ -n "$SERVICE_GITHUB_REPO" || -n "$SERVICE_PACKAGE_RID" ]]
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
ASPNETCORE_URLS=http://127.0.0.1:6610
NodePanel__CachedConfigPath=${DATA_DIR}/node-runtime-config.json

# Required before the node can connect to the panel:
# Same host / local direct-run example:
# NodePanel__PanelUrl=ws://127.0.0.1/control/ws
# Public panel HTTPS / WSS example:
# NodePanel__PanelUrl=wss://panel.example.com/control/ws
# NodePanel__Identity__NodeId=node-001
# NodePanel__ControlPlane__AccessToken=
EOF

    chmod 640 "$ENV_FILE"
}

preserve_existing_files() {
    local old_app_dir="$1"
    local new_app_dir="$2"

    if [[ -f "${old_app_dir}/appsettings.json" ]]; then
        cp -a "${old_app_dir}/appsettings.json" "${new_app_dir}/appsettings.json"
    fi

    if [[ -e "${old_app_dir}/node-runtime-config.json" && ! -L "${old_app_dir}/node-runtime-config.json" && ! -f "${DATA_DIR}/node-runtime-config.json" ]]; then
        mv "${old_app_dir}/node-runtime-config.json" "${DATA_DIR}/node-runtime-config.json"
    fi

    if [[ -d "${old_app_dir}/certificates" && ! -L "${old_app_dir}/certificates" ]]; then
        mkdir -p "$CERT_DIR"
        cp -a "${old_app_dir}/certificates/." "$CERT_DIR/"
    fi

    mkdir -p "$CERT_DIR"
    np_remove_path_if_exists "${new_app_dir}/node-runtime-config.json"
    np_remove_path_if_exists "${new_app_dir}/certificates"
    ln -sfn "../data/node-runtime-config.json" "${new_app_dir}/node-runtime-config.json"
    ln -sfn "../data/certificates" "${new_app_dir}/certificates"
}

install_or_update() {
    local operation_name="$1"
    shift || true
    parse_config_arguments "$operation_name" "$@"

    np_require_linux
    np_require_root
    np_require_cmd tar
    np_require_cmd systemctl

    load_saved_package_defaults

    local temp_root
    temp_root="$(mktemp -d)"
    trap 'rm -rf "$temp_root"' EXIT

    local source_root
    source_root="$(np_prepare_source_dir "$SCRIPT_DIR" "$SERVICE_SOURCE_ARG" "$temp_root" "$PACKAGE_PREFIX" "$SAVED_PACKAGE_GITHUB_REPO" "$SERVICE_GITHUB_TAG" "$SAVED_PACKAGE_RID")"
    load_package_info_defaults "$source_root"
    local source_app_dir="${source_root}/app"
    local staged_app_dir="${temp_root}/staged-app"
    local staged_launcher="${temp_root}/run.sh"

    if [[ ! -d "$source_app_dir" ]]; then
        np_die "Package source does not contain an app/ directory."
    fi

    np_ensure_service_account "$SYSTEM_GROUP" "$SYSTEM_USER" "$INSTALL_ROOT"
    mkdir -p "$INSTALL_ROOT" "$DATA_DIR" "$CERT_DIR" "$ENV_DIR"

    np_copy_dir_contents "$source_app_dir" "$staged_app_dir"
    preserve_existing_files "$APP_DIR" "$staged_app_dir"
    write_launcher_file "$staged_launcher"

    np_install_runtime_scripts "$SELF_SCRIPT_SOURCE" "$COMMON_SCRIPT_SOURCE" "$BIN_PATH" "$COMMON_INSTALL_DIR"

    if [[ ! -f "$ENV_FILE" ]]; then
        write_default_env_file
    fi

    apply_env_overrides
    persist_package_defaults

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
    fix_env_file_owner

    write_unit_file
    systemctl daemon-reload
    systemctl enable "${SYSTEMD_NAME}.service" >/dev/null
    systemctl restart "${SYSTEMD_NAME}.service"

    np_log "${DISPLAY_NAME} has been installed to ${INSTALL_ROOT}"
    np_log "Environment file: ${ENV_FILE}"
    systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
}

configure_component() {
    parse_config_arguments configure "$@"

    np_require_linux
    np_require_root

    if [[ -n "$SERVICE_SOURCE_ARG" ]]; then
        np_die "The configure command does not accept a package source."
    fi

    if [[ -n "$SERVICE_GITHUB_TAG" ]]; then
        np_die "The configure command does not accept --version or --tag."
    fi

    if ! has_env_overrides && ! has_package_overrides; then
        np_die "No configuration options were provided."
    fi

    load_saved_package_defaults
    apply_env_overrides
    persist_package_defaults
    np_log "Updated ${ENV_FILE}"

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl restart "${SYSTEMD_NAME}.service"
        systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
        return 0
    fi

    np_warn "${DISPLAY_NAME} is not installed yet. Configuration was written only."
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
        configure)
            configure_component "$@"
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
            run_systemctl status
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
