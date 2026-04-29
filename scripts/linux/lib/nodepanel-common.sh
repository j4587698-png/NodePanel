#!/usr/bin/env bash
set -euo pipefail

NODEPANEL_COMMON_LOADED=1
NODEPANEL_COMMON_SOURCE="${BASH_SOURCE[0]}"
NODEPANEL_SOURCE_MODE=""
NODEPANEL_RESOLVED_GITHUB_REPO=""
NODEPANEL_RESOLVED_GITHUB_TAG=""
NODEPANEL_RESOLVED_PACKAGE_RID=""

np_log() {
    printf '[nodepanel] %s\n' "$*" >&2
}

np_warn() {
    printf '[nodepanel] WARN: %s\n' "$*" >&2
}

np_die() {
    printf '[nodepanel] ERROR: %s\n' "$*" >&2
    exit 1
}

np_require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        np_die "This script only supports Linux."
    fi
}

np_require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        np_die "Please run this command as root."
    fi
}

np_require_cmd() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        np_die "Missing required command: ${command_name}"
    fi
}

np_first_non_empty() {
    local value
    for value in "$@"; do
        if [[ -n "${value:-}" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
    done

    printf '\n'
}

np_is_url() {
    local value="${1:-}"
    [[ "$value" =~ ^https?:// ]]
}

np_is_github_repo() {
    local value="${1:-}"
    [[ "$value" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]
}

np_archive_name_from_url() {
    local url="$1"
    local sanitized_url="${url%%\#*}"
    sanitized_url="${sanitized_url%%\?*}"

    local file_name="${sanitized_url##*/}"
    case "$file_name" in
        *.tar.gz|*.tgz|*.tar|*.zip)
            printf '%s\n' "$file_name"
            return 0
            ;;
        *)
            np_die "Cannot determine archive type from URL: ${url}. Use a URL ending with .tar.gz, .tgz, .tar or .zip."
            ;;
    esac
}

np_abs_path() {
    local value="${1:-}"
    if [[ -z "$value" ]]; then
        printf '\n'
        return 0
    fi

    if [[ "$value" == /* ]]; then
        printf '%s\n' "$value"
        return 0
    fi

    printf '%s\n' "$(pwd)/${value}"
}

np_strip_wrapping_quotes() {
    local value="${1-}"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
    fi

    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
    value="${value//\\\$/\$}"
    value="${value//\\\`/\`}"
    printf '%s\n' "$value"
}

np_read_key_value_file_value() {
    local file_path="$1"
    local key="$2"

    if [[ ! -f "$file_path" ]]; then
        printf '\n'
        return 0
    fi

    local raw_value
    raw_value="$(awk -v key="$key" '
        index($0, key "=") == 1 {
            print substr($0, length(key) + 2)
            exit
        }
    ' "$file_path")"

    np_strip_wrapping_quotes "$raw_value"
}

np_resolve_package_version() {
    local package_info_path="$1"
    local resolved_github_tag="${2:-}"
    local package_info_version

    package_info_version="$(np_read_key_value_file_value "$package_info_path" "version")"
    printf '%s\n' "$(np_first_non_empty "$package_info_version" "${resolved_github_tag#v}")"
}

np_normalize_version() {
    local version="${1-}"
    version="$(np_strip_wrapping_quotes "$version")"
    version="${version#"${version%%[![:space:]]*}"}"
    version="${version%"${version##*[![:space:]]}"}"
    version="${version#v}"
    version="${version#V}"
    version="${version%%+*}"
    printf '%s\n' "$version"
}

np_is_numeric_identifier() {
    local value="${1:-}"
    [[ "$value" =~ ^[0-9]+$ ]]
}

np_compare_versions() {
    local left
    local right
    left="$(np_normalize_version "${1-}")"
    right="$(np_normalize_version "${2-}")"

    if [[ "$left" == "$right" ]]; then
        printf '0\n'
        return 0
    fi

    local left_core="$left"
    local right_core="$right"
    local left_prerelease=""
    local right_prerelease=""

    if [[ "$left" == *-* ]]; then
        left_core="${left%%-*}"
        left_prerelease="${left#*-}"
    fi

    if [[ "$right" == *-* ]]; then
        right_core="${right%%-*}"
        right_prerelease="${right#*-}"
    fi

    local -a left_core_parts=()
    local -a right_core_parts=()
    local old_ifs="$IFS"
    IFS='.'
    read -r -a left_core_parts <<< "$left_core"
    read -r -a right_core_parts <<< "$right_core"
    IFS="$old_ifs"

    local max_core_parts="${#left_core_parts[@]}"
    if [[ "${#right_core_parts[@]}" -gt "$max_core_parts" ]]; then
        max_core_parts="${#right_core_parts[@]}"
    fi

    local index
    for ((index = 0; index < max_core_parts; index++)); do
        local left_part="${left_core_parts[$index]:-0}"
        local right_part="${right_core_parts[$index]:-0}"

        if ! np_is_numeric_identifier "$left_part"; then
            left_part="0"
        fi

        if ! np_is_numeric_identifier "$right_part"; then
            right_part="0"
        fi

        if ((10#$left_part > 10#$right_part)); then
            printf '1\n'
            return 0
        fi

        if ((10#$left_part < 10#$right_part)); then
            printf '%s\n' '-1'
            return 0
        fi
    done

    if [[ -z "$left_prerelease" && -z "$right_prerelease" ]]; then
        printf '0\n'
        return 0
    fi

    if [[ -z "$left_prerelease" ]]; then
        printf '1\n'
        return 0
    fi

    if [[ -z "$right_prerelease" ]]; then
        printf '%s\n' '-1'
        return 0
    fi

    local -a left_pre_parts=()
    local -a right_pre_parts=()
    IFS='.'
    read -r -a left_pre_parts <<< "$left_prerelease"
    read -r -a right_pre_parts <<< "$right_prerelease"
    IFS="$old_ifs"

    local max_pre_parts="${#left_pre_parts[@]}"
    if [[ "${#right_pre_parts[@]}" -gt "$max_pre_parts" ]]; then
        max_pre_parts="${#right_pre_parts[@]}"
    fi

    for ((index = 0; index < max_pre_parts; index++)); do
        local left_id="${left_pre_parts[$index]:-}"
        local right_id="${right_pre_parts[$index]:-}"

        if [[ -z "$left_id" && -n "$right_id" ]]; then
            printf '%s\n' '-1'
            return 0
        fi

        if [[ -n "$left_id" && -z "$right_id" ]]; then
            printf '1\n'
            return 0
        fi

        if [[ "$left_id" == "$right_id" ]]; then
            continue
        fi

        if np_is_numeric_identifier "$left_id" && np_is_numeric_identifier "$right_id"; then
            if ((10#$left_id > 10#$right_id)); then
                printf '1\n'
                return 0
            fi

            printf '%s\n' '-1'
            return 0
        fi

        if np_is_numeric_identifier "$left_id"; then
            printf '%s\n' '-1'
            return 0
        fi

        if np_is_numeric_identifier "$right_id"; then
            printf '1\n'
            return 0
        fi

        if [[ "$left_id" > "$right_id" ]]; then
            printf '1\n'
            return 0
        fi

        printf '%s\n' '-1'
        return 0
    done

    printf '0\n'
}

np_should_skip_update_version() {
    local display_name="$1"
    local operation_name="$2"
    local installed_version
    local target_version
    local comparison

    if [[ "$operation_name" != "update" ]]; then
        return 1
    fi

    installed_version="$(np_normalize_version "${3-}")"
    target_version="$(np_normalize_version "${4-}")"

    if [[ -z "$installed_version" ]]; then
        np_warn "${display_name}: installed package version is unknown. Continuing update."
        return 1
    fi

    if [[ -z "$target_version" ]]; then
        np_warn "${display_name}: target package version is unknown. Continuing update."
        return 1
    fi

    comparison="$(np_compare_versions "$target_version" "$installed_version")"
    case "$comparison" in
        1)
            np_log "${display_name}: update available ${installed_version} -> ${target_version}"
            return 1
            ;;
        0)
            np_log "${display_name}: installed version ${installed_version} is already up to date. Skipping update."
            return 0
            ;;
        -1)
            np_warn "${display_name}: target version ${target_version} is not newer than installed version ${installed_version}. Skipping update. Use install to reinstall or downgrade."
            return 0
            ;;
        *)
            np_warn "${display_name}: failed to compare versions (${installed_version} vs ${target_version}). Continuing update."
            return 1
            ;;
    esac
}

np_resolve_nologin_shell() {
    local candidate
    for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/false /bin/false; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    printf '/usr/sbin/nologin\n'
}

np_ensure_service_account() {
    local account_group="$1"
    local account_user="$2"
    local home_dir="$3"

    if ! getent group "$account_group" >/dev/null 2>&1; then
        groupadd --system "$account_group"
    fi

    if ! id -u "$account_user" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "$account_group" \
            --home-dir "$home_dir" \
            --create-home \
            --shell "$(np_resolve_nologin_shell)" \
            "$account_user"
    fi
}

np_download_file() {
    local url="$1"
    local output_path="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 15 -o "$output_path" "$url"
        return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -O "$output_path" "$url"
        return 0
    fi

    np_die "Neither curl nor wget is available for downloading package sources."
}

np_detect_linux_rid() {
    local machine_arch
    machine_arch="$(uname -m)"

    case "$machine_arch" in
        x86_64|amd64|x64)
            printf 'linux-x64\n'
            ;;
        aarch64|arm64)
            printf 'linux-arm64\n'
            ;;
        armv7l|armv7|armhf|armv6l|armv6)
            printf 'linux-arm\n'
            ;;
        *)
            np_die "Unsupported Linux architecture: ${machine_arch}. Use --rid to specify the package runtime explicitly."
            ;;
    esac
}

np_build_package_asset_name() {
    local package_prefix="$1"
    local package_rid="$2"
    printf '%s-%s.tar.gz\n' "$package_prefix" "$package_rid"
}

np_build_github_release_url() {
    local github_repo="$1"
    local asset_name="$2"
    local github_tag="${3:-}"

    if [[ -z "$github_tag" || "$github_tag" == "latest" ]]; then
        printf 'https://github.com/%s/releases/latest/download/%s\n' "$github_repo" "$asset_name"
        return 0
    fi

    printf 'https://github.com/%s/releases/download/%s/%s\n' "$github_repo" "$github_tag" "$asset_name"
}

np_fetch_github_latest_tag() {
    local github_repo="$1"
    local latest_url="https://github.com/${github_repo}/releases/latest"
    local effective_url=""

    if command -v curl >/dev/null 2>&1; then
        effective_url="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        effective_url="$(wget --server-response --spider --max-redirect=20 "$latest_url" 2>&1 | awk '
            /^[[:space:]]*Location: / {
                url=$2
            }
            END {
                gsub(/\r/, "", url)
                print url
            }
        ' || true)"
    fi

    if [[ -z "$effective_url" ]]; then
        printf '\n'
        return 0
    fi

    if [[ "$effective_url" != *"/releases/tag/"* ]]; then
        printf '\n'
        return 0
    fi

    local resolved_tag="${effective_url##*/}"
    if [[ -z "$resolved_tag" || "$resolved_tag" == "latest" ]]; then
        printf '\n'
        return 0
    fi

    printf '%s\n' "$resolved_tag"
}

np_resolve_github_request_ref() {
    local source_arg="${1:-}"
    local explicit_repo="${2:-}"
    local explicit_tag="${3:-}"
    local saved_repo="${4:-}"

    local repo="$explicit_repo"
    local tag="$explicit_tag"

    if [[ -n "$source_arg" ]]; then
        if np_is_url "$source_arg"; then
            return 1
        fi

        local absolute_source
        absolute_source="$(np_abs_path "$source_arg")"
        if [[ -d "$absolute_source" || -f "$absolute_source" ]]; then
            return 1
        fi

        if [[ "$source_arg" == *"@"* ]]; then
            local repo_candidate="${source_arg%@*}"
            local tag_candidate="${source_arg#*@}"
            if np_is_github_repo "$repo_candidate" && [[ -n "$tag_candidate" ]]; then
                repo="$repo_candidate"
                tag="$tag_candidate"
            fi
        elif np_is_github_repo "$source_arg"; then
            repo="$source_arg"
        elif [[ -n "$repo" ]]; then
            tag="$(np_first_non_empty "$tag" "$source_arg")"
        fi
    fi

    repo="$(np_first_non_empty "$repo" "$saved_repo")"
    if [[ -z "$repo" ]]; then
        return 1
    fi

    printf '%s\n%s\n' "$repo" "$tag"
}

np_resolve_github_release_target() {
    local source_arg="${1:-}"
    local explicit_repo="${2:-}"
    local explicit_tag="${3:-}"
    local saved_repo="${4:-}"

    local resolved_ref
    if ! resolved_ref="$(np_resolve_github_request_ref "$source_arg" "$explicit_repo" "$explicit_tag" "$saved_repo")"; then
        return 1
    fi

    local resolved_repo
    local resolved_tag
    resolved_repo="$(printf '%s\n' "$resolved_ref" | sed -n '1p')"
    resolved_tag="$(printf '%s\n' "$resolved_ref" | sed -n '2p')"

    if [[ -z "$resolved_tag" || "$resolved_tag" == "latest" ]]; then
        resolved_tag="$(np_fetch_github_latest_tag "$resolved_repo")"
    fi

    printf '%s\n%s\n%s\n' \
        "$resolved_repo" \
        "$resolved_tag" \
        "$(np_normalize_version "$resolved_tag")"
}

np_resolve_source_version_hint() {
    local source_arg="${1:-}"
    local explicit_repo="${2:-}"
    local explicit_tag="${3:-}"
    local saved_repo="${4:-}"

    local resolved_target
    if ! resolved_target="$(np_resolve_github_release_target "$source_arg" "$explicit_repo" "$explicit_tag" "$saved_repo")"; then
        printf '\n'
        return 0
    fi

    printf '%s\n' "$(printf '%s\n' "$resolved_target" | sed -n '3p')"
}

np_extract_archive() {
    local archive_path="$1"
    local destination_dir="$2"

    mkdir -p "$destination_dir"

    case "$archive_path" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive_path" -C "$destination_dir"
            ;;
        *.tar)
            tar -xf "$archive_path" -C "$destination_dir"
            ;;
        *.zip)
            np_require_cmd unzip
            unzip -q "$archive_path" -d "$destination_dir"
            ;;
        *)
            np_die "Unsupported package format: ${archive_path}"
            ;;
    esac
}

np_locate_package_root() {
    local extracted_root="$1"

    if [[ -d "$extracted_root/app" ]]; then
        printf '%s\n' "$extracted_root"
        return 0
    fi

    local entries=()
    while IFS= read -r -d '' item; do
        entries+=("$item")
    done < <(find "$extracted_root" -mindepth 1 -maxdepth 1 -type d -print0)

    if [[ "${#entries[@]}" -eq 1 && -d "${entries[0]}/app" ]]; then
        printf '%s\n' "${entries[0]}"
        return 0
    fi

    np_die "Cannot locate package root that contains an app/ directory."
}

np_prepare_github_release_source() {
    local github_repo="$1"
    local github_tag="${2:-}"
    local package_prefix="$3"
    local package_rid="${4:-}"
    local temp_root="$5"
    local resolved_github_tag="$github_tag"

    if ! np_is_github_repo "$github_repo"; then
        np_die "Invalid GitHub repository reference: ${github_repo}. Use owner/repo."
    fi

    if [[ -z "$package_prefix" ]]; then
        np_die "Missing package prefix for GitHub package lookup."
    fi

    if [[ -z "$package_rid" ]]; then
        package_rid="$(np_detect_linux_rid)"
    fi

    if [[ -z "$resolved_github_tag" || "$resolved_github_tag" == "latest" ]]; then
        resolved_github_tag="$(np_fetch_github_latest_tag "$github_repo")"
    fi

    local asset_name
    asset_name="$(np_build_package_asset_name "$package_prefix" "$package_rid")"

    local downloaded_archive="${temp_root}/${asset_name}"
    local extracted_dir="${temp_root}/package-extract"
    local release_url
    release_url="$(np_build_github_release_url "$github_repo" "$asset_name" "$(np_first_non_empty "$resolved_github_tag" "$github_tag")")"

    if [[ -n "$resolved_github_tag" ]]; then
        np_log "Downloading ${asset_name} from GitHub repo ${github_repo} (${resolved_github_tag})"
    elif [[ -n "$github_tag" && "$github_tag" != "latest" ]]; then
        np_log "Downloading ${asset_name} from GitHub repo ${github_repo} (${github_tag})"
    else
        np_log "Downloading ${asset_name} from GitHub repo ${github_repo} (latest)"
    fi

    np_download_file "$release_url" "$downloaded_archive"

    NODEPANEL_SOURCE_MODE="github"
    NODEPANEL_RESOLVED_GITHUB_REPO="$github_repo"
    NODEPANEL_RESOLVED_GITHUB_TAG="$(np_first_non_empty "$resolved_github_tag" "$github_tag")"
    NODEPANEL_RESOLVED_PACKAGE_RID="$package_rid"

    np_extract_archive "$downloaded_archive" "$extracted_dir"
    np_locate_package_root "$extracted_dir"
}

np_prepare_source_dir() {
    local script_dir="$1"
    local source_arg="${2:-}"
    local temp_root="$3"
    local package_prefix="${4:-}"
    local github_repo="${5:-}"
    local github_tag="${6:-}"
    local package_rid="${7:-}"

    NODEPANEL_SOURCE_MODE=""
    NODEPANEL_RESOLVED_GITHUB_REPO=""
    NODEPANEL_RESOLVED_GITHUB_TAG=""
    NODEPANEL_RESOLVED_PACKAGE_RID=""

    if [[ -z "$source_arg" ]]; then
        if [[ -d "$script_dir/app" ]]; then
            NODEPANEL_SOURCE_MODE="script-dir"
            printf '%s\n' "$script_dir"
            return 0
        fi

        if [[ -n "$github_repo" ]]; then
            np_prepare_github_release_source "$github_repo" "$github_tag" "$package_prefix" "$package_rid" "$temp_root"
            return 0
        fi

        np_die "No package source was provided, and the current directory does not contain an app/ folder. Pass a package directory, archive path, package URL or GitHub repo."
    fi

    if np_is_url "$source_arg"; then
        local archive_name
        archive_name="$(np_archive_name_from_url "$source_arg")"

        local downloaded_archive="$temp_root/${archive_name}"
        local extracted_dir="$temp_root/package-extract"
        np_log "Downloading package from ${source_arg}"
        np_download_file "$source_arg" "$downloaded_archive"
        NODEPANEL_SOURCE_MODE="url"
        np_extract_archive "$downloaded_archive" "$extracted_dir"
        np_locate_package_root "$extracted_dir"
        return 0
    fi

    local absolute_source
    absolute_source="$(np_abs_path "$source_arg")"

    if [[ -d "$absolute_source" ]]; then
        if [[ -d "$absolute_source/app" ]]; then
            NODEPANEL_SOURCE_MODE="directory"
            printf '%s\n' "$absolute_source"
            return 0
        fi

        np_die "Source directory must contain an app/ folder: ${absolute_source}"
    fi

    if [[ -f "$absolute_source" ]]; then
        local extracted_dir="$temp_root/package-extract"
        NODEPANEL_SOURCE_MODE="archive"
        np_extract_archive "$absolute_source" "$extracted_dir"
        np_locate_package_root "$extracted_dir"
        return 0
    fi

    if [[ "$source_arg" == *"@"* ]]; then
        local repo_candidate="${source_arg%@*}"
        local tag_candidate="${source_arg#*@}"
        if np_is_github_repo "$repo_candidate" && [[ -n "$tag_candidate" ]]; then
            np_prepare_github_release_source "$repo_candidate" "$tag_candidate" "$package_prefix" "$package_rid" "$temp_root"
            return 0
        fi
    fi

    if np_is_github_repo "$source_arg"; then
        np_prepare_github_release_source "$source_arg" "$github_tag" "$package_prefix" "$package_rid" "$temp_root"
        return 0
    fi

    if [[ -n "$github_repo" ]]; then
        np_prepare_github_release_source "$github_repo" "$source_arg" "$package_prefix" "$package_rid" "$temp_root"
        return 0
    fi

    np_die "Package source not found: ${source_arg}"
}

np_install_runtime_scripts() {
    local component_script_source="$1"
    local common_script_source="$2"
    local installed_script_path="$3"
    local installed_common_dir="$4"
    local manager_script_source="${5:-}"
    local installed_manager_path="${6:-}"
    local installed_common_path="${installed_common_dir}/nodepanel-common.sh"

    mkdir -p "$installed_common_dir"

    if [[ ! -e "$installed_common_path" || ! "$common_script_source" -ef "$installed_common_path" ]]; then
        install -m 644 "$common_script_source" "$installed_common_path"
    fi

    if [[ ! -e "$installed_script_path" || ! "$component_script_source" -ef "$installed_script_path" ]]; then
        install -m 755 "$component_script_source" "$installed_script_path"
    fi

    if [[ -n "$manager_script_source" && -n "$installed_manager_path" && -f "$manager_script_source" ]]; then
        if [[ ! -e "$installed_manager_path" || ! "$manager_script_source" -ef "$installed_manager_path" ]]; then
            install -m 755 "$manager_script_source" "$installed_manager_path"
        fi
    fi
}

np_resolve_manager_script_source() {
    local script_dir="$1"
    local env_source="${NODEPANEL_MANAGER_SCRIPT_SOURCE:-}"

    if [[ -n "$env_source" && -f "$env_source" ]]; then
        np_abs_path "$env_source"
        return 0
    fi

    if [[ -f "${script_dir}/nodepanel.sh" ]]; then
        np_abs_path "${script_dir}/nodepanel.sh"
        return 0
    fi

    printf '\n'
}

np_copy_dir_contents() {
    local source_dir="$1"
    local destination_dir="$2"

    mkdir -p "$destination_dir"
    cp -a "$source_dir/." "$destination_dir/"
}

np_remove_path_if_exists() {
    local target_path="$1"
    if [[ -e "$target_path" || -L "$target_path" ]]; then
        rm -rf "$target_path"
    fi
}

np_chown_if_exists() {
    local owner="$1"
    local target_path="$2"
    if [[ -e "$target_path" || -L "$target_path" ]]; then
        chown -R "$owner" "$target_path"
    fi
}

np_quote_env_value() {
    local value="${1-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\$}"
    value="${value//\`/\\\`}"
    printf '"%s"\n' "$value"
}

np_upsert_env_value() {
    local env_file="$1"
    local env_key="$2"
    local env_value="$3"
    local quoted_value
    local temp_file

    mkdir -p "$(dirname "$env_file")"
    touch "$env_file"

    quoted_value="$(np_quote_env_value "$env_value")"
    temp_file="$(mktemp)"

    awk -v key="$env_key" -v value="$quoted_value" '
        BEGIN { updated = 0 }
        index($0, key "=") == 1 {
            print key "=" value
            updated = 1
            next
        }
        { print }
        END {
            if (!updated) {
                print key "=" value
            }
        }
    ' "$env_file" > "$temp_file"

    cat "$temp_file" > "$env_file"
    rm -f "$temp_file"
}
