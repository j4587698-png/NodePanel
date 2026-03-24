#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_ROOT="${REPO_ROOT}/artifacts/linux"
CONFIGURATION="Release"
SELF_CONTAINED="true"
COMPONENTS=("service" "panel")
RIDS=("linux-x64")
GITHUB_REPO=""
VERSION=""

usage() {
    cat <<'EOF'
Usage:
  publish-linux.sh [options]

Options:
  --component service|panel|all   Build only one component. Default: all
  --rid RID                       Runtime identifier. Can be repeated. Default: linux-x64
  --configuration Release|Debug   Build configuration. Default: Release
  --self-contained true|false     Publish self-contained panel packages. Default: true
  --output-root PATH              Package output directory
  --github-repo OWNER/REPO        Persist GitHub release repo metadata into PACKAGE_INFO
  --version SEMVER                Override .NET/package version metadata
  -h, --help                      Show help

Examples:
  ./publish-linux.sh
  ./publish-linux.sh --component service --rid linux-arm64
  ./publish-linux.sh --github-repo owner/repo --rid linux-x64 --rid linux-arm64
  ./publish-linux.sh --github-repo owner/repo --version 0.1.0 --rid linux-x64
  ./publish-linux.sh --rid linux-x64 --rid linux-arm64 --self-contained false

Notes:
  service packages are always published as Native AOT self-contained binaries.
  --self-contained only changes panel packaging.
EOF
}

require_dotnet() {
    if ! command -v dotnet >/dev/null 2>&1; then
        printf 'dotnet command not found\n' >&2
        exit 1
    fi
}

set_components() {
    local component="$1"
    case "$component" in
        all)
            COMPONENTS=("service" "panel")
            ;;
        service|panel)
            COMPONENTS=("$component")
            ;;
        *)
            printf 'Unsupported component: %s\n' "$component" >&2
            exit 1
            ;;
    esac
}

package_component() {
    local component="$1"
    local rid="$2"

    local project_path
    local installer_path
    local package_prefix

    case "$component" in
        service)
            project_path="${REPO_ROOT}/service/NodePanel.Service/NodePanel.Service.csproj"
            installer_path="${SCRIPT_DIR}/nodepanel-service.sh"
            package_prefix="nodepanel-service"
            ;;
        panel)
            project_path="${REPO_ROOT}/panel/NodePanel.Panel/NodePanel.Panel.csproj"
            installer_path="${SCRIPT_DIR}/nodepanel-panel.sh"
            package_prefix="nodepanel-panel"
            ;;
        *)
            printf 'Unsupported component: %s\n' "$component" >&2
            exit 1
            ;;
    esac

    local package_name="${package_prefix}-${rid}"
    local work_root="${OUTPUT_ROOT}/work/${package_name}"
    local publish_dir="${work_root}/publish"
    local package_dir="${work_root}/${package_name}"
    local tarball_path="${OUTPUT_ROOT}/${package_name}.tar.gz"
    local common_script_path="${SCRIPT_DIR}/lib/nodepanel-common.sh"
    local readme_path="${SCRIPT_DIR}/README.md"
    local build_time
    local git_commit
    local publish_mode
    local component_self_contained
    local -a publish_args

    rm -rf "$work_root"
    mkdir -p "$publish_dir" "$package_dir/app" "$OUTPUT_ROOT"

    publish_mode="dotnet-publish"
    component_self_contained="$SELF_CONTAINED"
    publish_args=(
        --configuration "$CONFIGURATION"
        --runtime "$rid"
        --output "$publish_dir"
    )

    case "$component" in
        service)
            publish_mode="native-aot"
            component_self_contained="true"
            publish_args+=(
                --self-contained "true"
                -p:PublishAot=true
                -p:DebugSymbols=false
                -p:DebugType=None
                -p:StripSymbols=true
            )
            ;;
        panel)
            if [[ "$SELF_CONTAINED" == "true" ]]; then
                publish_mode="self-contained"
            else
                publish_mode="framework-dependent"
            fi

            publish_args+=(
                --self-contained "$SELF_CONTAINED"
                -p:UseAppHost=true
                -p:PublishSingleFile=false
                -p:PublishReadyToRun=false
            )
            ;;
    esac

    if [[ -n "$VERSION" ]]; then
        publish_args+=("-p:Version=$VERSION")
    fi

    printf '[publish] %s %s (%s)\n' "$component" "$rid" "$publish_mode"
    dotnet publish "$project_path" "${publish_args[@]}"

    cp -a "$publish_dir/." "$package_dir/app/"
    cp "$installer_path" "$package_dir/install.sh"
    cp "$common_script_path" "$package_dir/nodepanel-common.sh"
    cp "$readme_path" "$package_dir/README.md"
    chmod +x "$package_dir/install.sh" || true

    build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    git_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
    cat >"${package_dir}/PACKAGE_INFO" <<EOF
component=${component}
rid=${rid}
configuration=${CONFIGURATION}
self_contained=${component_self_contained}
publish_mode=${publish_mode}
git_commit=${git_commit}
build_time=${build_time}
github_repo=${GITHUB_REPO}
version=${VERSION}
EOF

    tar -czf "$tarball_path" -C "$work_root" "$package_name"
    printf '[publish] created %s\n' "$tarball_path"
}

main() {
    local raw_rids=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --component)
                [[ $# -ge 2 ]] || { printf 'Missing value for --component\n' >&2; exit 1; }
                set_components "$2"
                shift 2
                ;;
            --rid)
                [[ $# -ge 2 ]] || { printf 'Missing value for --rid\n' >&2; exit 1; }
                raw_rids+=("$2")
                shift 2
                ;;
            --configuration)
                [[ $# -ge 2 ]] || { printf 'Missing value for --configuration\n' >&2; exit 1; }
                CONFIGURATION="$2"
                shift 2
                ;;
            --self-contained)
                [[ $# -ge 2 ]] || { printf 'Missing value for --self-contained\n' >&2; exit 1; }
                SELF_CONTAINED="$2"
                shift 2
                ;;
            --output-root)
                [[ $# -ge 2 ]] || { printf 'Missing value for --output-root\n' >&2; exit 1; }
                OUTPUT_ROOT="$2"
                shift 2
                ;;
            --github-repo)
                [[ $# -ge 2 ]] || { printf 'Missing value for --github-repo\n' >&2; exit 1; }
                GITHUB_REPO="$2"
                shift 2
                ;;
            --version)
                [[ $# -ge 2 ]] || { printf 'Missing value for --version\n' >&2; exit 1; }
                VERSION="$2"
                shift 2
                ;;
            -h|--help|help)
                usage
                exit 0
                ;;
            *)
                printf 'Unknown argument: %s\n' "$1" >&2
                usage
                exit 1
                ;;
        esac
    done

    if [[ "${#raw_rids[@]}" -gt 0 ]]; then
        RIDS=("${raw_rids[@]}")
    fi

    require_dotnet
    mkdir -p "$OUTPUT_ROOT"

    local component
    local rid
    for component in "${COMPONENTS[@]}"; do
        for rid in "${RIDS[@]}"; do
            package_component "$component" "$rid"
        done
    done
}

main "$@"
