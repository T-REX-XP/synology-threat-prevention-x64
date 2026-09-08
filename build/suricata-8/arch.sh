# Arch names used by native/Docker Suricata builds. Source from repo scripts.
# TPS_ARCH is x86_64 or aarch64.

normalize_tps_arch() {
    case "$1" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *)
            echo "ERROR: unsupported arch '$1' (x86_64 or aarch64)" >&2
            return 1
            ;;
    esac
}

arch_engine_suffix() {
    case "$(normalize_tps_arch "$1")" in
        x86_64) echo linux-amd64 ;;
        aarch64) echo linux-arm64 ;;
    esac
}

arch_docker_platform() {
    case "$(normalize_tps_arch "$1")" in
        x86_64) echo linux/amd64 ;;
        aarch64) echo linux/arm64 ;;
    esac
}

arch_gnu_libdir() {
    case "$(normalize_tps_arch "$1")" in
        x86_64) echo /lib/x86_64-linux-gnu ;;
        aarch64) echo /lib/aarch64-linux-gnu ;;
    esac
}

arch_loader_name() {
    case "$(normalize_tps_arch "$1")" in
        x86_64) echo ld-linux-x86-64.so.2 ;;
        aarch64) echo ld-linux-aarch64.so.1 ;;
    esac
}

arch_loader_path() {
    local name gnu
    name="$(arch_loader_name "$1")"
    gnu="$(arch_gnu_libdir "$1")"
    if [ -f "/lib64/${name}" ]; then
        echo "/lib64/${name}"
    elif [ -f "${gnu}/${name}" ]; then
        echo "${gnu}/${name}"
    elif [ -f "/lib/${name}" ]; then
        echo "/lib/${name}"
    else
        echo "${gnu}/${name}"
    fi
}

arch_interp_on_nas() {
    echo "/var/packages/ThreatPrevention/target/lib/$(arch_loader_name "$1")"
}
