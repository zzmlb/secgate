#!/usr/bin/env bash
set -euo pipefail

# SecGate 一键安装脚本
# 用法: curl -fsSL <url>/install.sh | sudo bash [-s VERSION]

INSTALL_DIR="/opt/secgate"
SYMLINK="/usr/local/bin/secgate"
REPO_URL="https://github.com/zzmlb/secgate"
VERSION="${1:-latest}"
BACKUP_DIR="/tmp/secgate-backup-$(date +%s)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# 检查 root
[[ $EUID -eq 0 ]] || error "请使用 root 权限运行: sudo bash install.sh"

# 检查 Python3
command -v python3 >/dev/null || error "未找到 python3，请先安装: apt-get install python3"

# 解析版本
if [[ "$VERSION" == "latest" ]]; then
    # 尝试从 GitHub API 获取最新版本
    DOWNLOAD_URL="${REPO_URL}/releases/latest/download/secgate.tar.gz"
    VERSION_DISPLAY="最新版"
else
    VERSION="${VERSION#v}"  # 去掉 v 前缀
    DOWNLOAD_URL="${REPO_URL}/releases/download/v${VERSION}/secgate-${VERSION}.tar.gz"
    VERSION_DISPLAY="v${VERSION}"
fi

info "安装 SecGate ${VERSION_DISPLAY}"

# 备份已有数据
if [[ -d "$INSTALL_DIR" ]]; then
    info "检测到已有安装，备份数据文件..."
    mkdir -p "$BACKUP_DIR"
    for f in .credentials.json gateway/config.json; do
        [[ -f "$INSTALL_DIR/$f" ]] && cp "$INSTALL_DIR/$f" "$BACKUP_DIR/" && info "  备份 $f"
    done
    [[ -d "$INSTALL_DIR/dashboard/data" ]] && cp -r "$INSTALL_DIR/dashboard/data" "$BACKUP_DIR/dashboard-data" && info "  备份 dashboard/data/"
    [[ -d "$INSTALL_DIR/scanner/data" ]] && cp -r "$INSTALL_DIR/scanner/data" "$BACKUP_DIR/scanner-data" && info "  备份 scanner/data/"
    # 停止服务
    [[ -f "$INSTALL_DIR/secgate" ]] && python3 "$INSTALL_DIR/secgate" stop 2>/dev/null || true
fi

# 下载并解压
info "下载安装包..."
TMP_TAR="/tmp/secgate-download.tar.gz"
if ! curl -fsSL -o "$TMP_TAR" "$DOWNLOAD_URL"; then
    # 如果下载失败，尝试本地安装（仅当直接执行脚本文件时有效）
    SCRIPT_PATH="${BASH_SOURCE[0]:-}"
    if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
        SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
        if [[ -f "$SCRIPT_DIR/secgate" ]]; then
            info "使用本地文件安装..."
            mkdir -p "$INSTALL_DIR"
            rsync -a --exclude='__pycache__' --exclude='.git' --exclude='dist' --exclude='build' \
                  --exclude='*.egg-info' --exclude='*-discussion' --exclude='.pids.json' \
                  --exclude='.credentials.json' --exclude='dashboard/data' --exclude='scanner/data' \
                  "$SCRIPT_DIR/" "$INSTALL_DIR/"
        else
            error "下载失败且无法使用本地文件"
        fi
    else
        error "下载失败: $DOWNLOAD_URL"
    fi
else
    info "解压到 ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    tar xzf "$TMP_TAR" -C "$INSTALL_DIR" --strip-components=1
    rm -f "$TMP_TAR"
fi

# 恢复备份
if [[ -d "$BACKUP_DIR" ]]; then
    info "恢复备份数据..."
    [[ -f "$BACKUP_DIR/.credentials.json" ]] && cp "$BACKUP_DIR/.credentials.json" "$INSTALL_DIR/"
    [[ -f "$BACKUP_DIR/config.json" ]] && mkdir -p "$INSTALL_DIR/gateway" && cp "$BACKUP_DIR/config.json" "$INSTALL_DIR/gateway/"
    [[ -d "$BACKUP_DIR/dashboard-data" ]] && mkdir -p "$INSTALL_DIR/dashboard" && cp -r "$BACKUP_DIR/dashboard-data" "$INSTALL_DIR/dashboard/data"
    [[ -d "$BACKUP_DIR/scanner-data" ]] && mkdir -p "$INSTALL_DIR/scanner" && cp -r "$BACKUP_DIR/scanner-data" "$INSTALL_DIR/scanner/data"
    rm -rf "$BACKUP_DIR"
fi

# 设置权限
chmod +x "$INSTALL_DIR/secgate"

# 创建软链接
ln -sf "$INSTALL_DIR/secgate" "$SYMLINK"
info "已创建命令: $SYMLINK"

# 运行 setup
info "运行初始配置..."
python3 "$INSTALL_DIR/secgate" setup

info "安装完成！运行 'secgate status' 查看状态"
