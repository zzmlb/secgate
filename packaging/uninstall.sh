#!/usr/bin/env bash
set -euo pipefail

# SecGate 卸载脚本

INSTALL_DIR="/opt/secgate"
SYMLINK="/usr/local/bin/secgate"
SERVICE_FILE="/etc/systemd/system/secgate.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} 请使用 root 权限运行"; exit 1; }

echo "=========================================="
echo "  SecGate 卸载程序"
echo "=========================================="

# 停止服务
if [[ -f "$INSTALL_DIR/secgate" ]]; then
    info "停止服务..."
    python3 "$INSTALL_DIR/secgate" stop 2>/dev/null || true
fi

# 停止 systemd 服务
if [[ -f "$SERVICE_FILE" ]]; then
    systemctl stop secgate 2>/dev/null || true
    systemctl disable secgate 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    info "已移除 systemd 服务"
fi

# 询问是否保留数据
KEEP_DATA=false
if [[ -t 0 ]]; then  # 如果是交互式终端
    read -p "是否保留配置和数据文件？[y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] && KEEP_DATA=true
fi

if $KEEP_DATA && [[ -d "$INSTALL_DIR" ]]; then
    BACKUP="/tmp/secgate-data-$(date +%s)"
    mkdir -p "$BACKUP"
    [[ -f "$INSTALL_DIR/.credentials.json" ]] && cp "$INSTALL_DIR/.credentials.json" "$BACKUP/"
    [[ -f "$INSTALL_DIR/gateway/config.json" ]] && cp "$INSTALL_DIR/gateway/config.json" "$BACKUP/"
    [[ -d "$INSTALL_DIR/dashboard/data" ]] && cp -r "$INSTALL_DIR/dashboard/data" "$BACKUP/dashboard-data"
    [[ -d "$INSTALL_DIR/scanner/data" ]] && cp -r "$INSTALL_DIR/scanner/data" "$BACKUP/scanner-data"
    info "数据已备份到: $BACKUP"
fi

# 删除安装目录
[[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR" && info "已删除 $INSTALL_DIR"

# 删除软链接
[[ -L "$SYMLINK" ]] && rm -f "$SYMLINK" && info "已删除 $SYMLINK"

info "卸载完成"
