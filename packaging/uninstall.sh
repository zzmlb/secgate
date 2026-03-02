#!/usr/bin/env bash
set -euo pipefail

# SecGate 卸载脚本（向后兼容入口，实际逻辑已迁移到 secgate uninstall）

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} 请使用 root 权限运行"; exit 1; }

# 优先使用 secgate CLI 的 uninstall 命令
if command -v secgate &>/dev/null; then
    exec secgate uninstall
elif [[ -f /opt/secgate/secgate ]]; then
    exec python3 /opt/secgate/secgate uninstall
elif [[ -f "$(dirname "$0")/../secgate" ]]; then
    exec python3 "$(dirname "$0")/../secgate" uninstall
fi

echo -e "${RED}[ERROR]${NC} 找不到 secgate 命令。"
echo "请手动执行: sudo python3 /path/to/secgate uninstall"
exit 1
