#!/bin/bash
# 同步 config.json 白名单到 iptables 规则
# 当通过 API 修改白名单后调用此脚本
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/setup-iptables.sh"
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "iptables rules synced and saved"
