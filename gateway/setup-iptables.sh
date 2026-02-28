#!/bin/bash
# ============================================================
# iptables REDIRECT 网关配置脚本
#
# 逻辑：
# 1. 白名单 IP + 本机 → RETURN (直接访问服务，无认证)
# 2. 其他 IP → REDIRECT 到 Nginx 认证端口 (25xxx)
#
# 端口映射从 config.json 的 protected_ports 动态读取
# 默认: 5000→25000, 5001→25001, 5711→25711, 8000→28000, 8501→28501
# ============================================================

set -e

# 读取 gateway config.json 中的白名单（相对于脚本目录）
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.json"

# 从 config.json 动态读取端口映射
declare -A PORT_MAP
if [ -f "$CONFIG_FILE" ]; then
    while IFS='=' read -r port nginx_port; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$nginx_port" =~ ^[0-9]+$ ]]; then
            PORT_MAP[$port]=$nginx_port
        fi
    done < <(python3 -c "
import json, sys
with open('$CONFIG_FILE') as f:
    cfg = json.load(f)
for port, info in cfg.get('protected_ports', {}).items():
    nginx_port = str(info.get('nginx_port', int(port)+20000))
    if port.isdigit() and nginx_port.isdigit():
        print(f'{port}={nginx_port}')
" 2>/dev/null)
fi

# 如果没读到端口映射（config.json 缺失或无 protected_ports），使用默认值
if [ ${#PORT_MAP[@]} -eq 0 ]; then
    echo "  ! 警告: 未从 config.json 读取到端口映射，使用默认值"
    PORT_MAP=([5000]=25000 [5001]=25001 [5711]=25711 [8000]=28000 [8501]=28501)
fi

# 自定义链名称
CHAIN="GATEWAY_AUTH"

echo "=== 配置 iptables 网关认证 ==="

# 1. 清理旧规则
echo "[1/4] 清理旧的 iptables 规则..."
# 删除 PREROUTING 中引用自定义链的规则
iptables -t nat -D PREROUTING -j $CHAIN 2>/dev/null || true
# 清空并删除自定义链
iptables -t nat -F $CHAIN 2>/dev/null || true
iptables -t nat -X $CHAIN 2>/dev/null || true

# 2. 创建自定义链
echo "[2/4] 创建自定义链 $CHAIN..."
iptables -t nat -N $CHAIN

# 3. 添加白名单规则（RETURN = 跳过重定向，直连服务）
echo "[3/4] 添加白名单规则..."

# 本机回环地址
iptables -t nat -A $CHAIN -s 127.0.0.0/8 -j RETURN
echo "  + 127.0.0.0/8 (本机回环)"

# 本机公网 IP（自动检测）
SERVER_IP=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
if [ -n "$SERVER_IP" ]; then
    iptables -t nat -A $CHAIN -s "$SERVER_IP"/32 -j RETURN
    echo "  + $SERVER_IP (本机)"
fi

# 从 config.json 读取白名单
if [ -f "$CONFIG_FILE" ]; then
    # 使用 python3 解析 JSON
    WHITELIST=$(python3 -c "
import json
with open('$CONFIG_FILE') as f:
    cfg = json.load(f)
for ip in cfg.get('ip_whitelist', []):
    print(ip)
")
    while IFS= read -r ip; do
        if [ -n "$ip" ]; then
            iptables -t nat -A $CHAIN -s "$ip" -j RETURN
            echo "  + $ip"
        fi
    done <<< "$WHITELIST"
else
    echo "  ! 警告: $CONFIG_FILE 不存在，仅添加本机白名单"
fi

# 4. 添加 REDIRECT 规则（非白名单流量 → Nginx 认证端口）
echo "[4/4] 添加端口重定向规则..."
for PORT in "${!PORT_MAP[@]}"; do
    NGINX_PORT=${PORT_MAP[$PORT]}
    iptables -t nat -A $CHAIN -p tcp --dport $PORT -j REDIRECT --to-port $NGINX_PORT
    echo "  $PORT → $NGINX_PORT"
done

# 5. 将自定义链挂载到 PREROUTING（插入到最前面，确保在 DOCKER 链之前执行）
iptables -t nat -I PREROUTING 1 -j $CHAIN

echo ""
echo "=== iptables 网关配置完成 ==="
echo ""
echo "验证规则："
iptables -t nat -L $CHAIN -n --line-numbers
