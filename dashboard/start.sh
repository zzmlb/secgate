#!/bin/bash
# 安全监控看板启动脚本

cd "$(dirname "$0")"

# 密码优先从环境变量读取，其次从凭证文件读取
if [ -z "$DASHBOARD_PASSWORD" ]; then
    CRED_FILE="$(dirname "$0")/../.credentials.json"
    if [ -f "$CRED_FILE" ]; then
        export DASHBOARD_PASSWORD=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['dashboard_password'])" 2>/dev/null)
    fi
fi
if [ -z "$DASHBOARD_PASSWORD" ]; then
    echo "[!] 未设置 DASHBOARD_PASSWORD，请通过环境变量或 .credentials.json 配置"
    exit 1
fi

# 检查依赖
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[*] 安装Python依赖..."
    pip install -r requirements.txt
fi

# 杀掉已有的看板进程
if [ -f .dashboard.pid ]; then
    old_pid=$(cat .dashboard.pid)
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "[*] 停止旧进程 (PID: $old_pid)..."
        kill "$old_pid" 2>/dev/null
        sleep 1
    fi
    rm -f .dashboard.pid
fi

echo "======================================"
echo "  安全监控看板"
echo "  地址: http://0.0.0.0:5000"
echo "  用户名: admin"
echo "  密码: $DASHBOARD_PASSWORD"
echo "======================================"

# 启动服务
python3 app.py &
echo $! > .dashboard.pid
echo "[+] 看板已启动 (PID: $!)"
