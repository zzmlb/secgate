#!/bin/bash
# 安全监控看板启动脚本

cd "$(dirname "$0")"

# 设置默认密码（可通过环境变量覆盖）
export DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-Sec@2026!}"

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
