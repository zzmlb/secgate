#!/usr/bin/env bash
set -euo pipefail

# 构建 SecGate pip 包
# 用法: bash packaging/build-pip.sh [--upload]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_PROJECT_DIR="$PROJECT_DIR/src/secgate_pkg/project"
VERSION=$(cat "$PROJECT_DIR/VERSION")
UPLOAD=false

if [[ "${1:-}" == "--upload" ]]; then
    UPLOAD=true
fi

echo "=========================================="
echo "  构建 SecGate pip 包 v${VERSION}"
echo "=========================================="

# 清理旧文件
rm -rf "$PKG_PROJECT_DIR" "$PROJECT_DIR/dist" "$PROJECT_DIR/build" "$PROJECT_DIR"/*.egg-info "$PROJECT_DIR/src"/*.egg-info

# 创建目录
mkdir -p "$PKG_PROJECT_DIR"

# 复制项目文件到包内
rsync -a \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='.gitignore' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='*.egg-info' \
    --exclude='*-discussion' \
    --exclude='.pids.json' \
    --exclude='.credentials.json' \
    --exclude='dashboard/data' \
    --exclude='scanner/data' \
    --exclude='.files' \
    --exclude='src' \
    --exclude='secgate_pkg' \
    --exclude='secgate-*.tar.gz' \
    --exclude='pyproject.toml' \
    --exclude='MANIFEST.in' \
    --exclude='packaging' \
    --exclude='.chainlit' \
    --exclude='.claude' \
    "$PROJECT_DIR/" "$PKG_PROJECT_DIR/"

echo "项目文件已复制到 $PKG_PROJECT_DIR"

# 安装构建工具
pip3 install -q build 2>/dev/null || pip install -q build

# 构建
cd "$PROJECT_DIR"
python3 -m build

# 清理临时项目副本
rm -rf "$PKG_PROJECT_DIR"

echo ""
echo "构建完成:"
ls -lh "$PROJECT_DIR/dist/"
echo ""

if [[ "$UPLOAD" == "true" ]]; then
    pip3 install -q twine 2>/dev/null || pip install -q twine
    echo "上传到 PyPI..."
    twine upload "$PROJECT_DIR/dist/"*
    echo ""
    echo "发布成功! 用户可通过以下命令安装:"
    echo "  pip install secgate"
    echo "  sudo secgate setup"
else
    echo "本地测试: pip install dist/secgate-${VERSION}.tar.gz"
    echo "上传 PyPI: bash packaging/build-pip.sh --upload"
fi
