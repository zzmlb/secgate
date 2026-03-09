#!/usr/bin/env bash
set -euo pipefail

# SecGate 构建脚本 - 生成 tar.gz 发布包
# 用法: bash packaging/build.sh [VERSION]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "0.0.0")}"
VERSION="${VERSION#v}"  # 去掉 v 前缀

BUILD_DIR="/tmp/secgate-build-$$"
DIST_DIR="$PROJECT_DIR/dist"
ARCHIVE_NAME="secgate-${VERSION}.tar.gz"

echo "=========================================="
echo "  构建 SecGate v${VERSION}"
echo "=========================================="

# 清理
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/secgate-${VERSION}" "$DIST_DIR"

# 复制文件
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
    --exclude='gateway/config.json' \
    --exclude='agent/.env' \
    --exclude='security-plan.md' \
    --exclude='dashboard/data' \
    --exclude='scanner/data' \
    --exclude='master/data' \
    --exclude='.claude' \
    --exclude='.chainlit' \
    --exclude='.files' \
    --exclude='src' \
    --exclude='secgate_pkg' \
    --exclude='secgate-*.tar.gz' \
    "$PROJECT_DIR/" "$BUILD_DIR/secgate-${VERSION}/"

# 写入版本
echo "$VERSION" > "$BUILD_DIR/secgate-${VERSION}/VERSION"

# 打包
tar czf "$DIST_DIR/$ARCHIVE_NAME" -C "$BUILD_DIR" "secgate-${VERSION}"

# 校验和
SHA256=$(sha256sum "$DIST_DIR/$ARCHIVE_NAME" | cut -d' ' -f1)

# 清理
rm -rf "$BUILD_DIR"

echo ""
echo "构建完成:"
echo "  文件: $DIST_DIR/$ARCHIVE_NAME"
echo "  大小: $(du -h "$DIST_DIR/$ARCHIVE_NAME" | cut -f1)"
echo "  SHA256: $SHA256"
