"""pip install 后的 CLI 入口 - 自动部署到 /opt/secgate 并调用原始 secgate"""

import os
import sys
import shutil
import subprocess

INSTALL_DIR = os.environ.get("SECGATE_DIR", "/opt/secgate")


def ensure_deployed():
    """确保项目文件已部署到 INSTALL_DIR"""
    marker = os.path.join(INSTALL_DIR, "secgate")
    if os.path.exists(marker):
        return  # 已部署

    # 从包内复制文件到安装目录
    pkg_dir = os.path.join(os.path.dirname(__file__), "project")
    if not os.path.isdir(pkg_dir):
        print(f"[错误] 包内未找到项目文件: {pkg_dir}", file=sys.stderr)
        print("请尝试重新安装: pip install --force-reinstall secgate", file=sys.stderr)
        sys.exit(1)

    print(f"[SecGate] 首次运行，部署文件到 {INSTALL_DIR} ...")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    shutil.copytree(pkg_dir, INSTALL_DIR, dirs_exist_ok=True)
    os.chmod(os.path.join(INSTALL_DIR, "secgate"), 0o755)
    print(f"[SecGate] 部署完成")


def main():
    ensure_deployed()
    # 转发到实际的 secgate 脚本
    cmd = [sys.executable, os.path.join(INSTALL_DIR, "secgate")] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))
