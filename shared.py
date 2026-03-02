"""项目共享工具 - 公网 IP 检测 & 凭证自动生成"""

import os
import json
import secrets
import subprocess
import socket

PROJECT_DIR = os.path.dirname(__file__)
CREDENTIALS_FILE = os.path.join(PROJECT_DIR, ".credentials.json")

# Nginx 配置路径（Ubuntu/Debian 标准路径）
NGINX_CONF_PATH = os.environ.get(
    "SECGATE_NGINX_CONF",
    "/etc/nginx/sites-available/gateway.conf"
)
NGINX_ENABLED_PATH = os.environ.get(
    "SECGATE_NGINX_ENABLED",
    "/etc/nginx/sites-enabled/gateway.conf"
)

# ============ 公网 IP 自动检测 ============

_cached_public_ip = None


def detect_public_ip():
    """自动检测本机公网 IP，结果缓存"""
    global _cached_public_ip
    if _cached_public_ip:
        return _cached_public_ip

    # 方法1: 通过外部服务查询
    for url in ["https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"]:
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "3", url],
                capture_output=True, text=True, timeout=5,
            )
            ip = r.stdout.strip()
            if ip and _is_valid_ip(ip):
                _cached_public_ip = ip
                return ip
        except Exception:
            continue

    # 方法2: 通过 hostname 获取
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        ips = r.stdout.strip().split()
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("172.") and not ip.startswith("10.") and ":" not in ip:
                _cached_public_ip = ip
                return ip
    except Exception:
        pass

    # 方法3: socket 连接外部地址获取本机出口 IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        _cached_public_ip = ip
        return ip
    except Exception:
        pass

    return "127.0.0.1"


def _is_valid_ip(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ============ 凭证自动生成 ============

def load_credentials():
    """加载或初始化凭证文件，返回凭证字典"""
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_credentials(creds):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    os.chmod(CREDENTIALS_FILE, 0o600)


def get_or_create_credential(key, generator, env_var=None):
    """获取凭证：优先环境变量 > 凭证文件 > 自动生成

    Args:
        key: 凭证在文件中的键名
        generator: 生成函数，无参数
        env_var: 对应的环境变量名
    Returns:
        凭证值
    """
    # 优先使用环境变量
    if env_var:
        val = os.environ.get(env_var)
        if val:
            return val

    # 从凭证文件读取
    creds = load_credentials()
    if key in creds:
        return creds[key]

    # 自动生成并保存
    val = generator()
    creds[key] = val
    save_credentials(creds)
    return val
