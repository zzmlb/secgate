#!/usr/bin/env python3
"""网关认证服务 - 供 Nginx auth_request 调用"""

import os
import sys
import json
import time
import random
import secrets
import hashlib
import subprocess
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

# 将项目根目录加入路径
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from shared import detect_public_ip, get_or_create_credential

from flask import Flask, request, render_template, make_response, redirect, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)

# 登录日志
_login_logger = logging.getLogger("gateway_login")
_login_logger.setLevel(logging.INFO)
try:
    _login_handler = logging.FileHandler("/var/log/gateway_login.log")
    _login_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _login_logger.addHandler(_login_handler)
except Exception:
    pass  # 日志文件无法写入时不影响核心功能


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ============ 配置 ============
SECRET_KEY = get_or_create_credential(
    "gateway_secret", lambda: secrets.token_hex(32), env_var="GATEWAY_SECRET"
)
SESSION_MAX_AGE = 86400 * 7  # 7天
COOKIE_NAME = "gw_session"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
GATEWAY_DIR = os.path.dirname(__file__)

# 不允许保护的系统端口
EXCLUDED_PORTS = {22, 53, 5002}

# Nginx 代理端口分配范围
_PROXY_PORT_MIN = 20000
_PROXY_PORT_MAX = 65535


def _allocate_nginx_port(port, cfg):
    """为业务端口分配 Nginx 代理端口，保证不超 65535 且不冲突"""
    existing_nginx = {
        info.get("nginx_port", int(p) + 20000)
        for p, info in cfg.get("protected_ports", {}).items()
    }
    all_used = existing_nginx | {int(p) for p in cfg.get("protected_ports", {}).keys()}

    # 优先 port + 20000
    candidate = port + 20000
    if candidate <= _PROXY_PORT_MAX and candidate not in all_used:
        return candidate

    # 超限或冲突：从 _PROXY_PORT_MIN 起找空闲端口
    candidate = max(_PROXY_PORT_MIN, min(candidate, _PROXY_PORT_MAX))
    while candidate <= _PROXY_PORT_MAX and candidate in all_used:
        candidate += 1
    if candidate <= _PROXY_PORT_MAX:
        return candidate

    # 极端情况：反向搜索
    for c in range(_PROXY_PORT_MAX, _PROXY_PORT_MIN - 1, -1):
        if c not in all_used:
            return c
    return None


# 默认受保护端口（Dashboard + AI 助手，其余由用户通过管理页面添加）
DEFAULT_PROTECTED_PORTS = {
    "5000": {"nginx_port": 25000, "type": "standard", "comment": "安全监控看板"},
    "8502": {"nginx_port": 28502, "type": "chainlit", "comment": "AI 安全助手"},
}

serializer = URLSafeTimedSerializer(SECRET_KEY)


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        # 自动迁移：若无 protected_ports 字段，从默认端口初始化
        if "protected_ports" not in cfg:
            cfg["protected_ports"] = DEFAULT_PROTECTED_PORTS.copy()
            save_config(cfg)
        return cfg
    # 默认配置：生成一个初始 Token
    default_token = secrets.token_hex(32)
    cfg = {
        "tokens": {
            default_token: {
                "name": "default",
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        },
        "ip_whitelist": [],
        "protected_ports": DEFAULT_PROTECTED_PORTS.copy(),
    }
    save_config(cfg)
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def sync_iptables():
    """白名单变更后同步 iptables 规则"""
    script = os.path.join(os.path.dirname(__file__), "sync-whitelist.sh")
    if os.path.exists(script):
        subprocess.Popen(["bash", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def apply_gateway_changes(changed_ports=None):
    """端口保护变更后重新生成 Nginx 配置并同步 iptables，返回 (ok, error_msg)

    changed_ports: [(port_str, nginx_port_str), ...] 仅同步指定端口的 UFW 规则，None 则全量
    """
    # 1. 生成 Nginx 配置
    gen_script = os.path.join(GATEWAY_DIR, "generate-nginx.py")
    try:
        r = subprocess.run(
            ["python3", gen_script],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return False, f"生成 Nginx 配置失败: {r.stderr.strip()}"
    except Exception as e:
        return False, f"生成 Nginx 配置异常: {e}"

    # 2. 验证 Nginx 配置
    try:
        r = subprocess.run(
            ["nginx", "-t"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return False, f"Nginx 配置验证失败: {r.stderr.strip()}"
    except Exception as e:
        return False, f"Nginx 验证异常: {e}"

    # 3. 重载 Nginx
    try:
        r = subprocess.run(
            ["nginx", "-s", "reload"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return False, f"Nginx 重载失败: {r.stderr.strip()}"
    except Exception as e:
        return False, f"Nginx 重载异常: {e}"

    # 4. 同步 iptables
    sync_iptables()

    # 5. 同步 UFW 规则（仅新增端口，避免全量刷导致超时）
    _sync_ufw_for_ports(changed_ports)

    return True, ""


def _sync_ufw_for_ports(ports=None):
    """同步 UFW 规则。ports 为 [(port_str, nginx_port_str), ...] 列表，为 None 时全量同步"""
    try:
        if ports is None:
            cfg = load_config()
            ports = [
                (p, str(info.get("nginx_port", int(p) + 20000)))
                for p, info in cfg.get("protected_ports", {}).items()
            ]
        for port_str, nginx_port in ports:
            subprocess.run(
                ["ufw", "allow", port_str + "/tcp"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["ufw", "allow", nginx_port + "/tcp"],
                capture_output=True, timeout=5,
            )
    except Exception:
        pass  # UFW 同步失败不影响核心功能


TRUSTED_LOCAL = {"127.0.0.1", "::1", detect_public_ip()}


def ip_in_whitelist(ip):
    """检查 IP 是否在白名单中（支持 CIDR），本机自动放行"""
    import ipaddress

    if ip in TRUSTED_LOCAL:
        return True
    cfg = load_config()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in cfg.get("ip_whitelist", []):
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if addr in network:
                return True
        except ValueError:
            if ip == entry:
                return True
    return False


def verify_token(token):
    """验证 Token 是否有效（含过期检查）"""
    cfg = load_config()
    token_info = cfg.get("tokens", {}).get(token)
    if not token_info:
        return False
    expires = token_info.get("expires")
    if expires:
        try:
            if datetime.strptime(expires, "%Y-%m-%d %H:%M:%S") < datetime.now():
                return False
        except ValueError:
            pass
    return True


def create_session_cookie():
    """创建签名的 session cookie 值"""
    return serializer.dumps({"auth": True, "ts": datetime.now().timestamp()})


def verify_session_cookie(cookie_val):
    """验证 session cookie"""
    try:
        data = serializer.loads(cookie_val, max_age=SESSION_MAX_AGE)
        return data.get("auth") is True
    except (BadSignature, SignatureExpired):
        return False


def sanitize_next_url(url):
    """验证重定向 URL，防止开放重定向"""
    if not url or not isinstance(url, str):
        return "/"
    url = url.strip()
    if not url.startswith("/") or url.startswith("//") or "://" in url:
        return "/"
    return url


def get_client_ip():
    """获取真实客户端 IP，仅信任来自本机 Nginx 的 X-Real-IP"""
    if request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Real-IP", request.remote_addr)
    return request.remote_addr


_login_attempts = {}

def _check_rate_limit(ip):
    """检查登录速率限制：5分钟内最多10次"""
    now = time.time()
    window = 300  # 5 分钟
    max_attempts = 10

    # 随机概率清理过期记录（约 5%）
    if random.random() < 0.05:
        expired = [k for k, v in _login_attempts.items() if not v or v[-1] < now - window]
        for k in expired:
            del _login_attempts[k]

    attempts = _login_attempts.get(ip, [])
    # 清除超过窗口的记录
    attempts = [t for t in attempts if t > now - window]
    _login_attempts[ip] = attempts

    return len(attempts) >= max_attempts


# ============ 路由 ============

@app.route("/auth/verify")
def verify():
    """Nginx auth_request 调用此端点检查认证状态"""
    # 获取真实客户端 IP
    client_ip = get_client_ip()

    # 第1层：IP 白名单检查
    if ip_in_whitelist(client_ip):
        return "", 200

    # 第2层：Cookie 检查
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie and verify_session_cookie(cookie):
        return "", 200

    # 第3层：URL 中的 Token 检查（通过 X-Original-URI）
    original_uri = request.headers.get("X-Original-URI", "")
    if original_uri:
        parsed = urlparse(original_uri)
        params = parse_qs(parsed.query)
        token_list = params.get("token", [])
        if token_list and verify_token(token_list[0]):
            # Token 有效，返回 200 并设置 Cookie
            resp = make_response("", 200)
            resp.set_cookie(
                COOKIE_NAME,
                create_session_cookie(),
                httponly=True,
                samesite="Lax",
                max_age=SESSION_MAX_AGE,
                path="/",
            )
            return resp

    return "", 401


@app.route("/auth/login")
def login_page():
    """登录页面"""
    next_url = sanitize_next_url(request.args.get("next", "/"))
    return render_template("login.html", next_url=next_url)


@app.route("/auth/do-login", methods=["POST"])
def do_login():
    """处理登录表单提交"""
    client_ip = get_client_ip()
    if _check_rate_limit(client_ip):
        return jsonify({"error": "请求过于频繁，请稍后再试"}), 429

    token = request.form.get("token", "").strip()
    next_url = sanitize_next_url(request.form.get("next", "/"))

    _login_attempts.setdefault(client_ip, []).append(time.time())

    if verify_token(token):
        _login_attempts.pop(client_ip, None)
        _login_logger.info("LOGIN_SUCCESS ip=%s next=%s", client_ip, next_url)
        resp = make_response(redirect(next_url))
        resp.set_cookie(
            COOKIE_NAME,
            create_session_cookie(),
            httponly=True,
            samesite="Lax",
            max_age=SESSION_MAX_AGE,
            path="/",
        )
        return resp

    _login_logger.info("LOGIN_FAILED ip=%s next=%s", client_ip, next_url)
    return render_template("login.html", next_url=next_url, error="Token 无效")


@app.route("/auth/logout")
def logout():
    """登出"""
    resp = make_response(redirect("/auth/login"))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# ============ Token 管理 API（仅白名单 IP 可访问） ============

@app.route("/auth/api/tokens", methods=["GET"])
def list_tokens():
    """列出所有 Token"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    cfg = load_config()
    tokens = []
    for t, info in cfg.get("tokens", {}).items():
        tokens.append({
            "token_mask": t[:8] + "..." + t[-4:],
            "token_id": hashlib.sha256(t.encode()).hexdigest()[:16],
            "name": info.get("name", ""),
            "created": info.get("created", ""),
            "expires": info.get("expires", ""),
        })
    return jsonify({"tokens": tokens, "ip_whitelist": cfg.get("ip_whitelist", [])})


@app.route("/auth/api/tokens", methods=["POST"])
def create_token():
    """创建新 Token"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    name = data.get("name", "unnamed")
    token = secrets.token_hex(32)
    expire_days = data.get("expire_days", 90)
    try:
        expire_days = int(expire_days)
    except (ValueError, TypeError):
        expire_days = 90
    expires = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S")
    cfg = load_config()
    cfg["tokens"][token] = {
        "name": name,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expires": expires,
    }
    save_config(cfg)
    return jsonify({"token": token, "name": name, "expires": expires})


@app.route("/auth/api/tokens/<token_id>", methods=["DELETE"])
def delete_token(token_id):
    """删除（吊销）Token - 通过 token_id 匹配"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    cfg = load_config()
    for t in list(cfg.get("tokens", {})):
        if hashlib.sha256(t.encode()).hexdigest()[:16] == token_id:
            del cfg["tokens"][t]
            save_config(cfg)
            return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


@app.route("/auth/api/whitelist", methods=["POST"])
def add_whitelist():
    """添加 IP 白名单"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if ip:
        cfg = load_config()
        if ip not in cfg["ip_whitelist"]:
            cfg["ip_whitelist"].append(ip)
            save_config(cfg)
            sync_iptables()
        return jsonify({"ok": True})
    return jsonify({"error": "invalid ip"}), 400


@app.route("/auth/api/whitelist/<path:ip>", methods=["DELETE"])
def remove_whitelist(ip):
    """移除 IP 白名单"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    cfg = load_config()
    if ip in cfg.get("ip_whitelist", []):
        cfg["ip_whitelist"].remove(ip)
        save_config(cfg)
        sync_iptables()
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


@app.route("/auth/api/status")
def gateway_status():
    """网关状态（看板调用）"""
    cfg = load_config()
    protected = cfg.get("protected_ports", {})
    return jsonify({
        "token_count": len(cfg.get("tokens", {})),
        "whitelist_count": len(cfg.get("ip_whitelist", [])),
        "ip_whitelist": cfg.get("ip_whitelist", []),
        "server_ip": detect_public_ip(),
        "session_max_age_hours": SESSION_MAX_AGE // 3600,
        "protected_port_count": len(protected),
        "protected_ports": [
            {"port": int(p), "comment": info.get("comment", "")}
            for p, info in sorted(protected.items(), key=lambda x: int(x[0]))
        ],
    })


# ============ 端口保护管理 API ============

@app.route("/auth/api/ports", methods=["GET"])
def list_ports():
    """列出所有受保护端口"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    cfg = load_config()
    protected = cfg.get("protected_ports", {})
    ports = [
        {
            "port": int(p),
            "nginx_port": info.get("nginx_port", int(p) + 20000),
            "type": info.get("type", "standard"),
            "comment": info.get("comment", ""),
        }
        for p, info in sorted(protected.items(), key=lambda x: int(x[0]))
    ]
    return jsonify({"ports": ports})


@app.route("/auth/api/ports", methods=["POST"])
def add_port():
    """添加单个端口保护"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    try:
        port = int(data.get("port", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "端口号无效"}), 400

    if port <= 0 or port > 65535:
        return jsonify({"error": "端口号无效"}), 400
    if port in EXCLUDED_PORTS:
        return jsonify({"error": f"端口 {port} 为系统保留端口，不可保护"}), 400
    cfg = load_config()
    # 检查该端口是否已被其他端口用作 Nginx 代理端口
    existing_nginx_ports = {
        info.get("nginx_port", int(p) + 20000)
        for p, info in cfg.get("protected_ports", {}).items()
    }
    if port in existing_nginx_ports:
        return jsonify({"error": f"端口 {port} 已被用作 Nginx 认证代理端口，不可保护"}), 400

    comment = data.get("comment", "")
    is_chainlit = data.get("is_chainlit", False)
    port_type = "chainlit" if is_chainlit else "standard"
    nginx_port = _allocate_nginx_port(port, cfg)
    if nginx_port is None:
        return jsonify({"error": "无法分配可用的代理端口"}), 400
    port_str = str(port)
    if port_str in cfg.get("protected_ports", {}):
        return jsonify({"error": f"端口 {port} 已在保护列表中"}), 409

    # 保存配置
    if "protected_ports" not in cfg:
        cfg["protected_ports"] = {}
    cfg["protected_ports"][port_str] = {
        "nginx_port": nginx_port,
        "type": port_type,
        "comment": comment,
    }
    save_config(cfg)

    # 应用变更（仅同步当前端口的 UFW 规则）
    ok, err = apply_gateway_changes([(port_str, str(nginx_port))])
    if not ok:
        # 回滚
        del cfg["protected_ports"][port_str]
        save_config(cfg)
        return jsonify({"error": f"应用配置失败: {err}"}), 500

    return jsonify({"ok": True, "port": port, "nginx_port": nginx_port})


@app.route("/auth/api/ports/batch", methods=["POST"])
def add_ports_batch():
    """批量添加端口保护（一键全部保护）"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    ports_list = data.get("ports", [])
    if not ports_list:
        return jsonify({"error": "端口列表为空"}), 400

    cfg = load_config()
    if "protected_ports" not in cfg:
        cfg["protected_ports"] = {}

    # 备份当前配置用于回滚
    backup = json.dumps(cfg["protected_ports"])
    added = []

    for item in ports_list:
        try:
            port = int(item.get("port", 0))
        except (ValueError, TypeError):
            continue
        if port <= 0 or port > 65535 or port in EXCLUDED_PORTS:
            continue
        # 检查是否被用作 Nginx 代理端口
        existing_nginx_ports = {
            info.get("nginx_port", int(p) + 20000)
            for p, info in cfg.get("protected_ports", {}).items()
        }
        if port in existing_nginx_ports:
            continue
        port_str = str(port)
        if port_str in cfg["protected_ports"]:
            continue

        is_chainlit = item.get("is_chainlit", False)
        port_type = "chainlit" if is_chainlit else "standard"
        nginx_port = _allocate_nginx_port(port, cfg)
        if nginx_port is None:
            continue
        comment = item.get("comment", "")

        cfg["protected_ports"][port_str] = {
            "nginx_port": nginx_port,
            "type": port_type,
            "comment": comment,
        }
        added.append((port, nginx_port))

    if not added:
        return jsonify({"error": "没有可添加的端口"}), 400

    save_config(cfg)

    # 应用变更（仅同步新增端口的 UFW 规则）
    ufw_ports = [(str(p), str(np)) for p, np in added]
    ok, err = apply_gateway_changes(ufw_ports)
    if not ok:
        # 回滚
        cfg["protected_ports"] = json.loads(backup)
        save_config(cfg)
        return jsonify({"error": f"应用配置失败: {err}"}), 500

    return jsonify({"ok": True, "added": [p for p, _ in added], "count": len(added)})


@app.route("/auth/api/ports/<int:port>", methods=["DELETE"])
def remove_port(port):
    """移除端口保护"""
    client_ip = get_client_ip()
    if not ip_in_whitelist(client_ip):
        return jsonify({"error": "forbidden"}), 403

    cfg = load_config()
    port_str = str(port)
    if port_str not in cfg.get("protected_ports", {}):
        return jsonify({"error": "端口不在保护列表中"}), 404

    # 备份并删除
    backup = cfg["protected_ports"].pop(port_str)
    save_config(cfg)

    # 应用变更（删除无需新增 UFW 规则）
    ok, err = apply_gateway_changes([])
    if not ok:
        # 回滚
        cfg["protected_ports"][port_str] = backup
        save_config(cfg)
        return jsonify({"error": f"应用配置失败: {err}"}), 500

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
