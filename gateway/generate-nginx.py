#!/usr/bin/env python3
"""从 config.json 的 protected_ports 生成 Nginx gateway.conf"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from shared import NGINX_CONF_PATH

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
NGINX_CONF = NGINX_CONF_PATH

HEADER = """\
# ============================================================
# Gateway Authentication Proxy (iptables REDIRECT 方案)
# 由 generate-nginx.py 自动生成，请勿手动编辑
#
# 流量路径:
# 外部非白名单IP → iptables REDIRECT 到 25xxx → Nginx 认证 → proxy 回 127.0.0.1:原端口
# 白名单IP/本机 → iptables RETURN → 直达服务(无认证)
# ============================================================

limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

upstream auth_backend {
    server 127.0.0.1:5002;
    keepalive 32;
}
"""

STANDARD_TEMPLATE = """\
# -- {comment} :{port} → Nginx {nginx_port} --
server {{
    listen {nginx_port};
    server_name _;

    # 认证子请求
    auth_request /auth/verify;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie always;

    # 认证失败 → 跳转登录页
    error_page 401 = @login_redirect;
    location @login_redirect {{
        return 302 http://$host:{port}/auth/login?next=$request_uri;
    }}

    # 认证端点（不需要认证）
    location /auth/ {{
        auth_request off;
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Port {port};
    }}

    # 业务代理（回到原始服务）
    location / {{
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }}
}}
"""

CHAINLIT_TEMPLATE = """\
# -- {comment} :{port} → Nginx {nginx_port} --
# Chainlit 自身使用 /auth/ 路径，网关认证改用 /gw-auth/
server {{
    listen {nginx_port};
    server_name _;

    # 内部认证子请求指向专用路径
    auth_request /gw-auth/verify;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie always;

    error_page 401 = @login_redirect;
    location @login_redirect {{
        return 302 http://$host:{port}/gw-auth/login?next=$request_uri;
    }}

    # 网关认证端点（/gw-auth/ → 映射到 auth_backend 的 /auth/）
    location /gw-auth/ {{
        auth_request off;
        rewrite ^/gw-auth/(.*)$ /auth/$1 break;
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Port {port};
    }}

    # 所有请求（含 Chainlit 的 /auth/）代理到后端
    location / {{
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }}
}}
"""


def main():
    if not os.path.exists(CONFIG_PATH):
        print(f"错误: {CONFIG_PATH} 不存在", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        cfg = json.load(f)

    protected = cfg.get("protected_ports", {})
    if not protected:
        print("警告: 没有受保护端口，生成空配置", file=sys.stderr)

    parts = [HEADER]

    for port_str in sorted(protected.keys(), key=int):
        info = protected[port_str]
        port = int(port_str)
        nginx_port = info.get("nginx_port", port + 20000)
        comment = info.get("comment", f"端口 {port}")
        port_type = info.get("type", "standard")

        template = CHAINLIT_TEMPLATE if port_type == "chainlit" else STANDARD_TEMPLATE
        parts.append(template.format(
            port=port,
            nginx_port=nginx_port,
            comment=comment,
        ))

    conf_content = "\n".join(parts)

    with open(NGINX_CONF, "w") as f:
        f.write(conf_content)

    print(f"已生成 {NGINX_CONF}，包含 {len(protected)} 个端口配置")


if __name__ == "__main__":
    main()
