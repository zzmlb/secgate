#!/usr/bin/env python3
"""安全监控看板 - Flask后端"""

import os
import sys
import re
import json
import secrets
import subprocess
import ipaddress
import psutil
import time as _time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, jsonify, request, Response, redirect

# 将 pj226 目录加入路径，以便导入 scanner 模块
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from shared import detect_public_ip, get_or_create_credential

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# IP 地理位置缓存（持久化到文件）
_IP_GEO_CACHE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'ip_geo_cache.json')


def _load_geo_cache():
    try:
        if os.path.exists(_IP_GEO_CACHE_FILE):
            with open(_IP_GEO_CACHE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_geo_cache():
    try:
        os.makedirs(os.path.dirname(_IP_GEO_CACHE_FILE), exist_ok=True)
        with open(_IP_GEO_CACHE_FILE, 'w') as f:
            json.dump(_ip_geo_cache, f)
    except Exception:
        pass


_ip_geo_cache = _load_geo_cache()


def _lookup_ip_geo(ips):
    """批量查询 IP 地理位置，使用 ip-api.com 免费 API"""
    import requests as http_requests_geo
    # 找出未缓存的 IP
    uncached = [ip for ip in ips if ip not in _ip_geo_cache]

    if uncached:
        # ip-api.com 批量最多100，分批处理
        for i in range(0, min(len(uncached), 200), 100):
            batch = uncached[i:i+100]
            try:
                resp = http_requests_geo.post(
                    'http://ip-api.com/batch?fields=query,country,regionName,city,status&lang=zh-CN',
                    json=[{"query": ip} for ip in batch],
                    timeout=5
                )
                if resp.status_code == 200:
                    for item in resp.json():
                        ip = item.get('query', '')
                        if item.get('status') == 'success':
                            _ip_geo_cache[ip] = {
                                'country': item.get('country', '未知'),
                                'region': item.get('regionName', ''),
                                'city': item.get('city', ''),
                            }
                        else:
                            _ip_geo_cache[ip] = {'country': '未知', 'region': '', 'city': ''}
            except Exception:
                pass
        # 有新查询结果，保存缓存到文件
        _save_geo_cache()

    # 对未能查到的 IP 设默认值
    for ip in ips:
        if ip not in _ip_geo_cache:
            _ip_geo_cache[ip] = {'country': '未知', 'region': '', 'city': ''}

    return {ip: _ip_geo_cache[ip] for ip in ips}


# 基础HTTP认证
ADMIN_USER = "admin"
ADMIN_PASS = get_or_create_credential(
    "dashboard_password", lambda: secrets.token_urlsafe(12), env_var="DASHBOARD_PASSWORD"
)


def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS


def authenticate():
    # AJAX/fetch 请求不返回 WWW-Authenticate 头，避免浏览器弹出登录框
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"error": "认证失败"}), 401
    return Response(
        "认证失败，请提供正确的用户名和密码。",
        401,
        {"WWW-Authenticate": 'Basic realm="Security Dashboard"'},
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# ============ 缓存层 ============

_data_cache = {}
_data_cache_ts = {}


def _cached_call(key, func, args=(), ttl=30):
    now = _time.time()
    if key in _data_cache and now - _data_cache_ts.get(key, 0) < ttl:
        return _data_cache[key]
    result = func(*args)
    _data_cache[key] = result
    _data_cache_ts[key] = now
    return result


# ============ 预编译正则 ============

_RE_FAILED = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[.*Failed password for (?:invalid user )?(\S+) from (\S+)"
)
_RE_ACCEPTED = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[.*Accepted (\S+) for (\S+) from (\S+)"
)


# ============ 数据采集函数 ============

def parse_auth_log():
    """解析 /var/log/auth.log，提取SSH攻击数据"""
    failed_attempts = []
    successful_logins = []
    log_files = []

    # 检查可用的日志文件
    for f in ["/var/log/auth.log", "/var/log/auth.log.1"]:
        if os.path.exists(f):
            log_files.append(f)

    current_year = datetime.now().year

    for log_file in log_files:
        try:
            with open(log_file, "r", errors="ignore") as fh:
                for line in fh:
                    # Failed password
                    m = _RE_FAILED.search(line)
                    if m:
                        try:
                            ts = datetime.strptime(f"{current_year} {m.group(1)}", "%Y %b %d %H:%M:%S")
                            failed_attempts.append({
                                "time": ts,
                                "user": m.group(2),
                                "ip": m.group(3),
                            })
                        except ValueError:
                            pass
                        continue

                    # Accepted password / publickey
                    m = _RE_ACCEPTED.search(line)
                    if m:
                        try:
                            ts = datetime.strptime(f"{current_year} {m.group(1)}", "%Y %b %d %H:%M:%S")
                            successful_logins.append({
                                "time": ts,
                                "method": m.group(2),
                                "user": m.group(3),
                                "ip": m.group(4),
                            })
                        except ValueError:
                            pass
        except PermissionError:
            pass

    return failed_attempts, successful_logins


def get_attack_stats(days=None, _auth_log_result=None):
    """获取攻击统计数据"""
    if _auth_log_result is not None:
        failed, success = _auth_log_result
    else:
        failed, success = _cached_call('parse_auth_log', parse_auth_log, ttl=60)

    # 按时间范围过滤
    if days is not None:
        cutoff = datetime.now() - timedelta(days=days)
        failed = [a for a in failed if a["time"] >= cutoff]
        success = [s for s in success if s["time"] >= cutoff]

    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = now - timedelta(days=7)
    two_days_ago = now - timedelta(hours=48)
    six_hours_ago = now - timedelta(hours=6)

    # 单次遍历统计所有维度
    daily_counts = defaultdict(int)
    hourly_counts = defaultdict(int)
    hourly_trend = defaultdict(int)
    minute_trend = defaultdict(int)
    ip_counter = Counter()
    user_counter = Counter()
    today_attacks = 0

    for a in failed:
        t = a["time"]
        daily_counts[t.strftime("%m-%d")] += 1
        ip_counter[a["ip"]] += 1
        user_counter[a["user"]] += 1
        if t >= today_start:
            today_attacks += 1
        if t >= seven_days_ago:
            hourly_counts[t.hour] += 1
        if t >= two_days_ago:
            hourly_trend[t.strftime("%m-%d %H:00")] += 1
        if t >= six_hours_ago:
            minute_trend[t.strftime("%H:%M")] += 1

    top_ips = ip_counter.most_common(10)
    top_users = user_counter.most_common(10)
    sorted_hours = sorted(hourly_trend.items())
    sorted_minutes = sorted(minute_trend.items())
    sorted_days = sorted(daily_counts.items())

    # 合并所有 IP 一次查询地理位置（top_ips 是 all_ips 的子集）
    all_attack_ips = list(ip_counter.keys())
    all_geo = _lookup_ip_geo(all_attack_ips)

    country_counter = Counter()
    for ip, cnt in ip_counter.items():
        geo = all_geo.get(ip, {})
        c = geo.get('country', '未知')
        country_counter[c] += cnt
    top_countries = country_counter.most_common(15)

    return {
        "total_attacks": len(failed),
        "unique_ips": len(ip_counter),
        "today_attacks": today_attacks,
        "successful_logins": len(success),
        "daily_trend": {
            "dates": [d[0] for d in sorted_days],
            "counts": [d[1] for d in sorted_days],
        },
        "hourly_trend": {
            "dates": [d[0] for d in sorted_hours],
            "counts": [d[1] for d in sorted_hours],
        },
        "minute_trend": {
            "dates": [d[0] for d in sorted_minutes],
            "counts": [d[1] for d in sorted_minutes],
        },
        "hourly_distribution": {
            "hours": list(range(24)),
            "counts": [hourly_counts.get(h, 0) for h in range(24)],
        },
        "top_ips": [
            {
                "ip": ip, "count": cnt,
                "country": all_geo.get(ip, {}).get('country', '未知'),
                "region": all_geo.get(ip, {}).get('region', ''),
                "city": all_geo.get(ip, {}).get('city', ''),
            }
            for ip, cnt in top_ips
        ],
        "top_countries": [{"country": c, "count": cnt} for c, cnt in top_countries],
        "top_users": [{"user": u, "count": cnt} for u, cnt in top_users],
        "recent_success": [
            {
                "time": s["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "user": s["user"],
                "ip": s["ip"],
                "method": s["method"],
            }
            for s in sorted(success, key=lambda x: x["time"], reverse=True)[:10]
        ],
    }


def get_ssh_config():
    """获取SSH配置状态"""
    config = {
        "password_auth": "unknown",
        "pubkey_auth": "unknown",
        "root_login": "unknown",
        "port": "22",
        "max_auth_tries": "unknown",
    }
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                key, val = parts[0].lower(), parts[1].strip()
                if key == "passwordauthentication":
                    config["password_auth"] = val.lower()
                elif key == "pubkeyauthentication":
                    config["pubkey_auth"] = val.lower()
                elif key == "permitrootlogin":
                    config["root_login"] = val.lower()
                elif key == "port":
                    config["port"] = val
                elif key == "maxauthtries":
                    config["max_auth_tries"] = val
    except Exception:
        pass
    return config


def get_firewall_status():
    """获取防火墙状态"""
    result = {"active": False, "rules": [], "type": "unknown"}

    # 尝试UFW
    try:
        out = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            result["type"] = "ufw"
            lines = out.stdout.strip().split("\n")
            for line in lines:
                if "Status:" in line:
                    result["active"] = "active" in line.lower()
                elif line.strip() and not line.startswith("--") and "To" not in line.split()[:1]:
                    result["rules"].append(line.strip())
            return result
    except FileNotFoundError:
        pass

    # 尝试iptables
    try:
        out = subprocess.run(["iptables", "-L", "-n", "--line-numbers"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            result["type"] = "iptables"
            result["active"] = True
            lines = out.stdout.strip().split("\n")
            for line in lines:
                if line.strip():
                    result["rules"].append(line.strip())
            return result
    except FileNotFoundError:
        pass

    return result


def get_fail2ban_status():
    """获取fail2ban状态"""
    status = {"running": False, "jails": [], "banned_ips": 0, "banned_list": [], "jail_details": []}
    try:
        out = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            status["running"] = True
            m = re.search(r"Jail list:\s+(.*)", out.stdout)
            if m:
                jails = [j.strip() for j in m.group(1).split(",") if j.strip()]
                status["jails"] = jails
                for jail in jails:
                    jout = subprocess.run(
                        ["fail2ban-client", "status", jail],
                        capture_output=True, text=True, timeout=5,
                    )
                    jail_info = {"name": jail, "banned_count": 0, "banned_ips": []}
                    if jout.returncode == 0:
                        bm = re.search(r"Currently banned:\s+(\d+)", jout.stdout)
                        if bm:
                            cnt = int(bm.group(1))
                            status["banned_ips"] += cnt
                            jail_info["banned_count"] = cnt
                        ipm = re.search(r"Banned IP list:\s+(.*)", jout.stdout)
                        if ipm:
                            ips = [ip.strip() for ip in ipm.group(1).split() if ip.strip()]
                            jail_info["banned_ips"] = ips
                            status["banned_list"].extend(ips)
                    status["jail_details"].append(jail_info)
    except FileNotFoundError:
        status["running"] = False
    return status


def get_listening_ports():
    """获取所有监听端口"""
    ports = []
    try:
        out = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            for line in out.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    local_addr = parts[3]
                    # 解析地址和端口
                    if "]:" in local_addr:
                        addr, port = local_addr.rsplit(":", 1)
                    elif local_addr.startswith("["):
                        addr, port = local_addr.rsplit(":", 1)
                    else:
                        addr, port = local_addr.rsplit(":", 1)

                    # 提取进程信息
                    proc_info = parts[-1] if "users:" in parts[-1] else ""
                    proc_name = ""
                    pid = ""
                    pm = re.search(r'"([^"]+)",pid=(\d+)', proc_info)
                    if pm:
                        proc_name = pm.group(1)
                        pid = pm.group(2)

                    exposed = addr in ("0.0.0.0", "*", "[::]", "")
                    ports.append({
                        "port": port,
                        "address": addr,
                        "process": proc_name,
                        "pid": pid,
                        "exposed": exposed,
                        "state": "LISTEN",
                    })
    except Exception:
        pass
    return ports


def parse_ufw_log():
    """解析 UFW 防火墙拦截日志（syslog/kern.log）"""
    blocked = []
    current_year = datetime.now().year
    log_files = ["/var/log/syslog", "/var/log/syslog.1", "/var/log/kern.log"]

    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
        try:
            with open(log_file, "r", errors="ignore") as fh:
                for line in fh:
                    if "[UFW BLOCK]" not in line:
                        continue
                    # 提取时间
                    tm = re.match(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
                    # 提取源IP和目标端口
                    src_m = re.search(r"SRC=(\S+)", line)
                    dpt_m = re.search(r"DPT=(\d+)", line)
                    proto_m = re.search(r"PROTO=(\S+)", line)
                    if tm and src_m and dpt_m:
                        try:
                            ts = datetime.strptime(f"{current_year} {tm.group(1)}", "%Y %b %d %H:%M:%S")
                        except ValueError:
                            ts = datetime.now()
                        blocked.append({
                            "time": ts,
                            "src_ip": src_m.group(1),
                            "dst_port": int(dpt_m.group(1)),
                            "proto": proto_m.group(1) if proto_m else "TCP",
                        })
        except PermissionError:
            pass
    return blocked


def get_firewall_block_stats(days=None):
    """获取防火墙拦截统计"""
    blocked = parse_ufw_log()

    # 按时间范围过滤
    if days is not None:
        cutoff = datetime.now() - timedelta(days=days)
        blocked = [b for b in blocked if b["time"] >= cutoff]

    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # 按日期统计
    daily_counts = defaultdict(int)
    for b in blocked:
        daily_counts[b["time"].strftime("%m-%d")] += 1

    # 按小时统计
    hourly_counts = defaultdict(int)
    for b in blocked:
        if b["time"] >= today_start:
            hourly_counts[b["time"].hour] += 1

    # 按小时趋势（最近48小时）
    hourly_trend_fw = defaultdict(int)
    two_days_ago = now - timedelta(hours=48)
    for b in blocked:
        if b["time"] >= two_days_ago:
            hourly_trend_fw[b["time"].strftime("%m-%d %H:00")] += 1
    sorted_hours_fw = sorted(hourly_trend_fw.items())

    # 按分钟趋势（最近6小时）
    minute_trend_fw = defaultdict(int)
    six_hours_ago = now - timedelta(hours=6)
    for b in blocked:
        if b["time"] >= six_hours_ago:
            minute_trend_fw[b["time"].strftime("%H:%M")] += 1
    sorted_minutes_fw = sorted(minute_trend_fw.items())

    # 按目标端口统计
    port_counter = Counter(b["dst_port"] for b in blocked)
    top_ports = port_counter.most_common(15)

    # 按源IP统计
    ip_counter = Counter(b["src_ip"] for b in blocked)
    top_ips = ip_counter.most_common(10)

    # 按协议统计
    proto_counter = Counter(b["proto"] for b in blocked)

    # 常见端口标记攻击类型
    port_labels = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB", 25: "SMTP", 53: "DNS",
        445: "SMB", 3389: "RDP", 1433: "MSSQL", 23: "Telnet",
        21: "FTP", 8888: "Web-Alt", 9090: "Web-Alt", 4899: "Radmin",
        5900: "VNC", 2222: "SSH-Alt", 1025: "RPC",
    }

    today_blocks = sum(1 for b in blocked if b["time"] >= today_start)

    sorted_days = sorted(daily_counts.items())

    # IP地理位置查询
    fw_top_ip_list = [ip for ip, cnt in top_ips]
    fw_geo_info = _lookup_ip_geo(fw_top_ip_list)

    # 所有拦截IP的国家统计
    all_fw_ips = list(ip_counter.keys())
    all_fw_geo = _lookup_ip_geo(all_fw_ips)
    fw_country_counter = Counter()
    for ip, cnt in ip_counter.items():
        geo = all_fw_geo.get(ip, {})
        c = geo.get('country', '未知')
        fw_country_counter[c] += cnt
    fw_top_countries = fw_country_counter.most_common(15)

    return {
        "total_blocked": len(blocked),
        "today_blocked": today_blocks,
        "unique_ips": len(ip_counter),
        "top_ports": [
            {"port": p, "count": c, "label": port_labels.get(p, "Unknown")}
            for p, c in top_ports
        ],
        "top_ips": [
            {
                "ip": ip, "count": cnt,
                "country": fw_geo_info.get(ip, {}).get('country', '未知'),
                "region": fw_geo_info.get(ip, {}).get('region', ''),
                "city": fw_geo_info.get(ip, {}).get('city', ''),
            }
            for ip, cnt in top_ips
        ],
        "top_countries": [{"country": c, "count": cnt} for c, cnt in fw_top_countries],
        "proto_stats": dict(proto_counter),
        "daily_trend": {
            "dates": [d[0] for d in sorted_days],
            "counts": [d[1] for d in sorted_days],
        },
        "hourly_trend": {
            "dates": [d[0] for d in sorted_hours_fw],
            "counts": [d[1] for d in sorted_hours_fw],
        },
        "minute_trend": {
            "dates": [d[0] for d in sorted_minutes_fw],
            "counts": [d[1] for d in sorted_minutes_fw],
        },
        "hourly_distribution": {
            "hours": list(range(24)),
            "counts": [hourly_counts.get(h, 0) for h in range(24)],
        },
    }


def get_ssh_sessions():
    """获取当前活跃的 SSH 连接"""
    sessions = []
    try:
        # 方法1：使用 who 命令
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            for line in out.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    user = parts[0]
                    terminal = parts[1]
                    # 日期时间
                    date_str = ' '.join(parts[2:4])
                    # IP 地址（在括号里）
                    ip = ''
                    m = re.search(r'\((.+)\)', line)
                    if m:
                        ip = m.group(1)
                    sessions.append({
                        'user': user,
                        'terminal': terminal,
                        'login_time': date_str,
                        'ip': ip,
                    })
    except Exception:
        pass

    # 方法2：也用 ss 获取 SSH 连接数
    ssh_connections = 0
    try:
        out = subprocess.run(["ss", "-tn", "state", "established", "sport", "=", ":22"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            lines = out.stdout.strip().split('\n')
            ssh_connections = max(0, len(lines) - 1)  # 减去表头
    except Exception:
        pass

    return {
        'active_count': len(sessions),
        'tcp_connections': ssh_connections,
        'sessions': sessions,
    }


def get_system_resources():
    """获取系统资源使用情况"""
    cpu_percent = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime_seconds = int(datetime.now().timestamp() - psutil.boot_time())
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600

    return {
        "cpu_percent": cpu_percent,
        "memory": {
            "total": round(mem.total / (1024**3), 1),
            "used": round(mem.used / (1024**3), 1),
            "percent": mem.percent,
        },
        "disk": {
            "total": round(disk.total / (1024**3), 1),
            "used": round(disk.used / (1024**3), 1),
            "percent": round(disk.percent, 1),
        },
        "uptime": f"{days}天 {hours}小时",
        "hostname": os.uname().nodename,
    }


def _parse_range(range_str):
    """解析时间范围参数：7d/30d/90d/all → 天数(int)或 None"""
    if not range_str or range_str == 'all':
        return None
    m = re.match(r'^(\d+)d$', str(range_str))
    if m:
        return int(m.group(1))
    return 30  # 默认30天


def _describe_cron(expr):
    """将 cron 时间表达式转换为中文描述"""
    parts = expr.strip().split()
    if len(parts) < 5:
        return expr
    minute, hour, dom, month, dow = parts[:5]

    # 常见模式匹配
    if minute == '*' and hour == '*' and dom == '*' and month == '*' and dow == '*':
        return '每分钟'
    if hour == '*' and dom == '*' and month == '*' and dow == '*':
        if minute.startswith('*/'):
            return f'每 {minute[2:]} 分钟'
        return f'每小时第 {minute} 分'
    if dom == '*' and month == '*' and dow == '*':
        if hour.startswith('*/'):
            return f'每 {hour[2:]} 小时'
        return f'每天 {hour.zfill(2)}:{minute.zfill(2)}'
    if month == '*' and dow == '*' and dom != '*':
        return f'每月 {dom} 日 {hour.zfill(2)}:{minute.zfill(2)}'
    if dom == '*' and month == '*' and dow != '*':
        dow_names = {'0': '日', '1': '一', '2': '二', '3': '三', '4': '四', '5': '五', '6': '六', '7': '日'}
        dow_str = dow_names.get(dow, f'周{dow}')
        return f'每周{dow_str} {hour.zfill(2)}:{minute.zfill(2)}'
    return expr


def get_cron_jobs():
    """采集系统所有定时任务"""
    cron_jobs = []

    # 1. /etc/crontab（六段式，含 user 字段）
    try:
        with open('/etc/crontab', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 6)
                if len(parts) >= 7 and re.match(r'^[\d\*\/\,\-]', parts[0]):
                    schedule = ' '.join(parts[:5])
                    user = parts[5]
                    command = parts[6]
                    cron_jobs.append({
                        'user': user,
                        'schedule': schedule,
                        'schedule_desc': _describe_cron(schedule),
                        'command': command,
                        'source': '/etc/crontab',
                        'source_type': 'system',
                    })
    except Exception:
        pass

    # 2. /etc/cron.d/*（六段式）
    cron_d = '/etc/cron.d'
    if os.path.isdir(cron_d):
        for fname in os.listdir(cron_d):
            fpath = os.path.join(cron_d, fname)
            if not os.path.isfile(fpath) or fname.startswith('.'):
                continue
            try:
                with open(fpath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split(None, 6)
                        if len(parts) >= 7 and re.match(r'^[\d\*\/\,\-]', parts[0]):
                            schedule = ' '.join(parts[:5])
                            user = parts[5]
                            command = parts[6]
                            cron_jobs.append({
                                'user': user,
                                'schedule': schedule,
                                'schedule_desc': _describe_cron(schedule),
                                'command': command,
                                'source': f'/etc/cron.d/{fname}',
                                'source_type': 'system',
                            })
            except Exception:
                pass

    # 3. 用户 crontab（五段式，遍历有 shell 的用户）
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                shell = parts[6]
                if shell in ('/usr/sbin/nologin', '/bin/false', '/sbin/nologin'):
                    continue
                username = parts[0]
                try:
                    out = subprocess.run(
                        ['crontab', '-u', username, '-l'],
                        capture_output=True, text=True, timeout=5
                    )
                    if out.returncode == 0:
                        for cline in out.stdout.strip().split('\n'):
                            cline = cline.strip()
                            if not cline or cline.startswith('#'):
                                continue
                            cparts = cline.split(None, 5)
                            if len(cparts) >= 6 and re.match(r'^[\d\*\/\,\-]', cparts[0]):
                                schedule = ' '.join(cparts[:5])
                                command = cparts[5]
                                cron_jobs.append({
                                    'user': username,
                                    'schedule': schedule,
                                    'schedule_desc': _describe_cron(schedule),
                                    'command': command,
                                    'source': f'crontab -u {username}',
                                    'source_type': 'user',
                                })
                except Exception:
                    pass
    except Exception:
        pass

    # 4. /etc/cron.{hourly,daily,weekly,monthly}/
    for period in ['hourly', 'daily', 'weekly', 'monthly']:
        period_dir = f'/etc/cron.{period}'
        if not os.path.isdir(period_dir):
            continue
        period_desc = {'hourly': '每小时', 'daily': '每天', 'weekly': '每周', 'monthly': '每月'}.get(period, period)
        try:
            for fname in os.listdir(period_dir):
                fpath = os.path.join(period_dir, fname)
                if os.path.isfile(fpath) and not fname.startswith('.'):
                    cron_jobs.append({
                        'user': 'root',
                        'schedule': period,
                        'schedule_desc': period_desc,
                        'command': fname,
                        'source': period_dir,
                        'source_type': 'system',
                    })
        except Exception:
            pass

    # 统计
    by_source = {}
    for job in cron_jobs:
        st = job['source_type']
        by_source[st] = by_source.get(st, 0) + 1

    return {
        'cron_jobs': cron_jobs,
        'total': len(cron_jobs),
        'by_source': by_source,
    }


def get_gateway_mappings():
    """解析 Nginx 网关配置，返回 {网关端口: 业务端口} 映射"""
    mappings = {}
    try:
        with open("/etc/nginx/sites-available/gateway.conf") as f:
            content = f.read()
        for m in re.finditer(
            r"listen\s+(\d+);.*?proxy_pass\s+http://127\.0\.0\.1:(\d+)",
            content, re.DOTALL,
        ):
            gw_port, backend_port = int(m.group(1)), int(m.group(2))
            if gw_port != backend_port:
                mappings[gw_port] = backend_port
    except Exception:
        pass
    return mappings


def get_services_detail():
    """获取所有运行中服务的详细信息"""
    services = []
    try:
        out = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return services
    except Exception:
        return services

    # 获取公网IP
    public_ip = detect_public_ip()

    # 预先获取网关映射和 docker ps 结果（避免循环内重复调用）
    gw_map = get_gateway_mappings()
    reverse_gw = {v: k for k, v in gw_map.items()}
    _docker_ps_cache = None

    seen_ports = set()  # 用于 IPv4/IPv6 去重

    for line in out.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        local_addr = parts[3]
        if "]:" in local_addr:
            addr, port = local_addr.rsplit(":", 1)
        else:
            addr, port = local_addr.rsplit(":", 1)

        port = int(port)

        # IPv4/IPv6 去重：同一端口只保留第一条
        if port in seen_ports:
            continue
        seen_ports.add(port)

        # 提取进程信息
        proc_info = parts[-1] if "users:" in parts[-1] else ""
        proc_name = ""
        pid = ""
        pm = re.search(r'"([^"]+)",pid=(\d+)', proc_info)
        if pm:
            proc_name = pm.group(1)
            pid = pm.group(2)

        exposed = addr in ("0.0.0.0", "*", "[::]", "")

        # 获取进程详细信息
        cwd = ""
        cmdline = ""
        cpu_pct = 0.0
        mem_mb = 0.0
        create_time = ""
        if pid:
            try:
                p = psutil.Process(int(pid))
                cwd = p.cwd()
                cmdline = " ".join(p.cmdline())
                cpu_pct = p.cpu_percent(interval=0)
                mem_mb = round(p.memory_info().rss / (1024 * 1024), 1)
                create_time = datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # 判断服务类型和名称
        svc_type = "system"
        svc_name = proc_name
        svc_desc = ""
        is_web = False
        url = ""
        port_role = "primary"
        proxy_target = None
        gateway_port = None

        if port in gw_map:
            # 这是网关代理端口
            backend = gw_map[port]
            svc_type = "gateway"
            svc_name = f"认证代理 :{backend}"
            svc_desc = f"Nginx 认证网关，外部访问 :{backend} 时经 iptables 重定向至此端口进行 Token/Cookie 认证，通过后代理回 127.0.0.1:{backend}"
            is_web = True
            port_role = "gateway"
            proxy_target = backend
        elif "sshd" in proc_name:
            svc_name = "SSH Server"
            svc_desc = "OpenSSH 远程登录服务"
            svc_type = "infra"
        elif "mongod" in proc_name:
            svc_name = "MongoDB"
            svc_desc = "NoSQL 数据库"
            svc_type = "database"
        elif "systemd-resolve" in proc_name:
            svc_name = "DNS Resolver"
            svc_desc = "系统DNS解析服务"
            svc_type = "system"
        elif "chainlit" in proc_name or "chainlit" in cmdline:
            svc_name = "Chainlit App"
            svc_desc = f"AI对话应用 ({cwd})"
            svc_type = "web"
            is_web = True
        elif "flask" in cmdline.lower() or "app.py" in cmdline:
            if "gateway" in cwd:
                svc_name = "网关认证服务"
                svc_desc = "Gateway Auth 服务，处理 Nginx auth_request 的 Token/Cookie/IP白名单 认证验证"
                svc_type = "gateway"
                port_role = "auth_service"
            elif "dashboard" in cwd:
                svc_name = "Security Dashboard"
                svc_desc = "安全监控看板"
            elif "web/" in cmdline:
                svc_name = "Web Application"
                svc_desc = f"Flask Web应用 ({cwd})"
            else:
                svc_name = "Flask App"
                svc_desc = f"Python Web服务 ({cwd})"
            svc_type = svc_type if svc_type == "gateway" else "web"
            is_web = True
        elif "python" in proc_name:
            svc_name = "Python Service"
            svc_desc = f"Python 服务 ({cwd})"
            svc_type = "web"
            is_web = True
        elif "node" in proc_name:
            svc_name = "Node.js App"
            svc_desc = f"Node.js 服务 ({cwd})"
            svc_type = "web"
            is_web = True
        elif "docker-proxy" in proc_name:
            # Docker 端口映射——尝试识别容器内的真实服务
            svc_type = "web"
            is_web = True
            try:
                if _docker_ps_cache is None:
                    dk_out = subprocess.run(
                        ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"],
                        capture_output=True, text=True, timeout=5,
                    )
                    _docker_ps_cache = dk_out.stdout.strip() if dk_out.returncode == 0 else ""
                for dk_line in _docker_ps_cache.split("\n"):
                    if dk_line and f":{port}->" in dk_line:
                        dk_parts = dk_line.split("\t")
                        svc_name = dk_parts[0] if dk_parts else f"Docker ({port})"
                        dk_image = dk_parts[1] if len(dk_parts) > 1 else ""
                        svc_desc = f"Docker 容器 (镜像: {dk_image})"
                        break
                else:
                    svc_name = f"Docker ({port})"
                    svc_desc = "Docker 容器服务"
            except Exception:
                svc_name = f"Docker ({port})"
                svc_desc = "Docker 容器服务"
        elif "nginx" in proc_name:
            svc_name = "Nginx"
            svc_desc = "Web服务器/反向代理"
            svc_type = "web"
            is_web = True
        elif "java" in proc_name:
            svc_name = "Java Service"
            svc_desc = f"Java 应用 ({cwd})"
            svc_type = "web"
            is_web = True

        if is_web and exposed and port_role != "gateway":
            url = f"http://{public_ip}:{port}"

        # 业务端口标注其对应的网关端口
        if port_role == "primary" and port in reverse_gw:
            gateway_port = reverse_gw[port]

        services.append({
            "port": port,
            "address": addr,
            "exposed": exposed,
            "process": proc_name,
            "pid": pid,
            "svc_name": svc_name,
            "svc_desc": svc_desc,
            "svc_type": svc_type,
            "is_web": is_web,
            "url": url,
            "cwd": cwd,
            "cmdline": cmdline,
            "cpu_pct": cpu_pct,
            "mem_mb": mem_mb,
            "start_time": create_time,
            "port_role": port_role,
            "proxy_target": proxy_target,
            "gateway_port": gateway_port,
        })

    # 按端口排序
    services.sort(key=lambda s: s["port"])
    return services


# ============ AI 安全模块 ============

# AI API Key 正则规则库
AI_KEY_PATTERNS = [
    # 国际厂商 - 有独特前缀
    {"name": "OpenAI (Project)", "pattern": r'sk-proj-[A-Za-z0-9_-]{80,}', "env_var": "OPENAI_API_KEY", "provider": "OpenAI"},
    {"name": "OpenAI (Service Account)", "pattern": r'sk-svcacct-[A-Za-z0-9_-]{80,}', "env_var": "OPENAI_API_KEY", "provider": "OpenAI"},
    {"name": "OpenAI (Admin)", "pattern": r'sk-admin-[A-Za-z0-9_-]{20,}', "env_var": "OPENAI_API_KEY", "provider": "OpenAI"},
    {"name": "Anthropic Claude", "pattern": r'sk-ant-api03-[A-Za-z0-9_-]{80,}', "env_var": "ANTHROPIC_API_KEY", "provider": "Anthropic"},
    {"name": "Google Gemini", "pattern": r'AIzaSy[A-Za-z0-9_-]{33}', "env_var": "GOOGLE_API_KEY", "provider": "Google"},
    {"name": "AWS Access Key", "pattern": r'(?:AKIA|ASIA)[A-Z0-9]{16}', "env_var": "AWS_ACCESS_KEY_ID", "provider": "AWS"},
    {"name": "Groq", "pattern": r'gsk_[A-Za-z0-9]{48,}', "env_var": "GROQ_API_KEY", "provider": "Groq"},
    {"name": "HuggingFace", "pattern": r'hf_[A-Za-z0-9]{30,}', "env_var": "HF_TOKEN", "provider": "HuggingFace"},
    {"name": "Replicate", "pattern": r'r8_[A-Za-z0-9]{37,}', "env_var": "REPLICATE_API_TOKEN", "provider": "Replicate"},
    {"name": "Cohere", "pattern": r'co_[A-Za-z0-9]{35,}', "env_var": "COHERE_API_KEY", "provider": "Cohere"},
    {"name": "Fireworks AI", "pattern": r'fw_[A-Za-z0-9_-]{40,}', "env_var": "FIREWORKS_API_KEY", "provider": "Fireworks"},
    {"name": "Cerebras", "pattern": r'csk-[A-Za-z0-9_-]{40,}', "env_var": "CEREBRAS_API_KEY", "provider": "Cerebras"},
    {"name": "xAI Grok", "pattern": r'xai-[A-Za-z0-9_-]{80,}', "env_var": "XAI_API_KEY", "provider": "xAI"},
    {"name": "Perplexity", "pattern": r'pplx-[a-f0-9]{40,}', "env_var": "PERPLEXITY_API_KEY", "provider": "Perplexity"},
    {"name": "OpenRouter", "pattern": r'sk-or-v1-[a-f0-9]{48,}', "env_var": "OPENROUTER_API_KEY", "provider": "OpenRouter"},
    # 通用 sk- 前缀 (OpenAI旧版/DeepSeek/Moonshot/DashScope/百川)
    {"name": "OpenAI/DeepSeek/通义千问", "pattern": r'(?<![a-zA-Z0-9_-])sk-[a-zA-Z0-9]{32,64}(?![a-zA-Z0-9_-])', "env_var": "OPENAI_API_KEY", "provider": "OpenAI/DeepSeek/DashScope"},
]

# AI 相关的环境变量名
AI_ENV_VAR_NAMES = [
    "OPENAI_API_KEY", "OPENAI_API_BASE", "OPENAI_BASE_URL", "OPENAI_ORG_ID",
    "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
    "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
    "DEEPSEEK_API_KEY", "MISTRAL_API_KEY",
    "COHERE_API_KEY", "CO_API_KEY",
    "GROQ_API_KEY", "TOGETHER_API_KEY", "TOGETHERAI_API_KEY",
    "REPLICATE_API_TOKEN", "REPLICATE_API_KEY",
    "HF_TOKEN", "HUGGINGFACE_API_KEY", "HUGGING_FACE_HUB_TOKEN",
    "PERPLEXITY_API_KEY", "XAI_API_KEY",
    "FIREWORKS_API_KEY", "CEREBRAS_API_KEY", "OPENROUTER_API_KEY",
    "DASHSCOPE_API_KEY",
    "QIANFAN_AK", "QIANFAN_SK", "QIANFAN_ACCESS_KEY", "QIANFAN_SECRET_KEY",
    "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY",
    "VOLCENGINE_API_KEY", "ARK_API_KEY",
    "ZHIPUAI_API_KEY", "ZHIPU_API_KEY",
    "MINIMAX_API_KEY", "MINIMAX_GROUP_ID",
    "MOONSHOT_API_KEY",
    "YI_API_KEY", "BAICHUAN_API_KEY",
    "STEP_API_KEY", "TIANGONG_API_KEY",
    "SPARKAI_APP_ID", "SPARKAI_API_KEY", "SPARKAI_API_SECRET",
    "LITELLM_MASTER_KEY", "DIFY_API_KEY",
]

# AI SDK import 关键词
AI_SDK_IMPORTS = [
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("google.generativeai", "Google Gemini"),
    ("google.genai", "Google GenAI"),
    ("mistralai", "Mistral"),
    ("cohere", "Cohere"),
    ("groq", "Groq"),
    ("together", "Together AI"),
    ("replicate", "Replicate"),
    ("huggingface_hub", "HuggingFace"),
    ("transformers", "HuggingFace Transformers"),
    ("dashscope", "通义千问/DashScope"),
    ("qianfan", "百度千帆"),
    ("zhipuai", "智谱AI"),
    ("volcenginesdkarkruntime", "火山引擎/豆包"),
    ("minimax", "MiniMax"),
    ("langchain", "LangChain"),
    ("langchain_openai", "LangChain-OpenAI"),
    ("langchain_anthropic", "LangChain-Anthropic"),
    ("langchain_google_genai", "LangChain-Google"),
    ("langchain_community", "LangChain-Community"),
    ("llama_index", "LlamaIndex"),
    ("autogen", "AutoGen"),
    ("crewai", "CrewAI"),
    ("semantic_kernel", "Semantic Kernel"),
    ("dspy", "DSPy"),
    ("chainlit", "Chainlit"),
    ("streamlit", "Streamlit"),
    ("gradio", "Gradio"),
]

# 已知 AI 服务的进程/端口特征
AI_SERVICE_SIGNATURES = {
    "ollama": {"name": "Ollama", "type": "推理服务", "default_port": 11434, "desc": "本地大模型推理服务"},
    "vllm": {"name": "vLLM", "type": "推理服务", "default_port": 8000, "desc": "高性能 LLM 推理引擎"},
    "llama-server": {"name": "llama.cpp", "type": "推理服务", "default_port": 8080, "desc": "轻量级本地推理"},
    "text-generation-launcher": {"name": "TGI", "type": "推理服务", "default_port": 8080, "desc": "HuggingFace 推理服务"},
    "text-generation-router": {"name": "TGI Router", "type": "推理服务", "default_port": 8080, "desc": "HuggingFace 推理路由"},
    "local-ai": {"name": "LocalAI", "type": "推理服务", "default_port": 8080, "desc": "本地 AI 推理（OpenAI 兼容）"},
    "tritonserver": {"name": "Triton", "type": "推理服务", "default_port": 8000, "desc": "NVIDIA 推理服务"},
    "aphrodite": {"name": "Aphrodite", "type": "推理服务", "default_port": 2242, "desc": "vLLM 分支推理引擎"},
    "chainlit": {"name": "Chainlit", "type": "应用框架", "default_port": 8000, "desc": "对话式 AI 应用"},
    "streamlit": {"name": "Streamlit", "type": "应用框架", "default_port": 8501, "desc": "AI/数据应用框架"},
    "gradio": {"name": "Gradio", "type": "应用框架", "default_port": 7860, "desc": "ML 模型 Web UI"},
    "litellm": {"name": "LiteLLM", "type": "API 代理", "default_port": 4000, "desc": "LLM API 统一代理"},
}

# Docker 镜像名中的 AI 关键词
AI_DOCKER_IMAGES = {
    "ollama": "Ollama", "vllm": "vLLM", "localai": "LocalAI",
    "text-generation-inference": "TGI", "open-webui": "Open WebUI",
    "langgenius/dify": "Dify", "labring/fastgpt": "FastGPT",
    "justsong/one-api": "One API", "calciumion/new-api": "New API",
    "1panel/maxkb": "MaxKB", "mintplexlabs/anythingllm": "AnythingLLM",
    "lobehub/lobe-chat": "LobeChat", "danny-avila/librechat": "LibreChat",
    "litellm": "LiteLLM",
}


def _redact_key(value):
    """脱敏 API Key：显示前4后4，中间用 **** 替代"""
    if len(value) <= 12:
        return value[:3] + '****'
    return value[:4] + '****' + value[-4:]


def scan_ai_api_keys():
    """扫描文件系统中的 AI API Key"""
    findings = []
    scan_dirs = ["/root/pj226", "/root"]
    scan_extensions = {'.env', '.py', '.json', '.yaml', '.yml', '.toml', '.conf', '.cfg', '.ini', '.sh'}
    scan_filenames = {'.env', '.env.local', '.env.production', '.env.development',
                      'config.json', 'config.yaml', 'config.yml', 'settings.json',
                      'settings.yaml', '.credentials.json', 'docker-compose.yml',
                      'docker-compose.yaml', 'compose.yml', 'compose.yaml'}
    scanned_files = set()
    max_files = 500

    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            # 跳过不需要的目录
            dirs[:] = [d for d in dirs if d not in {
                '__pycache__', '.git', 'node_modules', '.venv', 'venv',
                'site-packages', '.cache', '.local', '.npm', '.pip',
            }]
            for fname in files:
                if len(scanned_files) >= max_files:
                    break
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if fname not in scan_filenames and ext not in scan_extensions:
                    continue
                if fpath in scanned_files:
                    continue
                scanned_files.add(fpath)
                try:
                    stat = os.stat(fpath)
                    if stat.st_size > 512 * 1024:  # 跳过大于512KB的文件
                        continue
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                # 检查环境变量名
                for env_name in AI_ENV_VAR_NAMES:
                    env_pattern = re.compile(rf'{re.escape(env_name)}\s*[=:]\s*["\']?(\S+?)["\']?\s*$', re.MULTILINE)
                    for m in env_pattern.finditer(content):
                        val = m.group(1).strip('"').strip("'")
                        if val and len(val) > 8 and val not in ('your-key-here', 'xxx', 'YOUR_API_KEY', 'sk-xxx', ''):
                            # 获取文件权限
                            try:
                                perm = oct(os.stat(fpath).st_mode)[-3:]
                            except Exception:
                                perm = '???'
                            findings.append({
                                "type": "env_var",
                                "name": env_name,
                                "value_redacted": _redact_key(val),
                                "file": fpath,
                                "file_perm": perm,
                                "risk": "high" if perm not in ('600', '400') else "low",
                                "provider": _guess_provider_from_env(env_name),
                            })

                # 检查 API Key 正则模式
                for rule in AI_KEY_PATTERNS:
                    for m in re.finditer(rule["pattern"], content):
                        key_val = m.group(0)
                        # 排除已经通过环境变量找到的
                        already_found = any(
                            f["value_redacted"] == _redact_key(key_val) and f["file"] == fpath
                            for f in findings
                        )
                        if not already_found:
                            try:
                                perm = oct(os.stat(fpath).st_mode)[-3:]
                            except Exception:
                                perm = '???'
                            findings.append({
                                "type": "key_pattern",
                                "name": rule["name"],
                                "value_redacted": _redact_key(key_val),
                                "file": fpath,
                                "file_perm": perm,
                                "risk": "high" if perm not in ('600', '400') else "medium",
                                "provider": rule["provider"],
                            })

    # 去重
    seen = set()
    unique = []
    for f in findings:
        key = (f["value_redacted"], f["file"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def _guess_provider_from_env(env_name):
    """根据环境变量名猜测提供商"""
    mapping = {
        "OPENAI": "OpenAI", "ANTHROPIC": "Anthropic", "GOOGLE": "Google",
        "GEMINI": "Google", "AZURE": "Azure", "DEEPSEEK": "DeepSeek",
        "MISTRAL": "Mistral", "COHERE": "Cohere", "GROQ": "Groq",
        "TOGETHER": "Together AI", "REPLICATE": "Replicate",
        "HF": "HuggingFace", "HUGGING": "HuggingFace", "HUGGINGFACE": "HuggingFace",
        "PERPLEXITY": "Perplexity", "XAI": "xAI", "FIREWORKS": "Fireworks",
        "CEREBRAS": "Cerebras", "OPENROUTER": "OpenRouter",
        "DASHSCOPE": "通义千问/DashScope",
        "QIANFAN": "百度千帆", "TENCENTCLOUD": "腾讯混元",
        "VOLCENGINE": "火山引擎", "ARK": "火山引擎/豆包",
        "ZHIPU": "智谱AI", "MINIMAX": "MiniMax",
        "MOONSHOT": "月之暗面/Kimi", "YI": "零一万物",
        "BAICHUAN": "百川智能", "STEP": "阶跃星辰",
        "TIANGONG": "昆仑万维/天工", "SPARKAI": "讯飞星火",
        "LITELLM": "LiteLLM", "DIFY": "Dify",
    }
    upper = env_name.upper()
    for prefix, provider in mapping.items():
        if prefix in upper:
            return provider
    return "未知"


def discover_ai_services():
    """发现运行中的 AI 服务"""
    services = []
    seen_pids = set()

    # 1. 扫描运行中的进程
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            info = proc.info
            pid = info['pid']
            name = (info['name'] or '').lower()
            cmdline = ' '.join(info['cmdline'] or []).lower()

            # 检查进程名匹配
            for key, sig in AI_SERVICE_SIGNATURES.items():
                if key in name or key in cmdline:
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                    # 获取端口
                    port = None
                    try:
                        conn_fn = getattr(proc, 'net_connections', None) or proc.connections
                        conns = conn_fn(kind='inet')
                        for conn in conns:
                            if conn.status == 'LISTEN':
                                port = conn.laddr.port
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                        pass

                    # 获取工作目录
                    cwd = ''
                    try:
                        cwd = proc.cwd()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    services.append({
                        "pid": pid,
                        "name": sig["name"],
                        "type": sig["type"],
                        "desc": sig["desc"],
                        "process": info['name'],
                        "port": port,
                        "cwd": cwd,
                        "auth": _check_service_auth(port),
                        "exposed": _check_port_exposed(port),
                    })
                    break

            # 检查 Python 命令行中的 AI SDK
            if 'python' in name:
                for sdk_key, sdk_name in AI_SDK_IMPORTS:
                    if sdk_key in cmdline:
                        if pid in seen_pids:
                            continue
                        seen_pids.add(pid)
                        port = None
                        try:
                            conn_fn = getattr(proc, 'net_connections', None) or proc.connections
                            conns = conn_fn(kind='inet')
                            for conn in conns:
                                if conn.status == 'LISTEN':
                                    port = conn.laddr.port
                                    break
                        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                            pass
                        cwd = ''
                        try:
                            cwd = proc.cwd()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        services.append({
                            "pid": pid,
                            "name": sdk_name,
                            "type": "应用框架",
                            "desc": f"{sdk_name} 应用",
                            "process": info['name'],
                            "port": port,
                            "cwd": cwd,
                            "auth": _check_service_auth(port),
                            "exposed": _check_port_exposed(port),
                        })
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # 2. 扫描 Docker 容器中的 AI 服务
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            for line in out.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split('\t')
                container_name = parts[0] if parts else ''
                image = parts[1] if len(parts) > 1 else ''
                ports_str = parts[2] if len(parts) > 2 else ''
                image_lower = image.lower()
                for img_key, ai_name in AI_DOCKER_IMAGES.items():
                    if img_key in image_lower or img_key in container_name.lower():
                        port = None
                        pm = re.search(r':(\d+)->', ports_str)
                        if pm:
                            port = int(pm.group(1))
                        services.append({
                            "pid": None,
                            "name": ai_name,
                            "type": "Docker 容器",
                            "desc": f"Docker 镜像: {image}",
                            "process": f"docker:{container_name}",
                            "port": port,
                            "cwd": "",
                            "auth": _check_service_auth(port) if port else "未知",
                            "exposed": _check_port_exposed(port) if port else False,
                        })
                        break
    except Exception:
        pass

    return services


def _check_port_exposed(port):
    """检查端口是否对外暴露"""
    if not port:
        return False
    try:
        out = subprocess.run(["ss", "-tlnp", "sport", "=", f":{port}"],
                             capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return "0.0.0.0" in out.stdout or "[::]" in out.stdout
    except Exception:
        pass
    return False


def _check_service_auth(port):
    """检查服务是否有认证保护"""
    if not port:
        return "未知"
    try:
        import requests as _req
        resp = _req.get(f"http://127.0.0.1:{port}/", timeout=2, allow_redirects=False)
        if resp.status_code == 401:
            return "HTTP Basic Auth"
        if resp.status_code == 403:
            return "已保护"
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                return "登录页认证"
        # 检查网关保护
        gw_map = get_gateway_mappings()
        reverse_gw = {v: k for k, v in gw_map.items()}
        if port in reverse_gw:
            return "网关Token认证"
        if resp.status_code == 200:
            body = resp.text[:2000].lower()
            if 'login' in body and ('password' in body or 'username' in body):
                return "登录页认证"
            return "无认证"
    except Exception:
        pass
    return "未知"


def scan_ai_code_imports():
    """扫描项目代码中的 AI SDK 使用"""
    imports_found = []
    scan_dirs = ["/root/pj226"]
    scanned = set()

    import_pattern = re.compile(
        r'^\s*(?:import|from)\s+(openai|anthropic|google\.generativeai|google\.genai|'
        r'mistralai|cohere|groq|together|replicate|huggingface_hub|transformers|'
        r'dashscope|qianfan|zhipuai|volcenginesdkarkruntime|minimax|'
        r'langchain|langchain_openai|langchain_anthropic|langchain_google_genai|'
        r'langchain_community|llama_index|autogen|crewai|semantic_kernel|dspy|'
        r'chainlit|streamlit|gradio)',
        re.MULTILINE
    )

    # API URL 特征
    url_pattern = re.compile(
        r'(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|'
        r'api\.deepseek\.com|api\.mistral\.ai|api\.cohere\.\w+|api\.groq\.com|'
        r'api\.together\.xyz|api\.replicate\.com|api-inference\.huggingface\.co|'
        r'dashscope\.aliyuncs\.com|aip\.baidubce\.com|open\.bigmodel\.cn|'
        r'api\.moonshot\.cn|api\.minimaxi\.com|api\.minimax\.io|'
        r'ark\.[^/]+\.volces\.com|api\.stepfun\.com|api\.baichuan-ai\.com|'
        r'api\.lingyiwanwu\.com|spark-api-open\.xf-yun\.com|'
        r'hunyuan\.tencentcloudapi\.com)'
    )

    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in {
                '__pycache__', '.git', 'node_modules', '.venv', 'venv', 'site-packages',
            }]
            for fname in files:
                if not fname.endswith('.py'):
                    continue
                fpath = os.path.join(root, fname)
                if fpath in scanned:
                    continue
                scanned.add(fpath)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                # SDK import
                for m in import_pattern.finditer(content):
                    sdk_name = m.group(1)
                    display_name = sdk_name
                    for key, name in AI_SDK_IMPORTS:
                        if sdk_name.startswith(key):
                            display_name = name
                            break
                    imports_found.append({
                        "sdk": display_name,
                        "import_str": m.group(0).strip(),
                        "file": fpath,
                    })

                # API URL
                for m in url_pattern.finditer(content):
                    url_host = m.group(1)
                    imports_found.append({
                        "sdk": f"API: {url_host}",
                        "import_str": url_host,
                        "file": fpath,
                    })

    # 去重
    seen = set()
    unique = []
    for item in imports_found:
        key = (item["sdk"], item["file"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def assess_ai_risks():
    """评估 AI 相关安全风险"""
    risks = []
    keys = scan_ai_api_keys()
    services = discover_ai_services()
    imports = scan_ai_code_imports()

    # ── 1. API Key 类风险 ──
    # 1a: Key 文件权限过宽
    for k in keys:
        if k["file_perm"] not in ('600', '400'):
            risks.append({
                "level": "high",
                "category": "API Key",
                "title": f"{k['provider']} Key 文件权限过宽",
                "detail": f"文件 {k['file']} 权限为 {k['file_perm']}，其他用户可读取密钥，建议改为 600",
                "fix": f"chmod 600 {k['file']}",
            })

    # 1b: Key 硬编码在源代码中（非 .env / 非 config 文件）
    code_exts = ('.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.sh')
    for k in keys:
        if k.get("type") == "key_pattern" and k["file"].endswith(code_exts):
            risks.append({
                "level": "high",
                "category": "API Key",
                "title": f"{k['provider']} Key 硬编码在源码中",
                "detail": f"文件 {k['file']} 中直接包含 API Key，应移至环境变量或 .env 文件",
                "fix": "将 Key 移到 .env 文件，代码中使用 os.environ 读取",
            })

    # 1c: Key 存放在 .env 但 .gitignore 未排除
    seen_env_dirs = set()
    for k in keys:
        if '.env' in os.path.basename(k["file"]):
            env_dir = os.path.dirname(k["file"])
            if env_dir in seen_env_dirs:
                continue
            seen_env_dirs.add(env_dir)
            gitignore_path = os.path.join(env_dir, '.gitignore')
            env_ignored = False
            if os.path.exists(gitignore_path):
                try:
                    with open(gitignore_path, 'r') as f:
                        for line in f:
                            if '.env' in line.strip():
                                env_ignored = True
                                break
                except Exception:
                    pass
            if not env_ignored:
                risks.append({
                    "level": "medium",
                    "category": "API Key",
                    "title": f".env 文件可能被 Git 追踪",
                    "detail": f"目录 {env_dir} 中的 .env 文件未在 .gitignore 中排除，密钥可能被提交到版本库",
                    "fix": f"在 {env_dir}/.gitignore 中添加 .env",
                })

    # 1d: 同一 Key 在多个文件中出现
    key_files = {}
    for k in keys:
        val = k.get("value_redacted", "")
        if val:
            key_files.setdefault(val, []).append(k["file"])
    for val, files in key_files.items():
        if len(files) > 1:
            risks.append({
                "level": "medium",
                "category": "API Key",
                "title": f"同一 API Key 在 {len(files)} 个文件中重复出现",
                "detail": f"Key ({val}) 出现在: {', '.join(files[:5])}{'...' if len(files)>5 else ''}",
                "fix": "统一在一处管理密钥，其他位置引用环境变量",
            })

    # ── 2. 服务暴露类风险 ──
    for svc in services:
        if svc.get("exposed") and svc.get("auth") == "无认证":
            risks.append({
                "level": "high",
                "category": "服务暴露",
                "title": f"{svc['name']} 对外暴露且无认证",
                "detail": f"端口 {svc.get('port')} 对外暴露，任何人可直接访问 AI 服务，可能被滥用或窃取数据",
                "fix": "添加认证机制或通过网关保护（iptables + Nginx auth_request）",
            })
        elif svc.get("exposed") and svc.get("auth") not in ("无认证", "未知"):
            pass  # 有认证，安全
        elif svc.get("exposed"):
            risks.append({
                "level": "medium",
                "category": "服务暴露",
                "title": f"{svc['name']} 对外暴露（认证状态未知）",
                "detail": f"端口 {svc.get('port')} 对外暴露，无法确认认证状态",
                "fix": "确认服务认证配置，建议加入网关保护",
            })

    # ── 3. 配置风险 ──
    # 3a: Chainlit 配置
    chainlit_configs = []
    for root, dirs, files in os.walk("/root"):
        dirs[:] = [d for d in dirs if d not in {'__pycache__', '.git', 'node_modules', '.local', '.cache'}]
        if root.count(os.sep) > 5:
            dirs.clear()
            continue
        for fname in files:
            if fname == 'config.toml' and '.chainlit' in root:
                chainlit_configs.append(os.path.join(root, fname))
    for cfg_path in chainlit_configs:
        try:
            with open(cfg_path, 'r') as f:
                cfg_content = f.read()
            if 'allow_origins = ["*"]' in cfg_content:
                risks.append({
                    "level": "medium",
                    "category": "配置风险",
                    "title": "Chainlit CORS 配置过宽",
                    "detail": f"{cfg_path} 中 allow_origins = [\"*\"]，允许任意跨域请求，可能被利用进行 CSRF 攻击",
                    "fix": "将 allow_origins 限制为实际使用的域名",
                })
            if 'accept = ["*/*"]' in cfg_content:
                risks.append({
                    "level": "low",
                    "category": "配置风险",
                    "title": "Chainlit 文件上传无类型限制",
                    "detail": f"{cfg_path} 中接受所有文件类型上传，可能被上传恶意文件",
                    "fix": "限制为需要的文件类型（如 .txt, .pdf, .csv）",
                })
        except Exception:
            pass

    # 3b: AI SDK 代码中使用 verify=False 或禁用 SSL
    for imp in imports:
        fpath = imp.get("file", "")
        try:
            with open(fpath, 'r', errors='ignore') as f:
                content = f.read()
            if 'verify=False' in content or 'verify = False' in content:
                risks.append({
                    "level": "medium",
                    "category": "配置风险",
                    "title": "AI 调用禁用了 SSL 验证",
                    "detail": f"文件 {fpath} 中存在 verify=False，可能遭受中间人攻击",
                    "fix": "移除 verify=False，使用正规 CA 证书",
                })
        except Exception:
            pass

    # ── 4. 调用方式风险 ──
    # 4a: 使用 HTTP 而非 HTTPS 调用 AI API
    http_pattern = re.compile(r'http://[^/]*(openai|anthropic|googleapis|deepseek|dashscope|bigmodel|huggingface)', re.I)
    for imp in imports:
        fpath = imp.get("file", "")
        try:
            with open(fpath, 'r', errors='ignore') as f:
                content = f.read()
            matches = http_pattern.findall(content)
            if matches:
                risks.append({
                    "level": "high",
                    "category": "调用方式",
                    "title": "AI API 使用明文 HTTP 调用",
                    "detail": f"文件 {fpath} 中通过 HTTP（非 HTTPS）调用 AI 服务，密钥和数据在传输中未加密",
                    "fix": "将所有 AI API 调用改为 HTTPS",
                })
        except Exception:
            pass

    # 4b: AI 服务日志可能包含敏感对话
    ai_log_patterns = ['/tmp/chainlit', '/tmp/ollama', '/tmp/vllm']
    for lp in ai_log_patterns:
        if os.path.exists(lp):
            try:
                perm = oct(os.stat(lp).st_mode)[-3:]
                if perm not in ('600', '400', '700'):
                    risks.append({
                        "level": "low",
                        "category": "调用方式",
                        "title": "AI 服务日志权限过宽",
                        "detail": f"日志 {lp} 权限为 {perm}，可能包含用户对话等敏感数据",
                        "fix": f"chmod 600 {lp}",
                    })
            except Exception:
                pass

    # ── 排序：high > medium > low ──
    level_order = {"high": 0, "medium": 1, "low": 2}
    risks.sort(key=lambda r: level_order.get(r["level"], 9))

    # 统计
    categories = sorted(set(r["category"] for r in risks))
    summary = {
        "high": sum(1 for r in risks if r["level"] == "high"),
        "medium": sum(1 for r in risks if r["level"] == "medium"),
        "low": sum(1 for r in risks if r["level"] == "low"),
        "total": len(risks),
        "categories": categories,
    }

    return {"risks": risks, "summary": summary}


def get_ai_security_data():
    """获取完整的 AI 安全数据"""
    services = discover_ai_services()
    keys = scan_ai_api_keys()
    imports = scan_ai_code_imports()
    risk_data = assess_ai_risks()

    return {
        "services": services,
        "service_count": len(services),
        "api_keys": keys,
        "key_count": len(keys),
        "imports": imports,
        "import_count": len(imports),
        "risks": risk_data["risks"],
        "risk_summary": risk_data["summary"],
    }


# ============ 路由 ============

@app.route("/")
@requires_auth
def index():
    return redirect("/services")


@app.route("/services")
@requires_auth
def services_page():
    return render_template("services.html")


@app.route("/api/data")
@requires_auth
def api_data():
    """返回所有监控数据的JSON接口"""
    range_str = request.args.get("range", "30d")
    days = _parse_range(range_str)

    # 共享 parse_auth_log 结果
    auth_log_result = _cached_call('parse_auth_log', parse_auth_log, ttl=60)

    # 通知未读数（安全导入，模块不存在时不影响主接口）
    try:
        from notifications import get_unread_count
        unread = get_unread_count()
    except Exception:
        unread = 0

    # 并行执行互相独立的采集函数
    with ThreadPoolExecutor(max_workers=6) as executor:
        f_attack = executor.submit(get_attack_stats, days=days, _auth_log_result=auth_log_result)
        f_firewall_blocks = executor.submit(get_firewall_block_stats, days=days)
        f_ssh_config = executor.submit(get_ssh_config)
        f_ssh_sessions = executor.submit(get_ssh_sessions)
        f_firewall = executor.submit(get_firewall_status)
        f_fail2ban = executor.submit(get_fail2ban_status)
        f_ports = executor.submit(get_listening_ports)
        f_system = executor.submit(get_system_resources)
        f_cron = executor.submit(get_cron_jobs)

    data = {
        "attack_stats": f_attack.result(),
        "firewall_blocks": f_firewall_blocks.result(),
        "ssh_config": f_ssh_config.result(),
        "ssh_sessions": f_ssh_sessions.result(),
        "firewall": f_firewall.result(),
        "fail2ban": f_fail2ban.result(),
        "ports": f_ports.result(),
        "system": f_system.result(),
        "cron_jobs": f_cron.result(),
        "unread_count": unread,
        "current_range": range_str,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return jsonify(data)


@app.route("/api/ai-security")
@requires_auth
def api_ai_security():
    """返回 AI 安全模块数据"""
    return jsonify(get_ai_security_data())


_ALLOWED_JAILS = {'sshd', 'nginx-http-auth'}


@app.route("/api/fail2ban/ban", methods=["POST"])
@requires_auth
def fail2ban_ban():
    """手动封禁 IP"""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    jail = data.get("jail", "sshd")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return jsonify({"error": "无效的 IP 地址"}), 400
    if jail not in _ALLOWED_JAILS:
        return jsonify({"error": f"不允许的 jail，可选: {', '.join(sorted(_ALLOWED_JAILS))}"}), 400
    try:
        out = subprocess.run(
            ["fail2ban-client", "set", jail, "banip", ip],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return jsonify({"ok": True, "message": f"已封禁 {ip}"})
        return jsonify({"error": out.stderr.strip() or "封禁失败"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Fail2Ban 未安装"}), 500


@app.route("/api/fail2ban/unban", methods=["POST"])
@requires_auth
def fail2ban_unban():
    """解封 IP"""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    jail = data.get("jail", "sshd")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return jsonify({"error": "无效的 IP 地址"}), 400
    if jail not in _ALLOWED_JAILS:
        return jsonify({"error": f"不允许的 jail，可选: {', '.join(sorted(_ALLOWED_JAILS))}"}), 400
    try:
        out = subprocess.run(
            ["fail2ban-client", "set", jail, "unbanip", ip],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return jsonify({"ok": True, "message": f"已解封 {ip}"})
        return jsonify({"error": out.stderr.strip() or "解封失败"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Fail2Ban 未安装"}), 500


@app.route("/api/ssh/toggle-password-auth", methods=["POST"])
@requires_auth
def toggle_ssh_password_auth():
    """切换 SSH 密码认证开关"""
    data = request.get_json() or {}
    enable = data.get("enable", False)
    new_val = "yes" if enable else "no"
    config_file = "/etc/ssh/sshd_config"

    try:
        with open(config_file, "r") as f:
            lines = f.readlines()

        found = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("PasswordAuthentication") or stripped.startswith("#PasswordAuthentication"):
                new_lines.append(f"PasswordAuthentication {new_val}\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"\nPasswordAuthentication {new_val}\n")

        with open(config_file, "w") as f:
            f.writelines(new_lines)

        # 重启 sshd
        subprocess.run(["systemctl", "restart", "sshd"], capture_output=True, timeout=10)
        return jsonify({"ok": True, "password_auth": new_val})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/services")
@requires_auth
def api_services():
    """返回所有运行中服务的详细信息"""
    return jsonify({
        "services": get_services_detail(),
        "system": get_system_resources(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


import requests as http_requests

GATEWAY_URL = "http://127.0.0.1:5002"


@app.route("/api/unprotected-ports")
@requires_auth
def api_unprotected_ports():
    """返回对外暴露但未受网关保护的端口列表"""
    # 获取所有服务端口
    all_services = get_services_detail()

    # 获取已保护端口
    gw_map = get_gateway_mappings()
    protected_backend_ports = set(gw_map.values())  # 业务端口集合
    proxy_ports = set(gw_map.keys())  # Nginx 代理端口集合

    # 系统排除端口
    excluded = {22, 53, 5002}  # SSH, DNS, 网关认证服务自身

    unprotected = []
    for svc in all_services:
        port = svc["port"]
        # 跳过：非对外暴露、已保护、Nginx 代理端口、系统端口、20000+ 端口
        if not svc["exposed"]:
            continue
        if port in protected_backend_ports:
            continue
        if port in proxy_ports:
            continue
        if port in excluded:
            continue
        if port >= 20000:
            continue
        # 跳过网关认证服务自身的端口角色
        if svc.get("port_role") == "auth_service":
            continue

        unprotected.append({
            "port": port,
            "svc_name": svc.get("svc_name", ""),
            "svc_desc": svc.get("svc_desc", ""),
            "process": svc.get("process", ""),
        })

    return jsonify({"ports": unprotected})


@app.route("/api/gateway/<path:path>", methods=["GET", "POST", "DELETE"])
@requires_auth
def proxy_gateway(path):
    """代理网关 API 请求到认证服务

    Dashboard 已通过 @requires_auth 验证用户身份，
    代理请求不传 X-Real-IP，让 Gateway 看到 127.0.0.1（本机信任）自动放行。
    """
    url = f"{GATEWAY_URL}/auth/api/{path}"
    try:
        if request.method == "GET":
            resp = http_requests.get(url, timeout=5)
        elif request.method == "POST":
            resp = http_requests.post(url, json=request.get_json(silent=True), timeout=5)
        elif request.method == "DELETE":
            resp = http_requests.delete(url, timeout=5)
        return (resp.content, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ============ 通知系统 API ============

@app.route("/api/notifications")
@requires_auth
def api_notifications():
    """获取通知列表"""
    from notifications import get_notifications, get_unread_count
    status = request.args.get("status")
    try:
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return jsonify({"error": "参数类型错误"}), 400
    notifs = get_notifications(status=status, limit=limit, offset=offset)
    return jsonify({"notifications": notifs, "unread_count": get_unread_count()})


@app.route("/api/notifications", methods=["POST"])
@requires_auth
def api_notifications_action():
    """操作通知：已读/忽略/全部已读"""
    from notifications import mark_notification, mark_all_read
    data = request.get_json() or {}
    action = data.get("action")
    if action == "read_all":
        mark_all_read()
        return jsonify({"ok": True})
    notif_id = data.get("id")
    if not notif_id or action not in ("read", "ignore"):
        return jsonify({"error": "参数错误"}), 400
    mark_notification(notif_id, action if action == "ignore" else "read")
    return jsonify({"ok": True})


@app.route("/api/notifications/count")
@requires_auth
def api_notifications_count():
    """轻量接口：仅返回未读计数"""
    from notifications import get_unread_count
    return jsonify({"unread_count": get_unread_count()})


# ============ AI 助手 API Key 设置 ============

@app.route("/api/llm-settings", methods=["GET"])
@requires_auth
def api_llm_settings_get():
    """读取 Anthropic API Key（脱敏返回）"""
    from shared import load_credentials
    creds = load_credentials()
    api_key = creds.get("anthropic_api_key", "")
    masked_key = ""
    if api_key:
        if len(api_key) > 8:
            masked_key = api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:]
        else:
            masked_key = "****"
    return jsonify({
        "api_key": masked_key,
        "configured": bool(api_key),
    })


@app.route("/api/llm-settings", methods=["POST"])
@requires_auth
def api_llm_settings_post():
    """保存 Anthropic API Key 到 .credentials.json"""
    from shared import load_credentials, save_credentials
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求体不能为空"}), 400

    api_key = (data.get("api_key") or "").strip()
    if not api_key:
        return jsonify({"error": "API Key 不能为空"}), 400

    creds = load_credentials()
    creds["anthropic_api_key"] = api_key
    save_credentials(creds)
    return jsonify({"ok": True, "message": "API Key 已保存，AI 助手将在下次对话时自动生效。"})


@app.route("/api/llm-settings/test", methods=["GET"])
@requires_auth
def api_llm_settings_test():
    """测试 API Key 是否有效（用 requests 调 Anthropic API）"""
    import requests as http_req
    from shared import load_credentials
    creds = load_credentials()
    api_key = creds.get("anthropic_api_key", "")

    if not api_key:
        return jsonify({"ok": False, "error": "未配置 API Key，请先保存"})

    try:
        resp = http_req.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "Hi"}],
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return jsonify({"ok": True, "message": "API Key 有效，连接成功！"})
        elif resp.status_code == 401:
            return jsonify({"ok": False, "error": "API Key 无效，请检查后重新输入"})
        else:
            err_text = resp.text[:200]
            return jsonify({"ok": False, "error": f"HTTP {resp.status_code}: {err_text}"})
    except http_req.exceptions.Timeout:
        return jsonify({"ok": False, "error": "连接超时，请检查网络"})
    except Exception as e:
        return jsonify({"ok": False, "error": f"测试失败: {str(e)[:200]}"})


# 注册安全扫描 Blueprint
try:
    from scanner import create_scanner_blueprint
    scanner_bp = create_scanner_blueprint()

    @scanner_bp.before_request
    def scanner_auth():
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()

    app.register_blueprint(scanner_bp)
except ImportError:
    print("[WARN] scanner 模块未找到，安全扫描功能不可用")


# AlertEngine 模块级启动（兼容 gunicorn 多 worker 模式）
import threading as _threading

_alert_engine_started = False
_alert_engine_lock = _threading.Lock()


def _start_alert_engine():
    global _alert_engine_started
    with _alert_engine_lock:
        if _alert_engine_started:
            return
        _alert_engine_started = True
    try:
        from notifications import AlertEngine
        _engine = AlertEngine()
        _engine.start()
    except Exception as e:
        print(f"[AlertEngine] 启动失败: {e}")


_start_alert_engine()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
