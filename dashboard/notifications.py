"""
通知与告警模块 - SQLite 存储层 + AlertEngine 检测引擎
负责安全告警的持久化存储和自动化检测
"""

import sqlite3
import json
import os
import atexit
import threading
from datetime import datetime, timedelta

# 数据库文件路径
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'notifications.db')

# 线程本地存储，保证每个线程使用独立的数据库连接
_local = threading.local()


_all_conns = []
_all_conns_lock = threading.Lock()


def _get_conn():
    """获取当前线程的数据库连接（线程安全）"""
    if not hasattr(_local, 'conn') or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        with _all_conns_lock:
            _all_conns.append(_local.conn)
    return _local.conn


def _cleanup_all_conns():
    """atexit 时关闭所有 SQLite 连接"""
    with _all_conns_lock:
        for conn in _all_conns:
            try:
                conn.close()
            except Exception:
                pass
        _all_conns.clear()


atexit.register(_cleanup_all_conns)


def _row_to_dict(row):
    """将 sqlite3.Row 对象转换为普通字典"""
    if row is None:
        return None
    d = dict(row)
    if 'context' in d and d['context']:
        try:
            d['context'] = json.loads(d['context'])
        except (json.JSONDecodeError, TypeError):
            pass
    return d


# ========== 数据库初始化 ==========

def init_db():
    """初始化数据库，创建通知表和状态表"""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            level TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            dedup_key TEXT,
            status TEXT DEFAULT 'unread',
            context TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            resolved_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_state (
            state_key TEXT PRIMARY KEY,
            state_value TEXT,
            updated_at TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_dedup_key ON notifications(dedup_key)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)")

    conn.commit()


# ========== 存储层函数 ==========

def create_notification(alert_type, level, title, message, dedup_key=None, context=None):
    """
    创建通知，同 dedup_key 的活跃通知存在则跳过
    活跃 = status in ('unread','read') AND resolved_at IS NULL
    """
    conn = _get_conn()
    now = datetime.now().isoformat()

    if dedup_key:
        existing = conn.execute(
            """SELECT id FROM notifications
               WHERE dedup_key = ? AND status IN ('unread', 'read') AND resolved_at IS NULL""",
            (dedup_key,)
        ).fetchone()
        if existing:
            return None

    ctx_str = json.dumps(context, ensure_ascii=False) if context else None
    cursor = conn.execute(
        """INSERT INTO notifications
           (alert_type, level, title, message, dedup_key, status, context, created_at)
           VALUES (?, ?, ?, ?, ?, 'unread', ?, ?)""",
        (alert_type, level, title, message, dedup_key, ctx_str, now)
    )
    conn.commit()
    return cursor.lastrowid


def get_notifications(status=None, level=None, limit=50, offset=0):
    """查询通知列表，按时间倒序（最新的在最上面）"""
    conn = _get_conn()
    query = """SELECT * FROM notifications WHERE 1=1"""
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if level:
        query += " AND level = ?"
        params.append(level)

    query += """ ORDER BY created_at DESC LIMIT ? OFFSET ?"""
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def mark_notification(notif_id, status):
    """标记通知状态（read/ignored）"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE notifications SET status = ?, updated_at = ? WHERE id = ?",
        (status, now, notif_id)
    )
    conn.commit()


def mark_all_read():
    """将全部未读通知标记为已读"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE notifications SET status = 'read', updated_at = ? WHERE status = 'unread'",
        (now,)
    )
    conn.commit()


def get_unread_count():
    """获取未读通知计数"""
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM notifications WHERE status = 'unread'"
    ).fetchone()
    return row['cnt']


def resolve_by_dedup_key(key):
    """按 dedup_key 解决通知，设置 resolved_at，释放后可重新告警"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        """UPDATE notifications SET resolved_at = ?, updated_at = ?
           WHERE dedup_key = ? AND resolved_at IS NULL""",
        (now, now, key)
    )
    conn.commit()


def get_state(key):
    """读取状态快照"""
    conn = _get_conn()
    row = conn.execute(
        "SELECT state_value FROM alert_state WHERE state_key = ?", (key,)
    ).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row['state_value'])
    except (json.JSONDecodeError, TypeError):
        return row['state_value']


def set_state(key, value):
    """写入状态快照"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    val_str = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    conn.execute(
        "INSERT OR REPLACE INTO alert_state (state_key, state_value, updated_at) VALUES (?, ?, ?)",
        (key, val_str, now)
    )
    conn.commit()


def cleanup_old(days=30):
    """清理 N 天前的已处理通知，并自动降级长时间未读的低优先级通知"""
    conn = _get_conn()
    now = datetime.now()

    # 自动降级：info 7天未读 → 自动已读
    info_cutoff = (now - timedelta(days=7)).isoformat()
    conn.execute(
        """UPDATE notifications SET status = 'read', updated_at = ?
           WHERE status = 'unread' AND level = 'info' AND created_at < ?""",
        (now.isoformat(), info_cutoff)
    )

    # 自动降级：warning 14天未读 → 自动已读
    warning_cutoff = (now - timedelta(days=14)).isoformat()
    conn.execute(
        """UPDATE notifications SET status = 'read', updated_at = ?
           WHERE status = 'unread' AND level = 'warning' AND created_at < ?""",
        (now.isoformat(), warning_cutoff)
    )

    # critical 不自动清理

    # 清理已处理通知
    cutoff = (now - timedelta(days=days)).isoformat()
    conn.execute(
        """DELETE FROM notifications
           WHERE created_at < ? AND (status IN ('read', 'ignored') OR resolved_at IS NOT NULL)""",
        (cutoff,)
    )
    conn.commit()


# ========== AlertEngine 检测引擎 ==========

class AlertEngine(threading.Thread):
    """安全告警检测引擎，daemon 线程，60 秒一次循环"""

    def __init__(self):
        super().__init__(daemon=True)
        self.name = "AlertEngine"
        init_db()
        self._tick = 0
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self._run_checks()
            except Exception as e:
                print(f"[AlertEngine] error: {e}")
            self._stop_event.wait(60)
            self._tick += 1

    def stop(self):
        self._stop_event.set()

    def _run_checks(self):
        # 共享 parse_auth_log 结果
        auth_log_result = None
        try:
            from app import parse_auth_log
            auth_log_result = parse_auth_log()
        except Exception as e:
            print(f"[AlertEngine] parse_auth_log error: {e}")

        if auth_log_result is not None:
            failed, successful = auth_log_result
            self._check_ssh_brute_force(failed)
            self._check_new_ssh_login(successful)
        else:
            self._check_ssh_brute_force()
            self._check_new_ssh_login()

        # 每次（1min）
        self._check_fail2ban_bans()

        # 每 5min（原为每 1min，降低重量级检测频率）
        if self._tick % 5 == 0:
            self._check_service_stopped()
            self._check_suspicious_requests()

        # 每 2min
        if self._tick % 2 == 0:
            self._check_unprotected_ports()

        # 每 5min
        if self._tick % 5 == 0:
            self._check_ssh_password_auth()
            self._check_disk_usage()

        # 每 10min（原为每 5min，降低重量级检测频率）
        if self._tick % 10 == 0:
            self._check_ai_no_auth()

        # 每小时清理（含自动降级未读通知）
        if self._tick % 60 == 0:
            cleanup_old(30)

    # ---- 规则 1：SSH 密码登录未关闭 ----
    def _check_ssh_password_auth(self):
        try:
            password_auth_on = False
            sshd_config = '/etc/ssh/sshd_config'
            if not os.path.exists(sshd_config):
                return
            with open(sshd_config, 'r') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith('#') or not stripped:
                        continue
                    if stripped.lower().startswith('passwordauthentication'):
                        val = stripped.split()[-1].lower()
                        password_auth_on = (val == 'yes')

            if password_auth_on:
                create_notification(
                    alert_type='ssh_config',
                    level='warning',
                    title='SSH 密码登录未关闭',
                    message='当前 SSH 配置允许密码登录，建议关闭密码认证仅使用密钥登录，以防止暴力破解攻击。',
                    dedup_key='ssh_password_auth',
                    context={'file': sshd_config}
                )
            else:
                resolve_by_dedup_key('ssh_password_auth')
        except Exception as e:
            print(f"[AlertEngine] _check_ssh_password_auth error: {e}")

    # ---- 规则 2：新端口未受保护 ----
    def _check_unprotected_ports(self):
        try:
            from app import get_listening_ports

            listening = get_listening_ports()
            protected_ports = set()
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'gateway', 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                for p in cfg.get('protected_ports', {}):
                    protected_ports.add(int(p))

            skip_ports = {22, 53, 5002}

            for item in listening:
                port = int(item.get('port', 0))
                exposed = item.get('exposed', True)

                if port in skip_ports or port >= 20000:
                    continue
                if not exposed:
                    continue

                dedup = f'unprotected_port_{port}'
                if port not in protected_ports:
                    create_notification(
                        alert_type='port_protection',
                        level='warning',
                        title=f'端口 {port} 未受网关保护',
                        message=f'检测到监听端口 {port} 未被安全网关保护，外部可直接访问，建议添加至网关保护列表。',
                        dedup_key=dedup,
                        context={'port': port}
                    )
                else:
                    resolve_by_dedup_key(dedup)
        except Exception as e:
            print(f"[AlertEngine] _check_unprotected_ports error: {e}")

    # ---- 规则 3：新 IP SSH 登录成功 ----
    def _check_new_ssh_login(self, successful=None):
        try:
            if successful is None:
                from app import parse_auth_log
                _failed, successful = parse_auth_log()
            current_ips = set()
            for entry in successful:
                ip = entry.get('ip')
                if ip:
                    current_ips.add(ip)

            known_ips = get_state('known_ssh_ips')

            if known_ips is None:
                # 首次启动保护：只写基线不告警
                set_state('known_ssh_ips', list(current_ips))
                return

            known_set = set(known_ips)
            new_ips = current_ips - known_set

            for ip in new_ips:
                create_notification(
                    alert_type='ssh_login',
                    level='info',
                    title=f'新 IP 登录 SSH: {ip}',
                    message=f'检测到来自新 IP 地址 {ip} 的 SSH 登录成功，请确认是否为授权访问。',
                    dedup_key=f'new_ssh_login_{ip}',
                    context={'ip': ip}
                )

            # 更新已知 IP 列表
            if new_ips:
                set_state('known_ssh_ips', list(known_set | current_ips))
        except Exception as e:
            print(f"[AlertEngine] _check_new_ssh_login error: {e}")

    # ---- 规则 4：Fail2Ban 封禁新 IP ----
    def _check_fail2ban_bans(self):
        try:
            from app import get_fail2ban_status

            status = get_fail2ban_status()
            # get_fail2ban_status() 返回 dict: {running, jails, banned_ips, banned_list, jail_details}
            current_banned = set(status.get('banned_list', []))

            known_banned = get_state('known_banned_ips')

            if known_banned is None:
                # 首次启动保护
                set_state('known_banned_ips', list(current_banned))
                return

            known_set = set(known_banned)
            new_banned = current_banned - known_set

            for ip in new_banned:
                create_notification(
                    alert_type='fail2ban',
                    level='info',
                    title=f'Fail2Ban 封禁 IP: {ip}',
                    message=f'Fail2Ban 已自动封禁 IP 地址 {ip}，该 IP 存在异常访问行为。',
                    dedup_key=f'fail2ban_ban_{ip}',
                    context={'ip': ip}
                )

            if new_banned:
                set_state('known_banned_ips', list(known_set | current_banned))
        except Exception as e:
            print(f"[AlertEngine] _check_fail2ban_bans error: {e}")

    # ---- 规则 5：SSH 暴力破解突增（1h>100次） ----
    def _check_ssh_brute_force(self, failed=None):
        try:
            if failed is None:
                from app import parse_auth_log
                failed, _successful = parse_auth_log()
            # failed 列表每项: {time: datetime, user: str, ip: str}
            one_hour_ago = datetime.now() - timedelta(hours=1)
            fail_count = sum(1 for entry in failed if entry.get('time') and entry['time'] >= one_hour_ago)

            hour_key = datetime.now().strftime('%Y%m%d%H')
            dedup = f'ssh_brute_force_{hour_key}'

            if fail_count > 100:
                create_notification(
                    alert_type='brute_force',
                    level='critical',
                    title='SSH 暴力破解攻击突增',
                    message=f'最近 1 小时内检测到 {fail_count} 次 SSH 登录失败，疑似暴力破解攻击，请立即检查。',
                    dedup_key=dedup,
                    context={'fail_count': fail_count, 'hour': hour_key}
                )
        except Exception as e:
            print(f"[AlertEngine] _check_ssh_brute_force error: {e}")

    # ---- 规则 6：AI 服务无认证暴露 ----
    def _check_ai_no_auth(self):
        try:
            from app import discover_ai_services

            services = discover_ai_services()
            current_keys = set()

            for svc in services:
                name = svc.get('name', 'unknown')
                port = svc.get('port', 0)
                exposed = svc.get('exposed', False)
                auth = svc.get('auth', '')
                dedup = f'ai_no_auth_{name}_{port}'
                current_keys.add(dedup)

                if exposed and auth == '无认证':
                    create_notification(
                        alert_type='ai_service',
                        level='warning',
                        title=f'AI 服务无认证暴露: {name}',
                        message=f'AI 服务 {name}（端口 {port}）已暴露且无认证保护，任何人可直接访问，存在安全风险。',
                        dedup_key=dedup,
                        context={'name': name, 'port': port}
                    )
                else:
                    resolve_by_dedup_key(dedup)
        except Exception as e:
            print(f"[AlertEngine] _check_ai_no_auth error: {e}")

    # ---- 规则 7：服务异常停止 ----
    def _check_service_stopped(self):
        try:
            from app import get_services_detail

            current_services = get_services_detail()
            current_set = {}
            for svc in current_services:
                port = svc.get('port', 0)
                proc = svc.get('process', svc.get('name', 'unknown'))
                key = f'{port}_{proc}'
                current_set[key] = svc

            known_services = get_state('known_services')

            if known_services is None:
                # 首次启动保护
                set_state('known_services', list(current_set.keys()))
                return

            known_keys = set(known_services)
            current_keys = set(current_set.keys())

            # 发现缺少的服务
            missing = known_keys - current_keys
            for key in missing:
                parts = key.split('_', 1)
                port = parts[0]
                proc = parts[1] if len(parts) > 1 else 'unknown'
                dedup = f'service_stopped_{port}_{proc}'
                create_notification(
                    alert_type='service_down',
                    level='critical',
                    title=f'服务异常停止: {proc} (端口 {port})',
                    message=f'检测到服务 {proc}（端口 {port}）已停止运行，请立即检查并恢复服务。',
                    dedup_key=dedup,
                    context={'port': port, 'process': proc}
                )

            # 恢复的服务
            recovered = current_keys - known_keys
            for key in recovered:
                parts = key.split('_', 1)
                port = parts[0]
                proc = parts[1] if len(parts) > 1 else 'unknown'
                resolve_by_dedup_key(f'service_stopped_{port}_{proc}')

            # 更新已知服务列表
            set_state('known_services', list(current_keys))
        except Exception as e:
            print(f"[AlertEngine] _check_service_stopped error: {e}")

    # ---- 规则 8：异常请求突增（1h>50次） ----
    def _check_suspicious_requests(self):
        try:
            from app import parse_nginx_access_log
            result = parse_nginx_access_log(hours=1)
            total = result.get('total_suspicious', 0)

            hour_key = datetime.now().strftime('%Y%m%d%H')
            dedup = f'suspicious_requests_{hour_key}'

            if total > 50:
                create_notification(
                    alert_type='suspicious_requests',
                    level='warning',
                    title='异常请求突增告警',
                    message=f'最近 1 小时内检测到 {total} 次异常请求（SQL注入/XSS/路径遍历等），请检查 Nginx 访问日志。',
                    dedup_key=dedup,
                    context={'count': total, 'hour': hour_key}
                )
        except Exception as e:
            print(f"[AlertEngine] _check_suspicious_requests error: {e}")

    # ---- 规则 9：磁盘空间不足（>90%） ----
    def _check_disk_usage(self):
        try:
            import psutil
            usage = psutil.disk_usage('/')
            percent = usage.percent

            if percent > 90:
                create_notification(
                    alert_type='disk_usage',
                    level='warning',
                    title='磁盘空间不足',
                    message=f'根分区磁盘使用率已达 {percent}%，超过 90% 警戒线，请及时清理磁盘空间。',
                    dedup_key='disk_usage_high',
                    context={'percent': percent, 'total_gb': round(usage.total / (1024**3), 1)}
                )
            else:
                resolve_by_dedup_key('disk_usage_high')
        except Exception as e:
            print(f"[AlertEngine] _check_disk_usage error: {e}")
