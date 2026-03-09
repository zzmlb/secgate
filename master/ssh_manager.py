"""SSH 连接管理器 - Paramiko 封装、连接池、SecGate 检测

认证方式参考 pj35/ssh-file-manager：
  - password: 密码认证
  - key_file: 本机密钥文件（自动检测 ~/.ssh/ 下所有私钥，无需指定路径）
  - key: 粘贴的私钥内容
"""

import io
import os
import threading
import time
import paramiko


class SSHConnection:
    """Paramiko SSH 连接封装，支持 password / key_file / key 三种认证"""

    def __init__(self, host, port=22, username='root',
                 auth_type='password', password=None,
                 private_key=None, key_file=None,
                 timeout=10):
        self.host = host
        self.port = port
        self.username = username
        self.auth_type = auth_type      # "password", "key_file", "key"
        self.password = password
        self.private_key = private_key  # 粘贴的私钥内容
        self.key_file = key_file        # 密钥文件路径（可选）
        self.timeout = timeout
        self._client = None

    def connect(self):
        """建立 SSH 连接"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )

        if self.auth_type == 'key_file':
            # 自动检测本机密钥文件（与 pj35 一致）
            key_path = self.key_file or self._find_local_key()
            if key_path:
                kwargs['key_filename'] = os.path.expanduser(key_path)
            else:
                # 回退：让 paramiko 自动查找
                kwargs['look_for_keys'] = True
                kwargs.pop('allow_agent', None)
        elif self.auth_type == 'key' and self.private_key:
            # 粘贴的私钥内容
            pkey = self._load_key_from_string(self.private_key)
            kwargs['pkey'] = pkey
        else:
            # 密码认证
            kwargs['password'] = self.password or ''

        client.connect(**kwargs)
        self._client = client
        return client

    def close(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def exec_command(self, cmd, timeout=15):
        """执行远程命令，返回 (exit_code, stdout, stderr)"""
        if not self._client:
            raise RuntimeError('SSH 未连接')
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, stdout.read().decode('utf-8', errors='replace').strip(), \
            stderr.read().decode('utf-8', errors='replace').strip()

    @staticmethod
    def _find_local_key():
        """扫描 ~/.ssh/ 自动查找第一个可用的私钥文件"""
        ssh_dir = os.path.expanduser('~/.ssh')
        if not os.path.isdir(ssh_dir):
            return None
        # 常见密钥文件名优先
        candidates = ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa']
        for name in candidates:
            path = os.path.join(ssh_dir, name)
            if os.path.isfile(path):
                return path
        # 再扫描其余文件
        for fname in sorted(os.listdir(ssh_dir)):
            if fname.endswith('.pub') or fname in (
                'known_hosts', 'config', 'authorized_keys', 'known_hosts.old'
            ):
                continue
            fpath = os.path.join(ssh_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, 'r') as f:
                    first_line = f.readline()
                if 'PRIVATE KEY' in first_line or 'BEGIN OPENSSH' in first_line:
                    return fpath
            except Exception:
                continue
        return None

    @staticmethod
    def _load_key_from_string(key_text):
        """从私钥文本内容加载 paramiko 密钥对象"""
        key_classes = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]
        last_err = None
        for cls in key_classes:
            try:
                return cls.from_private_key(io.StringIO(key_text))
            except Exception as e:
                last_err = e
        raise last_err


class ConnectionPool:
    """线程安全 SSH 连接池，自动清理超时连接"""

    IDLE_TIMEOUT = 300  # 秒

    def __init__(self):
        self._pool = {}   # node_id -> (SSHConnection, last_used_ts)
        self._lock = threading.Lock()
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def get(self, node_id, connect_fn):
        """获取连接，不存在则调用 connect_fn 创建"""
        with self._lock:
            if node_id in self._pool:
                conn, _ = self._pool[node_id]
                transport = conn._client.get_transport() if conn._client else None
                if transport and transport.is_active():
                    self._pool[node_id] = (conn, time.time())
                    return conn
                else:
                    conn.close()
                    del self._pool[node_id]
        conn = connect_fn()
        with self._lock:
            self._pool[node_id] = (conn, time.time())
        return conn

    def remove(self, node_id):
        with self._lock:
            item = self._pool.pop(node_id, None)
            if item:
                item[0].close()

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                expired = [nid for nid, (_, ts) in self._pool.items()
                           if now - ts > self.IDLE_TIMEOUT]
                for nid in expired:
                    item = self._pool.pop(nid, None)
                    if item:
                        item[0].close()


# 全局连接池实例
_pool = ConnectionPool()


def get_pool():
    return _pool


def check_secgate(conn):
    """通过 SSH 检测远程主机的 SecGate 安装状态和服务状态

    检测策略（纯只读，不干预子节点）：
    1. VERSION 文件 → 确认安装 + 版本号
    2. secgate status → 解析各服务运行状态和 PID
    3. 从 PID 反查实际监听端口（不硬编码 5000/5002）
    4. curl 验证端口上跑的确实是 SecGate Dashboard
    """
    info = {
        'installed': False,
        'version': None,
        'install_path': None,
        'dashboard_running': False,
        'gateway_running': False,
        'dashboard_port': None,
        'gateway_port': None,
    }

    # ---- 1. 检测安装：读 VERSION 文件 ----
    code, out, _ = conn.exec_command(
        'for p in /opt/secgate /root/pj226; do '
        '  [ -f "$p/VERSION" ] && echo "$p" && cat "$p/VERSION" && exit 0; '
        'done; exit 1'
    )
    if code == 0 and out:
        lines = out.strip().split('\n')
        info['install_path'] = lines[0]
        info['version'] = lines[1].strip()[:20] if len(lines) > 1 else None
        info['installed'] = True

    # 备用：检测 secgate 命令是否存在
    if not info['installed']:
        code, out, _ = conn.exec_command('which secgate 2>/dev/null')
        if code == 0 and out.strip():
            info['installed'] = True

    if not info['installed']:
        return info

    # ---- 2. secgate status → 解析 PID ----
    dashboard_pid = None
    gateway_pid = None
    code, out, _ = conn.exec_command('secgate status 2>/dev/null')
    if code == 0 and out:
        for line in out.split('\n'):
            low = line.lower()
            # 格式: "  dashboard     运行中  PID=1023951"
            if 'dashboard' in low and '运行中' in line:
                info['dashboard_running'] = True
                pid = _extract_pid(line)
                if pid:
                    dashboard_pid = pid
            elif 'gateway' in low and '运行中' in line:
                info['gateway_running'] = True
                pid = _extract_pid(line)
                if pid:
                    gateway_pid = pid

    # ---- 3. 从 PID 反查监听端口（不硬编码） ----
    if dashboard_pid:
        port = _pid_to_port(conn, dashboard_pid)
        if port:
            info['dashboard_port'] = port

    if gateway_pid:
        port = _pid_to_port(conn, gateway_pid)
        if port:
            info['gateway_port'] = port

    # ---- 4. 没拿到 PID 时回退：用 systemd 服务名检测 ----
    if info['dashboard_running'] and not info['dashboard_port']:
        # 尝试从 systemd ExecStart 中提取端口
        port = _detect_port_from_systemd(conn, 'secgate-dashboard')
        if port:
            info['dashboard_port'] = port

    if not info['dashboard_running']:
        # secgate 命令不存在时的回退：检测 systemd 服务
        code, out, _ = conn.exec_command(
            'systemctl is-active secgate-dashboard 2>/dev/null'
        )
        if code == 0 and out.strip() == 'active':
            info['dashboard_running'] = True
            port = _detect_port_from_systemd(conn, 'secgate-dashboard')
            if port:
                info['dashboard_port'] = port

    if not info['gateway_running']:
        code, out, _ = conn.exec_command(
            'systemctl is-active secgate-gateway 2>/dev/null'
        )
        if code == 0 and out.strip() == 'active':
            info['gateway_running'] = True

    # ---- 5. curl 验证已发现的 Dashboard 端口确实是 SecGate ----
    if info['dashboard_port']:
        code, out, _ = conn.exec_command(
            f'curl -s -o /dev/null -w "%{{http_code}}" '
            f'--max-time 2 http://127.0.0.1:{info["dashboard_port"]}/services 2>/dev/null'
        )
        # SecGate Dashboard /services 返回 401（需认证）或 200
        if code != 0 or out.strip() not in ('200', '401'):
            info['dashboard_port'] = None
            info['dashboard_running'] = False

    # ---- 6. 兜底：前面步骤没发现运行状态时，直接 curl 探测常见端口 ----
    # 场景：非 root 用户 ss 看不到进程、secgate 命令不存在、systemd 未启用
    if info['installed'] and not info['dashboard_running']:
        for port in (5000, 8080, 8000):
            code, out, _ = conn.exec_command(
                f'curl -s -o /dev/null -w "%{{http_code}}" '
                f'--max-time 2 http://127.0.0.1:{port}/services 2>/dev/null'
            )
            if code == 0 and out.strip() in ('200', '401'):
                info['dashboard_running'] = True
                info['dashboard_port'] = port
                break

    if info['installed'] and not info['gateway_running']:
        for port in (5002, 5001, 8001):
            code, out, _ = conn.exec_command(
                f'curl -s -o /dev/null -w "%{{http_code}}" '
                f'--max-time 2 http://127.0.0.1:{port}/auth/verify 2>/dev/null'
            )
            # /auth/verify 返回 302（跳转登录）或 200
            if code == 0 and out.strip() in ('200', '302', '401'):
                info['gateway_running'] = True
                info['gateway_port'] = port
                break

    return info


def _extract_pid(line):
    """从 'dashboard  运行中  PID=12345' 中提取 PID"""
    import re
    m = re.search(r'PID[=:]?\s*(\d+)', line)
    return m.group(1) if m else None


def _pid_to_port(conn, pid):
    """通过 ss 从 PID 反查监听端口"""
    # 防御：确保 pid 是纯数字
    if not pid or not str(pid).isdigit():
        return None
    code, out, _ = conn.exec_command(
        f'ss -tlnp 2>/dev/null | grep "pid={pid},"'
    )
    if code == 0 and out:
        import re
        # 格式: LISTEN 0 128 0.0.0.0:5000 ...
        m = re.search(r':(\d+)\s', out)
        if m:
            return int(m.group(1))
    return None


# 允许查询的 systemd 服务名白名单
_ALLOWED_SERVICES = {'secgate-dashboard', 'secgate-gateway'}


def _detect_port_from_systemd(conn, service_name):
    """从 systemd ExecStart 中提取 -b 0.0.0.0:PORT"""
    if service_name not in _ALLOWED_SERVICES:
        return None
    code, out, _ = conn.exec_command(
        f'systemctl cat {service_name} 2>/dev/null | grep ExecStart'
    )
    if code == 0 and out:
        import re
        m = re.search(r'-b\s+[\d.]+:(\d+)', out)
        if m:
            return int(m.group(1))
    return None
