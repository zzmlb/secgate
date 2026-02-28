"""
外连服务安全扫描器
检测本机监听的数据库/缓存等服务是否存在安全配置问题
包括未授权访问、对外暴露等风险
使用纯 socket 实现，不依赖第三方客户端库
"""

import socket
import struct
import psutil
from .base import BaseScanner


class OutconnScanner(BaseScanner):
    name = "外连服务安全扫描"
    description = "检测本机数据库、缓存等服务的安全配置（未授权访问、对外暴露等）"

    # socket 超时（秒）
    SOCKET_TIMEOUT = 3

    # 已知服务端口及检测配置
    KNOWN_SERVICES = {
        27017: {
            'name': 'MongoDB',
            'check_fn': '_check_mongodb',
        },
        6379: {
            'name': 'Redis',
            'check_fn': '_check_redis',
        },
        3306: {
            'name': 'MySQL',
            'check_fn': '_check_mysql',
        },
        9200: {
            'name': 'Elasticsearch',
            'check_fn': '_check_elasticsearch',
        },
        5432: {
            'name': 'PostgreSQL',
            'check_fn': '_check_postgresql',
        },
        11211: {
            'name': 'Memcached',
            'check_fn': '_check_memcached',
        },
    }

    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行外连服务安全扫描

        扫描流程:
        1. 使用 psutil 枚举本机所有监听的 TCP 端口
        2. 检查是否有已知服务运行在非安全配置下
        3. 对每个发现的服务进行安全检测
        """
        findings = []

        self._log(log_fn, task_id, 'INFO', '开始外连服务安全扫描')

        # 1. 获取所有监听的 TCP 连接
        listening_ports = self._get_listening_ports(task_id, log_fn)

        if not listening_ports:
            self._log(log_fn, task_id, 'INFO', '未发现监听中的 TCP 端口')
            return findings

        self._log(log_fn, task_id, 'INFO',
                  f'发现 {len(listening_ports)} 个监听端口')

        # 2. 逐个检查已知服务端口
        for port_info in listening_ports:
            if self._is_cancelled(cancel_flag):
                self._log(log_fn, task_id, 'WARN', '外连服务扫描已被取消')
                return findings

            port = port_info['port']
            bind_addr = port_info['address']
            pid = port_info.get('pid')
            proc_name = port_info.get('process', '未知进程')

            # 检查是否绑定在 0.0.0.0（对外暴露）
            is_exposed = bind_addr in ('0.0.0.0', '::', '*', '')

            if is_exposed:
                finding = {
                    'scanner': 'outconn',
                    'severity': 'MEDIUM',
                    'category': '服务对外暴露',
                    'title': f'端口 {port} ({proc_name}) 绑定在 0.0.0.0',
                    'description': (
                        f'进程 {proc_name} (PID: {pid}) 在端口 {port} 上监听所有网络接口 ({bind_addr})，'
                        f'这意味着该服务对外网可能可达'
                    ),
                    'location': f'{bind_addr}:{port}',
                    'remediation': (
                        '如果该服务只需内部访问，请将监听地址改为 127.0.0.1；'
                        '如果必须对外暴露，确保配置了认证和防火墙规则'
                    ),
                    'raw_data': {
                        'port': port,
                        'bind_address': bind_addr,
                        'pid': pid,
                        'process': proc_name,
                    }
                }
                findings.append(finding)

            # 3. 对已知服务进行深入安全检测
            if port in self.KNOWN_SERVICES:
                service_config = self.KNOWN_SERVICES[port]
                service_name = service_config['name']
                check_fn_name = service_config['check_fn']

                self._log(log_fn, task_id, 'INFO',
                          f'检测 {service_name} 服务 (端口 {port})')

                check_fn = getattr(self, check_fn_name, None)
                if check_fn:
                    try:
                        service_findings = check_fn(port, bind_addr, is_exposed)
                        findings.extend(service_findings)
                    except Exception as e:
                        self._log(log_fn, task_id, 'WARN',
                                  f'{service_name} 检测异常: {str(e)}')

        self._log(log_fn, task_id, 'INFO',
                  f'外连服务扫描完成，发现 {len(findings)} 个问题')
        return findings

    def _get_listening_ports(self, task_id, log_fn):
        """
        使用 psutil 获取所有监听中的 TCP 端口

        返回:
            端口信息字典列表 [{port, address, pid, process}, ...]
        """
        ports = []
        try:
            connections = psutil.net_connections(kind='tcp')
            for conn in connections:
                if conn.status == 'LISTEN':
                    addr = conn.laddr
                    pid = conn.pid

                    proc_name = '未知'
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    ports.append({
                        'port': addr.port,
                        'address': addr.ip,
                        'pid': pid,
                        'process': proc_name,
                    })
        except (psutil.AccessDenied, psutil.Error) as e:
            self._log(log_fn, task_id, 'WARN', f'获取监听端口信息失败: {str(e)}')

        return ports

    def _check_mongodb(self, port, bind_addr, is_exposed):
        """
        检测 MongoDB 是否存在未授权访问

        使用 MongoDB Wire Protocol 发送 isMaster 命令
        如果无需认证即可获得响应，说明存在未授权访问风险
        """
        findings = []
        host = '127.0.0.1'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 构建 MongoDB Wire Protocol 的 isMaster 查询消息
            # OP_QUERY (opcode=2004) 发送 isMaster 命令
            query_doc = self._bson_encode({
                'isMaster': 1,
            })
            full_collection = b'admin.$cmd\x00'
            # 消息头: length(4) + requestID(4) + responseTo(4) + opCode(4)
            # OP_QUERY: flags(4) + fullCollectionName + numberToSkip(4) + numberToReturn(4) + query
            body = (
                struct.pack('<i', 0) +  # flags
                full_collection +
                struct.pack('<i', 0) +  # numberToSkip
                struct.pack('<i', 1) +  # numberToReturn
                query_doc
            )
            header = struct.pack('<iiii',
                                 16 + len(body),  # messageLength
                                 1,  # requestID
                                 0,  # responseTo
                                 2004  # opCode = OP_QUERY
                                 )
            sock.sendall(header + body)

            # 接收响应
            resp_data = sock.recv(4096)
            sock.close()

            if resp_data and len(resp_data) > 16:
                # 收到有效响应说明可以无认证连接
                severity = 'CRITICAL' if is_exposed else 'HIGH'
                findings.append({
                    'scanner': 'outconn',
                    'severity': severity,
                    'category': '未授权访问',
                    'title': f'MongoDB (端口 {port}) 未启用认证',
                    'description': (
                        f'MongoDB 服务在端口 {port} 上可无需认证直接连接。'
                        f'攻击者可直接读写数据库中的数据。'
                        + (' 且该服务绑定在 0.0.0.0，对外网可达，风险极高！' if is_exposed else '')
                    ),
                    'location': f'{bind_addr}:{port}',
                    'remediation': (
                        '1. 启用 MongoDB 认证：在配置文件中设置 security.authorization: enabled\n'
                        '2. 创建管理员用户并设置强密码\n'
                        '3. 将监听地址改为 127.0.0.1\n'
                        '4. 使用防火墙限制访问来源'
                    ),
                })

        except socket.timeout:
            pass  # 超时不一定是问题
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _bson_encode(self, doc):
        """
        简单的 BSON 编码（只支持字符串和整数，用于构造 isMaster 查询）
        """
        result = b''
        for key, value in doc.items():
            key_bytes = key.encode('utf-8') + b'\x00'
            if isinstance(value, int):
                result += b'\x10' + key_bytes + struct.pack('<i', value)
            elif isinstance(value, str):
                val_bytes = value.encode('utf-8') + b'\x00'
                result += b'\x02' + key_bytes + struct.pack('<i', len(val_bytes)) + val_bytes
        result += b'\x00'
        return struct.pack('<i', len(result) + 4) + result

    def _check_redis(self, port, bind_addr, is_exposed):
        """
        检测 Redis 是否存在未授权访问

        尝试发送 PING 命令，如果返回 +PONG 说明无需认证
        """
        findings = []
        host = '127.0.0.1'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 发送 Redis RESP 协议的 PING 命令
            sock.sendall(b'*1\r\n$4\r\nPING\r\n')

            resp = sock.recv(1024)
            sock.close()

            resp_str = resp.decode('utf-8', errors='ignore').strip()

            if resp_str == '+PONG':
                # 可以无认证 PING，进一步检测是否可以执行 INFO 命令
                severity = 'CRITICAL' if is_exposed else 'HIGH'
                description = (
                    f'Redis 服务在端口 {port} 上可无需认证直接连接。'
                    f'攻击者可读写所有缓存数据，甚至利用 CONFIG SET 实现远程代码执行。'
                )
                if is_exposed:
                    description += ' 且该服务绑定在 0.0.0.0，对外网可达，风险极高！'

                findings.append({
                    'scanner': 'outconn',
                    'severity': severity,
                    'category': '未授权访问',
                    'title': f'Redis (端口 {port}) 未启用认证',
                    'description': description,
                    'location': f'{bind_addr}:{port}',
                    'remediation': (
                        '1. 在 redis.conf 中设置 requirepass 指定密码\n'
                        '2. 将 bind 地址改为 127.0.0.1\n'
                        '3. 禁用危险命令：rename-command CONFIG "", rename-command FLUSHALL ""\n'
                        '4. 使用防火墙限制访问来源'
                    ),
                })

                # 额外检测：是否可以获取 INFO 信息
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(self.SOCKET_TIMEOUT)
                    sock2.connect((host, port))
                    sock2.sendall(b'*1\r\n$4\r\nINFO\r\n')
                    info_resp = sock2.recv(4096)
                    sock2.close()
                    info_str = info_resp.decode('utf-8', errors='ignore')

                    if 'redis_version' in info_str:
                        findings.append({
                            'scanner': 'outconn',
                            'severity': 'MEDIUM',
                            'category': '信息泄露',
                            'title': f'Redis (端口 {port}) 信息泄露',
                            'description': '未认证用户可获取 Redis 服务的版本、配置、内存等详细信息',
                            'location': f'{bind_addr}:{port}',
                            'remediation': '启用 Redis 认证后此问题将自动修复',
                        })
                except Exception:
                    pass

            elif '-NOAUTH' in resp_str or '-ERR' in resp_str:
                # Redis 要求认证，这是正常的安全配置
                pass

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _check_mysql(self, port, bind_addr, is_exposed):
        """
        检测 MySQL 是否存在安全配置问题

        尝试连接 MySQL 端口，解析握手包获取版本和认证信息
        """
        findings = []
        host = '127.0.0.1'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # MySQL 连接后会主动发送握手包
            data = sock.recv(4096)
            sock.close()

            if data and len(data) > 4:
                # 解析 MySQL 握手包
                # 第5个字节是协议版本号
                protocol_version = data[4]

                if protocol_version == 10 or protocol_version == 9:
                    # 提取服务器版本号（以 \x00 结尾的字符串）
                    version_end = data.index(b'\x00', 5)
                    server_version = data[5:version_end].decode('utf-8', errors='ignore')

                    # 检查是否是旧版本 MySQL
                    version_parts = server_version.split('.')
                    try:
                        major = int(version_parts[0])
                        minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                    except (ValueError, IndexError):
                        major, minor = 0, 0

                    if major < 8 and not server_version.startswith('5.7'):
                        findings.append({
                            'scanner': 'outconn',
                            'severity': 'MEDIUM',
                            'category': '版本过旧',
                            'title': f'MySQL (端口 {port}) 版本过旧: {server_version}',
                            'description': f'MySQL 版本 {server_version} 可能存在已知安全漏洞',
                            'location': f'{bind_addr}:{port}',
                            'remediation': '升级到 MySQL 8.0 或更高版本',
                        })

                    if is_exposed:
                        findings.append({
                            'scanner': 'outconn',
                            'severity': 'HIGH',
                            'category': '服务对外暴露',
                            'title': f'MySQL (端口 {port}) 对外暴露',
                            'description': (
                                f'MySQL {server_version} 绑定在 {bind_addr}，对外网可达。'
                                f'攻击者可尝试暴力破解数据库密码'
                            ),
                            'location': f'{bind_addr}:{port}',
                            'remediation': (
                                '1. 将 bind-address 改为 127.0.0.1\n'
                                '2. 使用防火墙限制访问来源\n'
                                '3. 确保所有数据库用户使用强密码\n'
                                '4. 删除匿名用户和测试数据库'
                            ),
                        })

                    # 尝试无密码连接（root 用户）
                    anon_findings = self._try_mysql_anonymous(host, port, bind_addr)
                    findings.extend(anon_findings)

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _try_mysql_anonymous(self, host, port, bind_addr):
        """
        尝试用空密码连接 MySQL

        构造一个最简的 MySQL 客户端认证包尝试以 root 无密码登录
        """
        findings = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 接收握手包
            handshake = sock.recv(4096)
            if not handshake or len(handshake) < 5:
                sock.close()
                return findings

            # 构造简单的认证响应包（用户 root，空密码）
            # 客户端能力标志
            client_flags = 0x00000001 | 0x00000200 | 0x00008000  # LONG_PASSWORD | PROTOCOL_41 | SECURE_CONNECTION
            max_packet_size = 16777216
            charset = 33  # utf8

            username = b'root\x00'
            auth_response = b'\x00'  # 空密码

            payload = (
                struct.pack('<IIB', client_flags, max_packet_size, charset) +
                b'\x00' * 23 +  # 保留字节
                username +
                auth_response
            )

            # 包头: 长度(3字节) + 序号(1字节)
            packet = struct.pack('<I', len(payload))[:3] + b'\x01' + payload
            sock.sendall(packet)

            # 接收响应
            resp = sock.recv(4096)
            sock.close()

            if resp and len(resp) > 4:
                # 第5个字节为 0x00 表示 OK 包（登录成功）
                if resp[4] == 0x00:
                    findings.append({
                        'scanner': 'outconn',
                        'severity': 'CRITICAL',
                        'category': '未授权访问',
                        'title': f'MySQL (端口 {port}) root 用户空密码',
                        'description': 'MySQL root 用户无需密码即可登录，存在严重安全风险',
                        'location': f'{bind_addr}:{port}',
                        'remediation': (
                            '立即为 root 用户设置强密码：\n'
                            "ALTER USER 'root'@'localhost' IDENTIFIED BY '强密码';\n"
                            '删除匿名用户：DELETE FROM mysql.user WHERE user="";\n'
                            'FLUSH PRIVILEGES;'
                        ),
                    })

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _check_elasticsearch(self, port, bind_addr, is_exposed):
        """
        检测 Elasticsearch 是否存在未授权访问

        尝试通过 HTTP GET 请求获取集群信息
        """
        findings = []
        host = '127.0.0.1'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 发送 HTTP GET 请求
            http_request = (
                f'GET / HTTP/1.1\r\n'
                f'Host: {host}:{port}\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            )
            sock.sendall(http_request.encode())

            # 接收响应
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()

            resp_str = response.decode('utf-8', errors='ignore')

            # 检查是否返回了 Elasticsearch 集群信息
            if 'cluster_name' in resp_str or 'elasticsearch' in resp_str.lower():
                severity = 'CRITICAL' if is_exposed else 'HIGH'

                findings.append({
                    'scanner': 'outconn',
                    'severity': severity,
                    'category': '未授权访问',
                    'title': f'Elasticsearch (端口 {port}) 未启用认证',
                    'description': (
                        f'Elasticsearch 服务在端口 {port} 上可无需认证直接访问。'
                        f'攻击者可读取、修改、删除索引数据。'
                        + (' 且对外网可达！' if is_exposed else '')
                    ),
                    'location': f'{bind_addr}:{port}',
                    'remediation': (
                        '1. 启用 Elasticsearch Security（X-Pack Security）\n'
                        '2. 设置 network.host: 127.0.0.1 或配置防火墙\n'
                        '3. 使用 HTTPS 加密通信\n'
                        '4. 配置基于角色的访问控制（RBAC）'
                    ),
                })

                # 尝试访问索引列表
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(self.SOCKET_TIMEOUT)
                    sock2.connect((host, port))
                    cat_request = (
                        f'GET /_cat/indices HTTP/1.1\r\n'
                        f'Host: {host}:{port}\r\n'
                        f'Connection: close\r\n'
                        f'\r\n'
                    )
                    sock2.sendall(cat_request.encode())
                    cat_resp = b''
                    while True:
                        try:
                            chunk = sock2.recv(4096)
                            if not chunk:
                                break
                            cat_resp += chunk
                        except socket.timeout:
                            break
                    sock2.close()
                    cat_str = cat_resp.decode('utf-8', errors='ignore')

                    if '200' in cat_str.split('\r\n')[0]:
                        findings.append({
                            'scanner': 'outconn',
                            'severity': 'HIGH',
                            'category': '信息泄露',
                            'title': f'Elasticsearch (端口 {port}) 索引列表可访问',
                            'description': '未认证用户可获取所有索引列表信息',
                            'location': f'{bind_addr}:{port}/_cat/indices',
                            'remediation': '启用 Elasticsearch 认证后此问题将自动修复',
                        })
                except Exception:
                    pass

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _check_postgresql(self, port, bind_addr, is_exposed):
        """
        检测 PostgreSQL 安全配置

        尝试发送 StartupMessage 检测是否可以无密码连接
        """
        findings = []
        host = '127.0.0.1'

        if is_exposed:
            findings.append({
                'scanner': 'outconn',
                'severity': 'HIGH',
                'category': '服务对外暴露',
                'title': f'PostgreSQL (端口 {port}) 对外暴露',
                'description': (
                    f'PostgreSQL 绑定在 {bind_addr}，对外网可达。'
                    f'攻击者可尝试暴力破解数据库密码'
                ),
                'location': f'{bind_addr}:{port}',
                'remediation': (
                    '1. 修改 postgresql.conf 中的 listen_addresses 为 127.0.0.1\n'
                    '2. 检查 pg_hba.conf 确保认证方式不是 trust\n'
                    '3. 使用防火墙限制访问来源'
                ),
            })

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 构造 PostgreSQL StartupMessage（尝试 postgres 用户）
            user = b'user\x00postgres\x00'
            database = b'database\x00postgres\x00'
            params = user + database + b'\x00'

            # StartupMessage: Length(4) + ProtocolVersion(4) + params
            protocol_version = struct.pack('>HH', 3, 0)  # 3.0
            msg_length = 4 + len(protocol_version) + len(params)
            message = struct.pack('>I', msg_length) + protocol_version + params

            sock.sendall(message)
            resp = sock.recv(4096)
            sock.close()

            if resp:
                msg_type = chr(resp[0])
                if msg_type == 'R':
                    # Authentication request
                    auth_type = struct.unpack('>I', resp[5:9])[0] if len(resp) >= 9 else -1
                    if auth_type == 0:
                        # AuthenticationOk - 无需密码即可登录
                        findings.append({
                            'scanner': 'outconn',
                            'severity': 'CRITICAL',
                            'category': '未授权访问',
                            'title': f'PostgreSQL (端口 {port}) 允许无密码登录',
                            'description': (
                                'PostgreSQL 允许 postgres 用户无需密码登录，'
                                '可能 pg_hba.conf 中配置了 trust 认证方式'
                            ),
                            'location': f'{bind_addr}:{port}',
                            'remediation': (
                                '修改 pg_hba.conf，将认证方式从 trust 改为 md5 或 scram-sha-256；'
                                '为所有数据库用户设置强密码'
                            ),
                        })

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings

    def _check_memcached(self, port, bind_addr, is_exposed):
        """
        检测 Memcached 是否存在未授权访问

        发送 stats 命令检查是否可以无认证访问
        """
        findings = []
        host = '127.0.0.1'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            sock.connect((host, port))

            # 发送 stats 命令
            sock.sendall(b'stats\r\n')

            resp = sock.recv(4096)
            sock.close()

            resp_str = resp.decode('utf-8', errors='ignore')

            if 'STAT' in resp_str:
                severity = 'CRITICAL' if is_exposed else 'HIGH'
                findings.append({
                    'scanner': 'outconn',
                    'severity': severity,
                    'category': '未授权访问',
                    'title': f'Memcached (端口 {port}) 未启用认证',
                    'description': (
                        f'Memcached 在端口 {port} 上可无需认证直接访问，'
                        f'攻击者可读取缓存数据，还可能被利用进行 DDoS 反射放大攻击。'
                        + (' 且对外暴露！' if is_exposed else '')
                    ),
                    'location': f'{bind_addr}:{port}',
                    'remediation': (
                        '1. 启用 Memcached SASL 认证\n'
                        '2. 绑定到 127.0.0.1：-l 127.0.0.1\n'
                        '3. 使用防火墙限制访问来源\n'
                        '4. 如果不需要 UDP 协议，禁用它：-U 0'
                    ),
                })

        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return findings
