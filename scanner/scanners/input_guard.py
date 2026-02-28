"""
输入防护检测扫描器（动态扫描）
对目标 URL 发送各类 Fuzz 载荷，检测是否存在注入漏洞
包括 SQL 注入、XSS、路径遍历、SSRF 等
"""

import time
import re
import requests
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from .base import BaseScanner


class InputGuardScanner(BaseScanner):
    name = "输入防护检测"
    description = "通过 Fuzz 测试检测 SQL 注入、XSS、路径遍历、SSRF 等输入防护问题"

    # 请求超时（秒）
    REQUEST_TIMEOUT = 5
    # 请求间隔（秒），避免打挂目标服务
    REQUEST_DELAY = 0.3
    # 用户代理
    USER_AGENT = "SecurityScanner/1.0"

    # SQL 注入测试载荷
    SQL_PAYLOADS = [
        "' OR 1=1 --",
        '"; DROP TABLE--',
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1 OR 1=1",
        "'; WAITFOR DELAY '0:0:5'--",
    ]

    # SQL 注入检测特征（响应中包含这些内容表示可能存在漏洞）
    SQL_ERROR_PATTERNS = [
        re.compile(r'SQL\s*syntax.*MySQL', re.IGNORECASE),
        re.compile(r'Warning.*mysql_', re.IGNORECASE),
        re.compile(r'PostgreSQL.*ERROR', re.IGNORECASE),
        re.compile(r'ORA-\d{5}', re.IGNORECASE),
        re.compile(r'Microsoft.*ODBC.*SQL', re.IGNORECASE),
        re.compile(r'SQLite.*error', re.IGNORECASE),
        re.compile(r'Unclosed\s*quotation', re.IGNORECASE),
        re.compile(r'near\s*".*":\s*syntax\s*error', re.IGNORECASE),
        re.compile(r'unterminated\s*quoted\s*string', re.IGNORECASE),
    ]

    # XSS 测试载荷
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
    ]

    # 路径遍历测试载荷
    PATH_TRAVERSAL_PAYLOADS = [
        '../../etc/passwd',
        '..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252fetc%252fpasswd',
    ]

    # 路径遍历成功特征
    PATH_TRAVERSAL_INDICATORS = [
        re.compile(r'root:.*:0:0:', re.IGNORECASE),
        re.compile(r'\[boot loader\]', re.IGNORECASE),
        re.compile(r'# localhost', re.IGNORECASE),
    ]

    # SSRF 测试载荷（用于检测 url 类参数）
    SSRF_PAYLOADS = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:22',
        'http://localhost:6379',
        'http://[::1]/',
    ]

    # 常见可 Fuzz 的端点路径（如果目标没有提供具体端点）
    COMMON_ENDPOINTS = [
        '/api/search',
        '/api/login',
        '/api/query',
        '/search',
        '/login',
        '/api/users',
        '/api/data',
    ]

    # 常见可 Fuzz 的参数名
    COMMON_PARAMS = [
        'q', 'query', 'search', 'keyword', 'id', 'name', 'user',
        'username', 'email', 'page', 'file', 'path', 'url', 'redirect',
        'callback', 'next', 'return', 'goto', 'target',
    ]

    # URL 相关的参数名（用于 SSRF 检测）
    URL_PARAMS = ['url', 'redirect', 'next', 'return', 'goto', 'target',
                  'callback', 'link', 'href', 'src', 'uri', 'dest']

    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行输入防护扫描

        对目标 URL 发送 Fuzz 载荷，检测注入漏洞
        """
        findings = []

        if not target_url:
            self._log(log_fn, task_id, 'WARN', '输入防护扫描需要目标 URL，已跳过')
            return findings

        self._log(log_fn, task_id, 'INFO', f'开始输入防护扫描，目标: {target_url}')

        # 确保 URL 有 scheme
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url

        # 创建 requests Session 以复用连接
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.USER_AGENT,
        })
        session.verify = False  # 跳过 SSL 验证（扫描器场景）

        # 1. 先探测目标是否可达
        try:
            resp = session.get(target_url, timeout=self.REQUEST_TIMEOUT)
            self._log(log_fn, task_id, 'INFO', f'目标可达，状态码: {resp.status_code}')
        except requests.RequestException as e:
            self._log(log_fn, task_id, 'ERROR', f'目标不可达: {str(e)}')
            return findings

        # 2. 收集可用的端点
        endpoints = self._discover_endpoints(session, target_url, task_id, cancel_flag, log_fn)
        self._log(log_fn, task_id, 'INFO', f'发现 {len(endpoints)} 个可用端点')

        # 3. SQL 注入测试
        if not self._is_cancelled(cancel_flag):
            sql_findings = self._test_sql_injection(
                session, target_url, endpoints, task_id, cancel_flag, log_fn
            )
            findings.extend(sql_findings)

        # 4. XSS 测试
        if not self._is_cancelled(cancel_flag):
            xss_findings = self._test_xss(
                session, target_url, endpoints, task_id, cancel_flag, log_fn
            )
            findings.extend(xss_findings)

        # 5. 路径遍历测试
        if not self._is_cancelled(cancel_flag):
            traversal_findings = self._test_path_traversal(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(traversal_findings)

        # 6. SSRF 测试
        if not self._is_cancelled(cancel_flag):
            ssrf_findings = self._test_ssrf(
                session, target_url, endpoints, task_id, cancel_flag, log_fn
            )
            findings.extend(ssrf_findings)

        session.close()

        self._log(log_fn, task_id, 'INFO', f'输入防护扫描完成，发现 {len(findings)} 个问题')
        return findings

    def _discover_endpoints(self, session, base_url, task_id, cancel_flag, log_fn):
        """
        探测目标上可用的端点

        尝试访问常见端点路径，收集返回非 404 的端点
        """
        active_endpoints = []

        for endpoint in self.COMMON_ENDPOINTS:
            if self._is_cancelled(cancel_flag):
                break

            url = urljoin(base_url, endpoint)
            try:
                resp = session.get(url, timeout=self.REQUEST_TIMEOUT, allow_redirects=False)
                if resp.status_code != 404:
                    active_endpoints.append(endpoint)
                time.sleep(self.REQUEST_DELAY)
            except requests.RequestException:
                continue

        return active_endpoints

    def _test_sql_injection(self, session, base_url, endpoints, task_id, cancel_flag, log_fn):
        """
        SQL 注入测试

        向每个端点的参数中注入 SQL 载荷，检查响应中是否包含数据库错误信息
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '开始 SQL 注入测试')

        # 对每个端点和参数组合进行测试
        test_targets = self._build_test_targets(base_url, endpoints)

        for url, param_name in test_targets:
            if self._is_cancelled(cancel_flag):
                break

            for payload in self.SQL_PAYLOADS:
                if self._is_cancelled(cancel_flag):
                    break

                try:
                    # GET 请求测试
                    test_url = f"{url}?{urlencode({param_name: payload})}"
                    resp = session.get(test_url, timeout=self.REQUEST_TIMEOUT)
                    time.sleep(self.REQUEST_DELAY)

                    # 检查响应中的 SQL 错误特征
                    body = resp.text
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if pattern.search(body):
                            finding = {
                                'scanner': 'input_guard',
                                'severity': 'CRITICAL',
                                'category': 'SQL 注入',
                                'title': f'疑似 SQL 注入漏洞 ({param_name})',
                                'description': (
                                    f'在端点 {url} 的参数 {param_name} 中注入载荷 "{payload}" 后，'
                                    f'响应包含数据库错误信息，疑似存在 SQL 注入漏洞'
                                ),
                                'location': url,
                                'remediation': (
                                    '使用参数化查询（Prepared Statement）替代字符串拼接SQL；'
                                    '使用ORM框架；对用户输入进行严格的白名单校验'
                                ),
                                'raw_data': {
                                    'payload': payload,
                                    'parameter': param_name,
                                    'matched_pattern': pattern.pattern,
                                    'status_code': resp.status_code,
                                }
                            }
                            findings.append(finding)
                            break  # 一个参数只报告一次

                    # POST 请求测试
                    try:
                        resp_post = session.post(
                            url,
                            data={param_name: payload},
                            timeout=self.REQUEST_TIMEOUT
                        )
                        time.sleep(self.REQUEST_DELAY)

                        body_post = resp_post.text
                        for pattern in self.SQL_ERROR_PATTERNS:
                            if pattern.search(body_post):
                                finding = {
                                    'scanner': 'input_guard',
                                    'severity': 'CRITICAL',
                                    'category': 'SQL 注入',
                                    'title': f'疑似 SQL 注入漏洞 - POST ({param_name})',
                                    'description': (
                                        f'在端点 {url} 的 POST 参数 {param_name} 中注入载荷 "{payload}" 后，'
                                        f'响应包含数据库错误信息'
                                    ),
                                    'location': url,
                                    'remediation': '使用参数化查询替代字符串拼接SQL；使用ORM框架',
                                    'raw_data': {
                                        'method': 'POST',
                                        'payload': payload,
                                        'parameter': param_name,
                                        'status_code': resp_post.status_code,
                                    }
                                }
                                findings.append(finding)
                                break
                    except requests.RequestException:
                        pass

                except requests.RequestException:
                    continue

        self._log(log_fn, task_id, 'INFO', f'SQL 注入测试完成，发现 {len(findings)} 个问题')
        return findings

    def _test_xss(self, session, base_url, endpoints, task_id, cancel_flag, log_fn):
        """
        XSS 跨站脚本测试

        检查注入的 XSS 载荷是否被原样反射在响应中
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '开始 XSS 测试')

        test_targets = self._build_test_targets(base_url, endpoints)

        for url, param_name in test_targets:
            if self._is_cancelled(cancel_flag):
                break

            for payload in self.XSS_PAYLOADS:
                if self._is_cancelled(cancel_flag):
                    break

                try:
                    test_url = f"{url}?{urlencode({param_name: payload})}"
                    resp = session.get(test_url, timeout=self.REQUEST_TIMEOUT)
                    time.sleep(self.REQUEST_DELAY)

                    # 检查载荷是否被原样反射
                    if payload in resp.text:
                        content_type = resp.headers.get('Content-Type', '')
                        # 确认是 HTML 响应（JSON 中的反射不算 XSS）
                        if 'html' in content_type.lower() or 'text/' in content_type.lower():
                            finding = {
                                'scanner': 'input_guard',
                                'severity': 'HIGH',
                                'category': 'XSS 跨站脚本',
                                'title': f'疑似反射型 XSS 漏洞 ({param_name})',
                                'description': (
                                    f'在端点 {url} 的参数 {param_name} 中注入 XSS 载荷后，'
                                    f'载荷被原样反射在 HTML 响应中，可能存在反射型 XSS 漏洞'
                                ),
                                'location': url,
                                'remediation': (
                                    '对所有用户输入进行HTML实体编码输出；'
                                    '实施 Content-Security-Policy 头；'
                                    '使用模板引擎的自动转义功能'
                                ),
                                'raw_data': {
                                    'payload': payload,
                                    'parameter': param_name,
                                    'content_type': content_type,
                                }
                            }
                            findings.append(finding)
                            break  # 一个参数只报告一次

                except requests.RequestException:
                    continue

        self._log(log_fn, task_id, 'INFO', f'XSS 测试完成，发现 {len(findings)} 个问题')
        return findings

    def _test_path_traversal(self, session, base_url, task_id, cancel_flag, log_fn):
        """
        路径遍历测试

        在常见的文件参数中注入路径遍历载荷
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '开始路径遍历测试')

        file_params = ['file', 'path', 'page', 'doc', 'document', 'template',
                       'include', 'dir', 'folder']

        for param_name in file_params:
            if self._is_cancelled(cancel_flag):
                break

            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                if self._is_cancelled(cancel_flag):
                    break

                try:
                    test_url = f"{base_url}?{urlencode({param_name: payload})}"
                    resp = session.get(test_url, timeout=self.REQUEST_TIMEOUT)
                    time.sleep(self.REQUEST_DELAY)

                    # 检查是否成功读取到系统文件
                    for indicator in self.PATH_TRAVERSAL_INDICATORS:
                        if indicator.search(resp.text):
                            finding = {
                                'scanner': 'input_guard',
                                'severity': 'CRITICAL',
                                'category': '路径遍历',
                                'title': f'路径遍历漏洞 ({param_name})',
                                'description': (
                                    f'通过参数 {param_name} 的路径遍历载荷 "{payload}" '
                                    f'成功读取到系统敏感文件'
                                ),
                                'location': base_url,
                                'remediation': (
                                    '对文件路径参数进行严格校验，使用白名单限制可访问的文件范围；'
                                    '禁止路径中出现 ".." 序列；使用 chroot 或沙箱限制文件访问'
                                ),
                                'raw_data': {
                                    'payload': payload,
                                    'parameter': param_name,
                                    'status_code': resp.status_code,
                                }
                            }
                            findings.append(finding)
                            break
                    else:
                        continue
                    break  # 一个参数发现后跳过其他载荷

                except requests.RequestException:
                    continue

        self._log(log_fn, task_id, 'INFO', f'路径遍历测试完成，发现 {len(findings)} 个问题')
        return findings

    def _test_ssrf(self, session, base_url, endpoints, task_id, cancel_flag, log_fn):
        """
        SSRF（服务器端请求伪造）测试

        检测 URL 类型的参数是否可以被利用发起内部网络请求
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '开始 SSRF 测试')

        # 对目标根路径和所有端点进行测试
        test_urls = [base_url] + [urljoin(base_url, ep) for ep in endpoints]

        for url in test_urls:
            if self._is_cancelled(cancel_flag):
                break

            for param_name in self.URL_PARAMS:
                if self._is_cancelled(cancel_flag):
                    break

                for payload in self.SSRF_PAYLOADS:
                    if self._is_cancelled(cancel_flag):
                        break

                    try:
                        test_url = f"{url}?{urlencode({param_name: payload})}"
                        resp = session.get(test_url, timeout=self.REQUEST_TIMEOUT)
                        time.sleep(self.REQUEST_DELAY)

                        # 检测是否成功访问了内部资源
                        # 检查是否返回了云元数据、内网服务信息等
                        body = resp.text.lower()
                        ssrf_indicators = [
                            'ami-id', 'instance-id', 'local-ipv4',  # AWS 元数据
                            'computemetadata',  # GCP 元数据
                            '+pong', '+ok', 'redis_version',  # Redis
                            'openssh', 'ssh-',  # SSH Banner
                        ]

                        for indicator in ssrf_indicators:
                            if indicator in body:
                                finding = {
                                    'scanner': 'input_guard',
                                    'severity': 'CRITICAL',
                                    'category': 'SSRF 服务器端请求伪造',
                                    'title': f'疑似 SSRF 漏洞 ({param_name})',
                                    'description': (
                                        f'在端点 {url} 的参数 {param_name} 中注入内部地址 "{payload}" 后，'
                                        f'响应中包含内部服务信息，疑似存在 SSRF 漏洞'
                                    ),
                                    'location': url,
                                    'remediation': (
                                        '对用户提供的 URL 进行严格验证，使用白名单限制可访问的域名和 IP 范围；'
                                        '禁止访问内网地址（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8）；'
                                        '禁止访问云元数据服务地址（169.254.169.254）'
                                    ),
                                    'raw_data': {
                                        'payload': payload,
                                        'parameter': param_name,
                                        'matched_indicator': indicator,
                                        'status_code': resp.status_code,
                                    }
                                }
                                findings.append(finding)
                                break
                        else:
                            continue
                        break  # 一个参数发现后跳过

                    except requests.RequestException:
                        continue

        self._log(log_fn, task_id, 'INFO', f'SSRF 测试完成，发现 {len(findings)} 个问题')
        return findings

    def _build_test_targets(self, base_url, endpoints):
        """
        构建测试目标列表（URL + 参数名的组合）

        返回:
            [(url, param_name), ...] 列表
        """
        targets = []

        # 基础 URL + 所有常见参数
        all_urls = [base_url] + [urljoin(base_url, ep) for ep in endpoints]

        # 为每个 URL 选择部分参数测试（避免组合爆炸）
        input_params = ['q', 'query', 'search', 'id', 'name', 'user', 'username', 'email']

        for url in all_urls:
            for param in input_params:
                targets.append((url, param))

        return targets
