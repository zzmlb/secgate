"""
Web 漏洞扫描器（动态扫描）
检测目标 Web 应用的常见安全问题：
- HTTP 安全头缺失
- Cookie 安全属性
- 敏感文件暴露
- 错误信息泄露
- 目录列表
- 不安全的 HTTP 方法
"""

import re
import time
import requests
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urljoin
from .base import BaseScanner


class WebVulnScanner(BaseScanner):
    name = "Web 漏洞扫描"
    description = "检测 Web 应用的安全头、Cookie 配置、敏感文件暴露、信息泄露等常见安全问题"

    # 请求超时
    REQUEST_TIMEOUT = 5
    # 请求间隔
    REQUEST_DELAY = 0.3
    # 用户代理
    USER_AGENT = "SecurityScanner/1.0"

    # 必须检查的安全头列表
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'description': '防止页面被嵌入 iframe（点击劫持防护）',
            'severity': 'MEDIUM',
            'valid_values': ['DENY', 'SAMEORIGIN'],
            'remediation': "添加响应头: X-Frame-Options: DENY 或 X-Frame-Options: SAMEORIGIN",
        },
        'X-Content-Type-Options': {
            'description': '防止浏览器 MIME 类型嗅探',
            'severity': 'LOW',
            'valid_values': ['nosniff'],
            'remediation': "添加响应头: X-Content-Type-Options: nosniff",
        },
        'Strict-Transport-Security': {
            'description': '强制 HTTPS 连接（HSTS）',
            'severity': 'MEDIUM',
            'valid_values': None,  # 只要存在即可
            'remediation': "添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        'Content-Security-Policy': {
            'description': '内容安全策略，防止 XSS 和数据注入攻击',
            'severity': 'MEDIUM',
            'valid_values': None,
            'remediation': (
                "添加响应头: Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'"
            ),
        },
        'X-XSS-Protection': {
            'description': '浏览器内置 XSS 过滤器（虽已过时但仍建议设置）',
            'severity': 'LOW',
            'valid_values': None,
            'remediation': "添加响应头: X-XSS-Protection: 1; mode=block",
        },
        'Referrer-Policy': {
            'description': '控制 Referer 头的发送策略',
            'severity': 'LOW',
            'valid_values': None,
            'remediation': "添加响应头: Referrer-Policy: strict-origin-when-cross-origin",
        },
        'Permissions-Policy': {
            'description': '控制浏览器功能的访问权限（取代 Feature-Policy）',
            'severity': 'LOW',
            'valid_values': None,
            'remediation': "添加响应头: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        },
    }

    # 敏感文件路径列表
    SENSITIVE_PATHS = [
        {'path': '/.env', 'description': '环境变量配置文件', 'severity': 'CRITICAL'},
        {'path': '/.git/config', 'description': 'Git 仓库配置文件', 'severity': 'CRITICAL'},
        {'path': '/.git/HEAD', 'description': 'Git HEAD 文件', 'severity': 'CRITICAL'},
        {'path': '/.svn/entries', 'description': 'SVN 版本控制文件', 'severity': 'HIGH'},
        {'path': '/debug', 'description': '调试页面', 'severity': 'HIGH'},
        {'path': '/admin', 'description': '管理后台', 'severity': 'MEDIUM'},
        {'path': '/swagger.json', 'description': 'Swagger API 文档', 'severity': 'MEDIUM'},
        {'path': '/swagger-ui.html', 'description': 'Swagger UI', 'severity': 'MEDIUM'},
        {'path': '/api-docs', 'description': 'API 文档', 'severity': 'MEDIUM'},
        {'path': '/phpinfo.php', 'description': 'PHP 信息页面', 'severity': 'HIGH'},
        {'path': '/server-status', 'description': 'Apache Server Status', 'severity': 'MEDIUM'},
        {'path': '/nginx_status', 'description': 'Nginx Status', 'severity': 'MEDIUM'},
        {'path': '/.htaccess', 'description': 'Apache 配置文件', 'severity': 'MEDIUM'},
        {'path': '/.htpasswd', 'description': 'Apache 密码文件', 'severity': 'CRITICAL'},
        {'path': '/wp-config.php', 'description': 'WordPress 配置文件', 'severity': 'CRITICAL'},
        {'path': '/config.php', 'description': 'PHP 配置文件', 'severity': 'HIGH'},
        {'path': '/backup.sql', 'description': '数据库备份文件', 'severity': 'CRITICAL'},
        {'path': '/dump.sql', 'description': '数据库导出文件', 'severity': 'CRITICAL'},
        {'path': '/robots.txt', 'description': '搜索引擎爬虫配置', 'severity': 'INFO'},
        {'path': '/sitemap.xml', 'description': '站点地图', 'severity': 'INFO'},
        {'path': '/crossdomain.xml', 'description': 'Flash 跨域策略', 'severity': 'LOW'},
        {'path': '/.DS_Store', 'description': 'macOS 目录元数据', 'severity': 'LOW'},
        {'path': '/WEB-INF/web.xml', 'description': 'Java Web 应用配置', 'severity': 'HIGH'},
    ]

    # 目录列表检测路径
    DIRECTORY_PATHS = [
        '/images/', '/uploads/', '/static/', '/assets/',
        '/files/', '/backup/', '/tmp/', '/logs/',
    ]

    # 目录列表特征
    DIRECTORY_LISTING_PATTERNS = [
        re.compile(r'Index\s+of\s+/', re.IGNORECASE),
        re.compile(r'<title>Directory listing', re.IGNORECASE),
        re.compile(r'Parent Directory', re.IGNORECASE),
        re.compile(r'Directory Listing For', re.IGNORECASE),
    ]

    # 不安全的 HTTP 方法
    UNSAFE_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']

    # 错误信息泄露特征
    ERROR_PATTERNS = [
        re.compile(r'Traceback\s*\(most\s+recent\s+call\s+last\)', re.IGNORECASE),
        re.compile(r'File\s+".*",\s+line\s+\d+', re.IGNORECASE),
        re.compile(r'<b>Fatal\s+error</b>', re.IGNORECASE),
        re.compile(r'Stack\s*Trace:', re.IGNORECASE),
        re.compile(r'java\.lang\.\w+Exception', re.IGNORECASE),
        re.compile(r'at\s+\w+\.\w+\.\w+\(.*\.java:\d+\)', re.IGNORECASE),
        re.compile(r'Microsoft\.AspNetCore', re.IGNORECASE),
        re.compile(r'System\.Exception', re.IGNORECASE),
        re.compile(r'DEBUG\s*=\s*True', re.IGNORECASE),
        re.compile(r'DJANGO_SETTINGS_MODULE', re.IGNORECASE),
        re.compile(r'Laravel.*Exception', re.IGNORECASE),
    ]

    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行 Web 漏洞扫描
        """
        findings = []

        if not target_url:
            self._log(log_fn, task_id, 'WARN', 'Web 漏洞扫描需要目标 URL，已跳过')
            return findings

        # 确保 URL 有 scheme
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url

        self._log(log_fn, task_id, 'INFO', f'开始 Web 漏洞扫描，目标: {target_url}')

        # 创建 requests Session
        session = requests.Session()
        session.headers.update({'User-Agent': self.USER_AGENT})
        session.verify = False

        # 1. 检测目标是否可达并获取基准响应
        try:
            base_resp = session.get(target_url, timeout=self.REQUEST_TIMEOUT)
            self._log(log_fn, task_id, 'INFO', f'目标可达，状态码: {base_resp.status_code}')
        except requests.RequestException as e:
            self._log(log_fn, task_id, 'ERROR', f'目标不可达: {str(e)}')
            return findings

        # 1.5 SSL/TLS 证书检测（在可达性检查后、安全头检查前）
        if not self._is_cancelled(cancel_flag):
            ssl_findings = self._check_ssl_tls(target_url, task_id, cancel_flag, log_fn)
            findings.extend(ssl_findings)

        # 2. HTTP 安全头检查
        if not self._is_cancelled(cancel_flag):
            header_findings = self._check_security_headers(base_resp, target_url, task_id, log_fn)
            findings.extend(header_findings)

        # 3. Cookie 安全检查
        if not self._is_cancelled(cancel_flag):
            cookie_findings = self._check_cookies(base_resp, target_url, task_id, log_fn)
            findings.extend(cookie_findings)

        # 4. 敏感文件探测
        if not self._is_cancelled(cancel_flag):
            sensitive_findings = self._check_sensitive_files(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(sensitive_findings)

        # 5. 错误信息泄露检测
        if not self._is_cancelled(cancel_flag):
            error_findings = self._check_error_disclosure(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(error_findings)

        # 6. 目录列表检测
        if not self._is_cancelled(cancel_flag):
            dir_findings = self._check_directory_listing(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(dir_findings)

        # 7. HTTP 方法检测
        if not self._is_cancelled(cancel_flag):
            method_findings = self._check_http_methods(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(method_findings)

        # 8. CORS 误配置检测
        if not self._is_cancelled(cancel_flag):
            cors_findings = self._check_cors(
                session, target_url, task_id, cancel_flag, log_fn
            )
            findings.extend(cors_findings)

        session.close()

        self._log(log_fn, task_id, 'INFO', f'Web 漏洞扫描完成，发现 {len(findings)} 个问题')
        return findings

    def _check_security_headers(self, response, target_url, task_id, log_fn):
        """
        检查 HTTP 安全响应头

        遍历必须存在的安全头，检查是否缺失或值不正确
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检查 HTTP 安全头')

        for header_name, config in self.SECURITY_HEADERS.items():
            header_value = response.headers.get(header_name)

            if header_value is None:
                # 安全头缺失
                findings.append({
                    'scanner': 'web_vuln',
                    'severity': config['severity'],
                    'category': 'HTTP 安全头缺失',
                    'title': f'缺少安全头: {header_name}',
                    'description': f'{config["description"]}。该安全头未在响应中设置。',
                    'location': target_url,
                    'remediation': config['remediation'],
                })
            elif config['valid_values']:
                # 检查值是否有效
                if header_value.upper().split(',')[0].strip() not in [v.upper() for v in config['valid_values']]:
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'LOW',
                        'category': 'HTTP 安全头配置不当',
                        'title': f'安全头 {header_name} 值不推荐: {header_value}',
                        'description': (
                            f'{header_name} 的当前值为 "{header_value}"，'
                            f'推荐值为: {", ".join(config["valid_values"])}'
                        ),
                        'location': target_url,
                        'remediation': config['remediation'],
                    })

        # 检查 Server 头是否暴露过多信息
        server_header = response.headers.get('Server')
        if server_header and ('/' in server_header):
            findings.append({
                'scanner': 'web_vuln',
                'severity': 'LOW',
                'category': '信息泄露',
                'title': f'Server 头暴露版本信息: {server_header}',
                'description': f'Server 头包含详细的服务器版本信息: {server_header}，可能帮助攻击者针对性利用',
                'location': target_url,
                'remediation': '配置 Web 服务器隐藏版本信息，如 Nginx: server_tokens off;',
            })

        # 检查 X-Powered-By 头
        powered_by = response.headers.get('X-Powered-By')
        if powered_by:
            findings.append({
                'scanner': 'web_vuln',
                'severity': 'LOW',
                'category': '信息泄露',
                'title': f'X-Powered-By 暴露技术栈: {powered_by}',
                'description': f'X-Powered-By 头暴露了后端技术栈: {powered_by}',
                'location': target_url,
                'remediation': '移除 X-Powered-By 响应头',
            })

        self._log(log_fn, task_id, 'INFO', f'安全头检查完成，发现 {len(findings)} 个问题')
        return findings

    def _check_cookies(self, response, target_url, task_id, log_fn):
        """
        检查 Cookie 安全属性

        检测 Set-Cookie 头中的 HttpOnly、Secure、SameSite 属性
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检查 Cookie 安全属性')

        set_cookie_headers = response.headers.get('Set-Cookie')
        if not set_cookie_headers:
            # 尝试从 raw headers 获取多个 Set-Cookie
            raw_headers = response.raw.headers if hasattr(response.raw, 'headers') else {}
            cookies_list = raw_headers.getlist('Set-Cookie') if hasattr(raw_headers, 'getlist') else []
            if not cookies_list:
                return findings
        else:
            cookies_list = [set_cookie_headers]

        for cookie_str in cookies_list:
            cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else '未知'
            cookie_lower = cookie_str.lower()

            # 检查 HttpOnly
            if 'httponly' not in cookie_lower:
                findings.append({
                    'scanner': 'web_vuln',
                    'severity': 'MEDIUM',
                    'category': 'Cookie 安全',
                    'title': f'Cookie "{cookie_name}" 缺少 HttpOnly 属性',
                    'description': (
                        f'Cookie "{cookie_name}" 未设置 HttpOnly 属性，'
                        f'JavaScript 可以读取该 Cookie，增加 XSS 攻击窃取 Cookie 的风险'
                    ),
                    'location': target_url,
                    'remediation': '在设置 Cookie 时添加 HttpOnly 标记',
                })

            # 检查 Secure（仅对 HTTPS 站点有意义）
            if 'secure' not in cookie_lower and target_url.startswith('https'):
                findings.append({
                    'scanner': 'web_vuln',
                    'severity': 'MEDIUM',
                    'category': 'Cookie 安全',
                    'title': f'Cookie "{cookie_name}" 缺少 Secure 属性',
                    'description': (
                        f'Cookie "{cookie_name}" 未设置 Secure 属性，'
                        f'可能在 HTTP 请求中被传输，有中间人攻击风险'
                    ),
                    'location': target_url,
                    'remediation': '在设置 Cookie 时添加 Secure 标记',
                })

            # 检查 SameSite
            if 'samesite' not in cookie_lower:
                findings.append({
                    'scanner': 'web_vuln',
                    'severity': 'LOW',
                    'category': 'Cookie 安全',
                    'title': f'Cookie "{cookie_name}" 缺少 SameSite 属性',
                    'description': (
                        f'Cookie "{cookie_name}" 未设置 SameSite 属性，'
                        f'可能导致 CSRF（跨站请求伪造）攻击'
                    ),
                    'location': target_url,
                    'remediation': '在设置 Cookie 时添加 SameSite=Lax 或 SameSite=Strict',
                })

        self._log(log_fn, task_id, 'INFO', f'Cookie 检查完成，发现 {len(findings)} 个问题')
        return findings

    def _check_sensitive_files(self, session, target_url, task_id, cancel_flag, log_fn):
        """
        检测敏感文件是否可公开访问

        探测常见的敏感路径（.env, .git, 备份文件等）
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '开始敏感文件探测')

        for item in self.SENSITIVE_PATHS:
            if self._is_cancelled(cancel_flag):
                break

            path = item['path']
            url = urljoin(target_url, path)

            try:
                resp = session.get(
                    url,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=False
                )
                time.sleep(self.REQUEST_DELAY)

                # 2xx 响应且内容非空，说明文件可能存在
                if 200 <= resp.status_code < 300 and len(resp.content) > 0:
                    # 额外验证：排除通用的 404 页面伪装为 200
                    content_type = resp.headers.get('Content-Type', '')
                    content = resp.text[:500].lower()

                    # 如果是 HTML 且包含常见 404 关键字，跳过
                    if 'html' in content_type:
                        if any(kw in content for kw in ['not found', '404', 'page not found']):
                            continue

                    # 对特定文件做内容验证
                    if path == '/.env':
                        if '=' not in resp.text[:200]:
                            continue
                    elif path == '/.git/config':
                        if '[core]' not in resp.text:
                            continue
                    elif path == '/.git/HEAD':
                        if 'ref:' not in resp.text and len(resp.text.strip()) != 40:
                            continue

                    severity = item['severity']
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': severity,
                        'category': '敏感文件暴露',
                        'title': f'敏感文件可公开访问: {path}',
                        'description': (
                            f'{item["description"]}可通过 URL 公开访问。'
                            f'状态码: {resp.status_code}，'
                            f'内容长度: {len(resp.content)} 字节'
                        ),
                        'location': url,
                        'remediation': (
                            f'在 Web 服务器配置中禁止访问 {path} 路径；'
                            f'如果使用 Nginx，添加: location {path} {{ deny all; return 404; }}'
                        ),
                        'raw_data': {
                            'status_code': resp.status_code,
                            'content_length': len(resp.content),
                            'content_type': content_type,
                        }
                    })

            except requests.RequestException:
                continue

        self._log(log_fn, task_id, 'INFO', f'敏感文件探测完成，发现 {len(findings)} 个问题')
        return findings

    def _check_error_disclosure(self, session, target_url, task_id, cancel_flag, log_fn):
        """
        检测错误信息泄露

        发送畸形请求触发服务器错误，检查是否返回了详细的堆栈跟踪等信息
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检测错误信息泄露')

        # 畸形请求载荷
        error_triggers = [
            # 不存在的路径
            '/this_path_does_not_exist_' + 'a' * 50,
            # 非法字符
            '/%00%ff%fe',
            # 超长路径
            '/' + 'A' * 5000,
            # 触发类型错误的参数
            '/api?id[]=1&id[]=2',
            # 特殊的错误触发路径
            '/error',
            '/debug/error',
        ]

        for trigger in error_triggers:
            if self._is_cancelled(cancel_flag):
                break

            url = urljoin(target_url, trigger)

            try:
                resp = session.get(url, timeout=self.REQUEST_TIMEOUT)
                time.sleep(self.REQUEST_DELAY)

                body = resp.text

                for pattern in self.ERROR_PATTERNS:
                    if pattern.search(body):
                        findings.append({
                            'scanner': 'web_vuln',
                            'severity': 'HIGH',
                            'category': '错误信息泄露',
                            'title': '服务器错误信息包含敏感堆栈跟踪',
                            'description': (
                                f'访问 {trigger} 时，服务器返回了包含堆栈跟踪或调试信息的错误页面。'
                                f'攻击者可利用这些信息了解后端技术细节和文件结构'
                            ),
                            'location': url,
                            'remediation': (
                                '1. 在生产环境关闭 DEBUG 模式\n'
                                '2. 配置统一的错误处理，返回通用错误页面\n'
                                '3. 确保异常信息只写入日志，不返回给客户端'
                            ),
                            'raw_data': {
                                'trigger': trigger,
                                'status_code': resp.status_code,
                                'matched_pattern': pattern.pattern,
                            }
                        })
                        break  # 每个触发器只报告一次

            except requests.RequestException:
                continue

        self._log(log_fn, task_id, 'INFO', f'错误信息泄露检测完成，发现 {len(findings)} 个问题')
        return findings

    def _check_directory_listing(self, session, target_url, task_id, cancel_flag, log_fn):
        """
        检测目录列表是否启用

        检查常见目录是否返回目录列表页面
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检测目录列表')

        for dir_path in self.DIRECTORY_PATHS:
            if self._is_cancelled(cancel_flag):
                break

            url = urljoin(target_url, dir_path)

            try:
                resp = session.get(url, timeout=self.REQUEST_TIMEOUT)
                time.sleep(self.REQUEST_DELAY)

                if resp.status_code == 200:
                    body = resp.text
                    for pattern in self.DIRECTORY_LISTING_PATTERNS:
                        if pattern.search(body):
                            findings.append({
                                'scanner': 'web_vuln',
                                'severity': 'MEDIUM',
                                'category': '目录列表',
                                'title': f'目录列表已启用: {dir_path}',
                                'description': (
                                    f'路径 {dir_path} 返回了目录列表页面，'
                                    f'攻击者可浏览目录中的所有文件，可能发现敏感文件'
                                ),
                                'location': url,
                                'remediation': (
                                    '禁用目录列表：\n'
                                    '- Nginx: autoindex off;\n'
                                    '- Apache: Options -Indexes'
                                ),
                            })
                            break

            except requests.RequestException:
                continue

        self._log(log_fn, task_id, 'INFO', f'目录列表检测完成，发现 {len(findings)} 个问题')
        return findings

    def _check_http_methods(self, session, target_url, task_id, cancel_flag, log_fn):
        """
        检测不安全的 HTTP 方法

        使用 OPTIONS 请求和直接发送不安全方法来检测
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检测不安全的 HTTP 方法')

        # 1. 先发 OPTIONS 请求查看 Allow 头
        try:
            resp = session.options(target_url, timeout=self.REQUEST_TIMEOUT)
            time.sleep(self.REQUEST_DELAY)

            allow_header = resp.headers.get('Allow', '')
            if allow_header:
                allowed_methods = [m.strip().upper() for m in allow_header.split(',')]
                for method in self.UNSAFE_METHODS:
                    if method in allowed_methods:
                        severity = 'HIGH' if method == 'TRACE' else 'MEDIUM'
                        findings.append({
                            'scanner': 'web_vuln',
                            'severity': severity,
                            'category': '不安全的 HTTP 方法',
                            'title': f'允许不安全的 HTTP 方法: {method}',
                            'description': (
                                f'服务器允许 {method} 方法。'
                                + (' TRACE 方法可被利用进行 Cross-Site Tracing (XST) 攻击。' if method == 'TRACE' else '')
                                + (' PUT/DELETE 方法可能允许攻击者修改或删除服务器资源。' if method in ('PUT', 'DELETE') else '')
                            ),
                            'location': target_url,
                            'remediation': (
                                f'在 Web 服务器配置中禁用 {method} 方法：\n'
                                f'- Nginx: if ($request_method ~* "^({method})") {{ return 405; }}\n'
                                f'- Apache: <LimitExcept GET POST> Deny from all </LimitExcept>'
                            ),
                        })
        except requests.RequestException:
            pass

        # 2. 直接测试 TRACE 方法（最危险）
        if not self._is_cancelled(cancel_flag):
            try:
                resp = session.request('TRACE', target_url, timeout=self.REQUEST_TIMEOUT)
                time.sleep(self.REQUEST_DELAY)

                if resp.status_code == 200 and 'TRACE' in resp.text.upper():
                    # 确认 TRACE 未被上面的 OPTIONS 检测到
                    already_found = any(
                        'TRACE' in f.get('title', '') for f in findings
                    )
                    if not already_found:
                        findings.append({
                            'scanner': 'web_vuln',
                            'severity': 'HIGH',
                            'category': '不安全的 HTTP 方法',
                            'title': '允许 TRACE HTTP 方法',
                            'description': (
                                '服务器响应了 TRACE 请求并回显了请求内容，'
                                '攻击者可利用此进行 Cross-Site Tracing (XST) 攻击，窃取 Cookie 和认证信息'
                            ),
                            'location': target_url,
                            'remediation': '在 Web 服务器配置中禁用 TRACE 方法',
                        })
            except requests.RequestException:
                pass

        self._log(log_fn, task_id, 'INFO', f'HTTP 方法检测完成，发现 {len(findings)} 个问题')
        return findings

    def _check_cors(self, session, target_url, task_id, cancel_flag, log_fn):
        """
        检测 CORS 误配置

        检测逻辑:
        1. 发送带 Origin: https://evil.com 的请求
        2. 检查 Access-Control-Allow-Origin 是否反射了任意来源
        3. 检查是否允许 Access-Control-Allow-Credentials: true
        4. 测试 null origin 是否被信任
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '检测 CORS 配置')

        # 测试 1: 使用恶意 Origin
        test_origins = [
            ('https://evil.com', '任意外部域名'),
            ('null', 'null origin'),
        ]

        for origin, origin_desc in test_origins:
            if self._is_cancelled(cancel_flag):
                break

            try:
                headers = {'Origin': origin}
                resp = session.get(
                    target_url,
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT
                )
                time.sleep(self.REQUEST_DELAY)

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                if not acao:
                    continue

                # 检查是否反射了我们的 Origin
                origin_reflected = (acao == origin or acao == '*')
                credentials_allowed = (acac == 'true')

                if origin_reflected and credentials_allowed:
                    # 最严重: 反射 Origin + 允许 Credentials
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'HIGH',
                        'category': 'CORS 误配置',
                        'title': f'CORS 配置允许{origin_desc}携带凭据访问',
                        'description': (
                            f'服务器对来源 "{origin}" 的请求返回了 '
                            f'Access-Control-Allow-Origin: {acao} 和 '
                            f'Access-Control-Allow-Credentials: true。'
                            f'攻击者可以从任意网站发起带凭据的跨域请求，窃取用户数据。'
                        ),
                        'location': target_url,
                        'remediation': (
                            '1. 不要将 Access-Control-Allow-Origin 设为 * 或反射任意 Origin\n'
                            '2. 配置明确的白名单域名\n'
                            '3. 当允许 Credentials 时，必须指定确切的 Origin'
                        ),
                        'raw_data': {
                            'test_origin': origin,
                            'acao': acao,
                            'acac': acac,
                        }
                    })
                elif origin_reflected:
                    # 中等: 反射 Origin 但不允许 Credentials
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'MEDIUM',
                        'category': 'CORS 误配置',
                        'title': f'CORS 配置反射{origin_desc}',
                        'description': (
                            f'服务器对来源 "{origin}" 的请求返回了 '
                            f'Access-Control-Allow-Origin: {acao}。'
                            f'虽然未允许携带凭据，但仍可能被用于信息泄露。'
                        ),
                        'location': target_url,
                        'remediation': (
                            '配置明确的白名单域名，避免使用 * 或反射任意 Origin'
                        ),
                        'raw_data': {
                            'test_origin': origin,
                            'acao': acao,
                            'acac': acac,
                        }
                    })
            except requests.RequestException:
                continue

        # 测试 2: 检查 preflight 请求是否过于宽松
        if not self._is_cancelled(cancel_flag):
            try:
                preflight_headers = {
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'DELETE',
                    'Access-Control-Request-Headers': 'X-Custom-Header',
                }
                resp = session.options(
                    target_url,
                    headers=preflight_headers,
                    timeout=self.REQUEST_TIMEOUT
                )
                time.sleep(self.REQUEST_DELAY)

                acam = resp.headers.get('Access-Control-Allow-Methods', '')
                if acam and 'DELETE' in acam.upper():
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    if acao in ('https://evil.com', '*'):
                        findings.append({
                            'scanner': 'web_vuln',
                            'severity': 'MEDIUM',
                            'category': 'CORS 误配置',
                            'title': 'CORS 预检请求允许危险方法',
                            'description': (
                                f'CORS 预检响应允许来自任意来源的 DELETE 方法。'
                                f'Access-Control-Allow-Methods: {acam}'
                            ),
                            'location': target_url,
                            'remediation': '限制 Access-Control-Allow-Methods 仅包含必要的 HTTP 方法',
                        })
            except requests.RequestException:
                pass

        self._log(log_fn, task_id, 'INFO', f'CORS 检测完成，发现 {len(findings)} 个问题')
        return findings

    def _check_ssl_tls(self, target_url, task_id, cancel_flag, log_fn):
        """
        检测 SSL/TLS 证书安全问题

        使用 Python 内置 ssl + socket 模块
        仅在 target_url 为 HTTPS 或端口 443 时执行
        """
        findings = []

        # 解析主机名和端口
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port
        scheme = parsed.scheme

        if not port:
            port = 443 if scheme == 'https' else 80

        # 仅对 HTTPS 或 443 端口执行
        if scheme != 'https' and port != 443:
            return findings

        self._log(log_fn, task_id, 'INFO', f'检测 SSL/TLS 证书安全，目标: {hostname}:{port}')

        # 1. 获取证书信息
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # getpeercert with CERT_NONE returns empty dict, need binary
                    cert_bin = ssock.getpeercert(binary_form=True)

            # 用验证模式再获取一次证书详情
            try:
                context2 = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock2:
                    with context2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                        cert = ssock2.getpeercert()
            except ssl.SSLCertVerificationError as e:
                err_msg = str(e)
                if 'self-signed' in err_msg.lower() or 'self signed' in err_msg.lower():
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'HIGH',
                        'category': 'SSL/TLS 证书问题',
                        'title': '使用自签名证书',
                        'description': '服务器使用自签名 SSL 证书，浏览器将显示安全警告，用户易受中间人攻击',
                        'location': f'{hostname}:{port}',
                        'remediation': '使用受信任的 CA 签发的证书（如 Let\'s Encrypt 免费证书）',
                    })
                elif 'expired' in err_msg.lower():
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'CRITICAL',
                        'category': 'SSL/TLS 证书问题',
                        'title': 'SSL 证书已过期',
                        'description': f'服务器 SSL 证书已过期: {err_msg}',
                        'location': f'{hostname}:{port}',
                        'remediation': '立即更新 SSL 证书',
                    })
                elif 'hostname mismatch' in err_msg.lower() or 'doesn\'t match' in err_msg.lower():
                    findings.append({
                        'scanner': 'web_vuln',
                        'severity': 'HIGH',
                        'category': 'SSL/TLS 证书问题',
                        'title': 'SSL 证书主机名不匹配',
                        'description': f'证书中的主机名与实际访问的主机名不匹配: {err_msg}',
                        'location': f'{hostname}:{port}',
                        'remediation': '确保 SSL 证书包含正确的域名（CN 或 SAN）',
                    })
                # 自签名时 cert 可能为空，跳过后续检测
                cert = None
            except ssl.SSLError:
                cert = None
            except Exception:
                cert = None

            if cert:
                # 2. 检查证书过期
                not_after_str = cert.get('notAfter', '')
                if not_after_str:
                    try:
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        now = datetime.utcnow()

                        if not_after < now:
                            findings.append({
                                'scanner': 'web_vuln',
                                'severity': 'CRITICAL',
                                'category': 'SSL/TLS 证书问题',
                                'title': 'SSL 证书已过期',
                                'description': f'证书过期时间: {not_after_str}，已过期',
                                'location': f'{hostname}:{port}',
                                'remediation': '立即更新 SSL 证书',
                            })
                        elif not_after < now + timedelta(days=30):
                            days_left = (not_after - now).days
                            findings.append({
                                'scanner': 'web_vuln',
                                'severity': 'MEDIUM',
                                'category': 'SSL/TLS 证书问题',
                                'title': f'SSL 证书即将过期（剩余 {days_left} 天）',
                                'description': f'证书过期时间: {not_after_str}，将在 {days_left} 天后过期',
                                'location': f'{hostname}:{port}',
                                'remediation': '尽快更新 SSL 证书，建议配置自动续期（如 certbot）',
                            })
                    except ValueError:
                        pass

                # 3. 检查自签名（issuer == subject）
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                subject = dict(x[0] for x in cert.get('subject', ()))
                if issuer and subject and issuer == subject:
                    already_found = any('自签名' in f.get('title', '') for f in findings)
                    if not already_found:
                        findings.append({
                            'scanner': 'web_vuln',
                            'severity': 'HIGH',
                            'category': 'SSL/TLS 证书问题',
                            'title': '使用自签名证书',
                            'description': f'证书的颁发者和主体相同（{issuer.get("commonName", "未知")}），属于自签名证书',
                            'location': f'{hostname}:{port}',
                            'remediation': '使用受信任的 CA 签发的证书（如 Let\'s Encrypt 免费证书）',
                        })

        except socket.timeout:
            self._log(log_fn, task_id, 'WARN', f'SSL/TLS 连接超时: {hostname}:{port}')
        except ConnectionRefusedError:
            self._log(log_fn, task_id, 'WARN', f'SSL/TLS 连接被拒绝: {hostname}:{port}')
        except Exception as e:
            self._log(log_fn, task_id, 'WARN', f'SSL/TLS 检测异常: {str(e)}')

        # 4. TLS 版本检测（尝试连接 TLSv1.0/1.1）
        if not self._is_cancelled(cancel_flag):
            for tls_version_name, tls_protocol in [('TLSv1.0', ssl.PROTOCOL_TLS), ('TLSv1.1', ssl.PROTOCOL_TLS)]:
                if self._is_cancelled(cancel_flag):
                    break
                try:
                    ctx = ssl.SSLContext(tls_protocol)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    if tls_version_name == 'TLSv1.0':
                        ctx.maximum_version = ssl.TLSVersion.TLSv1
                        ctx.minimum_version = ssl.TLSVersion.TLSv1
                    elif tls_version_name == 'TLSv1.1':
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_1

                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                            # 连接成功意味着服务器支持该版本
                            findings.append({
                                'scanner': 'web_vuln',
                                'severity': 'MEDIUM',
                                'category': 'SSL/TLS 配置问题',
                                'title': f'服务器支持不安全的 {tls_version_name}',
                                'description': f'服务器仍然支持已弃用的 {tls_version_name} 协议，存在已知安全漏洞',
                                'location': f'{hostname}:{port}',
                                'remediation': f'禁用 {tls_version_name}，仅允许 TLSv1.2 和 TLSv1.3',
                            })
                except (ssl.SSLError, OSError, ValueError):
                    pass  # 连接失败意味着不支持该版本（好事）

        self._log(log_fn, task_id, 'INFO', f'SSL/TLS 检测完成，发现 {len(findings)} 个问题')
        return findings
