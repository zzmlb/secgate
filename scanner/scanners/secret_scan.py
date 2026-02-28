"""
敏感数据泄露检测扫描器
使用正则匹配 + 信息熵分析来检测代码中的硬编码密钥、密码、API Token 等
"""

import os
import re
import math
import logging
from .base import BaseScanner

logger = logging.getLogger(__name__)


class SecretScanner(BaseScanner):
    name = "敏感数据泄露检测"
    description = "检测代码中硬编码的密码、API 密钥、Token 等敏感信息"

    # 需要跳过的目录
    SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.venv', 'venv',
                 '.tox', '.eggs', '.mypy_cache', '.pytest_cache', 'dist', 'build'}

    # 需要跳过的文件扩展名（二进制文件等）
    SKIP_EXTENSIONS = {'.pyc', '.pyo', '.so', '.o', '.a', '.dll', '.exe', '.bin',
                       '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                       '.mp3', '.mp4', '.avi', '.mov', '.zip', '.tar', '.gz',
                       '.bz2', '.rar', '.7z', '.woff', '.woff2', '.ttf', '.eot',
                       '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.db', '.sqlite'}

    # 文件大小限制：1MB
    MAX_FILE_SIZE = 1 * 1024 * 1024

    # 敏感数据检测规则列表
    # 每条规则包含: name(规则名), pattern(正则), severity(严重等级), description(描述), remediation(修复建议)
    RULES = [
        {
            'name': 'MongoDB URI（含密码）',
            'pattern': re.compile(
                r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\'"]+',
                re.IGNORECASE
            ),
            'severity': 'CRITICAL',
            'category': '数据库凭据泄露',
            'description': '发现包含用户名和密码的 MongoDB 连接字符串',
            'remediation': '将 MongoDB URI 移至环境变量或密钥管理服务中，不要在代码中硬编码',
        },
        {
            'name': 'OpenAI API Key',
            'pattern': re.compile(r'sk-[a-zA-Z0-9]{32,}'),
            'severity': 'CRITICAL',
            'category': 'API 密钥泄露',
            'description': '发现疑似 OpenAI API 密钥（sk- 开头）',
            'remediation': '立即轮换该 API 密钥，并将其移至环境变量中',
        },
        {
            'name': 'AWS Access Key',
            'pattern': re.compile(r'AKIA[0-9A-Z]{16}'),
            'severity': 'CRITICAL',
            'category': 'API 密钥泄露',
            'description': '发现疑似 AWS Access Key ID（AKIA 开头）',
            'remediation': '立即轮换该 AWS 密钥，使用 IAM 角色或密钥管理服务替代硬编码',
        },
        {
            'name': 'AWS Secret Key',
            'pattern': re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[\'"]?([a-zA-Z0-9/+=]{40})[\'"]?'),
            'severity': 'CRITICAL',
            'category': 'API 密钥泄露',
            'description': '发现疑似 AWS Secret Access Key',
            'remediation': '立即轮换该 AWS 密钥，使用 IAM 角色或密钥管理服务替代硬编码',
        },
        {
            'name': 'GitHub Token',
            'pattern': re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}'),
            'severity': 'HIGH',
            'category': 'API 密钥泄露',
            'description': '发现疑似 GitHub Personal Access Token',
            'remediation': '立即撤销该 Token，使用 GitHub App 或环境变量管理凭据',
        },
        {
            'name': '通用密码赋值',
            'pattern': re.compile(
                r'(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)\s*[=:]\s*[\'"][^\'"]{4,}[\'"]',
                re.IGNORECASE
            ),
            'severity': 'HIGH',
            'category': '硬编码密码',
            'description': '发现硬编码的密码/密钥/Token 赋值',
            'remediation': '将敏感值移至环境变量、.env 文件（需加入 .gitignore）或密钥管理服务',
        },
        {
            'name': 'JWT / Bearer Token',
            'pattern': re.compile(r'(?:Bearer\s+)?eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
            'severity': 'HIGH',
            'category': 'Token 泄露',
            'description': '发现硬编码的 JWT Token',
            'remediation': '移除硬编码的 JWT，Token 应通过认证流程动态获取',
        },
        {
            'name': 'RSA / SSH 私钥',
            'pattern': re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
            'severity': 'CRITICAL',
            'category': '私钥泄露',
            'description': '发现硬编码的 RSA/SSH 私钥',
            'remediation': '私钥不应存储在代码仓库中，请使用密钥管理服务或加密存储',
        },
        {
            'name': '硬编码 IP 数据库连接',
            'pattern': re.compile(
                r'(?:mysql|postgresql|postgres|redis|mongo)(?:ql)?://[^@]*@(?:\d{1,3}\.){3}\d{1,3}:\d+',
                re.IGNORECASE
            ),
            'severity': 'MEDIUM',
            'category': '硬编码连接信息',
            'description': '发现包含硬编码 IP 地址的数据库连接字符串',
            'remediation': '将数据库连接信息移至环境变量或配置文件中',
        },
        {
            'name': 'Slack Webhook',
            'pattern': re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
            'severity': 'MEDIUM',
            'category': 'Webhook 泄露',
            'description': '发现 Slack Webhook URL',
            'remediation': '轮换该 Webhook URL，并将其存储在环境变量中',
        },
        {
            'name': '通用 Secret（高熵值字符串）',
            'pattern': re.compile(
                r'(?:SECRET|KEY|TOKEN|PASS)\s*[=:]\s*[\'"]([a-zA-Z0-9+/=_\-]{20,})[\'"]',
                re.IGNORECASE
            ),
            'severity': 'MEDIUM',
            'category': '疑似密钥',
            'description': '发现疑似高熵值密钥字符串',
            'remediation': '确认该值是否为敏感信息，如是，请移至安全存储',
        },
    ]

    def __init__(self):
        super().__init__()
        self._merged_rules = None

    @property
    def merged_rules(self):
        """合并外部 YAML 规则和内置规则，YAML 规则优先，按 name 去重"""
        if self._merged_rules is None:
            external = self._load_external_rules()
            if external:
                # YAML 规则优先，按 name 去重
                rules_by_name = {}
                for rule in external:
                    rules_by_name[rule['name']] = rule
                for rule in self.RULES:
                    if rule['name'] not in rules_by_name:
                        rules_by_name[rule['name']] = rule
                self._merged_rules = list(rules_by_name.values())
                logger.info(f'已加载 {len(self._merged_rules)} 条敏感数据检测规则（外部 {len(external)} + 内置 fallback）')
            else:
                self._merged_rules = list(self.RULES)
                logger.info(f'使用内置 {len(self._merged_rules)} 条规则（外部规则加载失败）')
        return self._merged_rules

    @classmethod
    def _load_external_rules(cls):
        """从 YAML 文件加载外部规则并合并"""
        try:
            from ..rules.loader import load_rules, compile_patterns
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
            yaml_path = os.path.join(rules_dir, 'secret_rules.yaml')
            raw_rules = load_rules(yaml_path)
            if not raw_rules:
                return []
            compiled = compile_patterns(raw_rules)
            # 转换为内部格式
            external_rules = []
            for r in compiled:
                external_rules.append({
                    'name': r['name'],
                    'pattern': r['compiled_pattern'],
                    'severity': r.get('severity', 'MEDIUM'),
                    'category': r.get('category', '敏感信息'),
                    'description': r.get('description', ''),
                    'remediation': r.get('remediation', ''),
                    'entropy_check': r.get('entropy_check', False),
                })
            return external_rules
        except Exception as e:
            logger.warning(f'加载外部规则失败: {e}')
            return []

    # .env 文件中的敏感变量名模式
    ENV_SENSITIVE_PATTERNS = re.compile(
        r'^(?:DB_|DATABASE_|MONGO|REDIS|MYSQL|POSTGRES|SECRET|TOKEN|API_KEY|'
        r'AWS_|PRIVATE_KEY|PASSWORD|PASSWD|AUTH|SMTP_PASS|MAIL_PASS|'
        r'ENCRYPTION_KEY|SIGNING_KEY|JWT_SECRET)',
        re.IGNORECASE
    )

    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行敏感数据泄露扫描

        扫描目标路径下的所有文本文件，使用正则匹配和熵值检测发现硬编码的密钥和敏感信息
        """
        findings = []

        if not target_path:
            self._log(log_fn, task_id, 'WARN', '敏感数据扫描需要目标路径，已跳过')
            return findings

        if not os.path.isdir(target_path):
            self._log(log_fn, task_id, 'ERROR', f'目标路径不存在: {target_path}')
            return findings

        self._log(log_fn, task_id, 'INFO', f'开始敏感数据泄露扫描，目标路径: {target_path}')

        file_count = 0
        scanned_count = 0

        for root, dirs, files in os.walk(target_path):
            # 跳过无需扫描的目录
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for fname in files:
                if self._is_cancelled(cancel_flag):
                    self._log(log_fn, task_id, 'WARN', '敏感数据扫描已被取消')
                    return findings

                filepath = os.path.join(root, fname)
                file_count += 1

                # 跳过二进制文件扩展名
                _, ext = os.path.splitext(fname)
                if ext.lower() in self.SKIP_EXTENSIONS:
                    continue

                # 跳过大文件（超过 1MB）
                try:
                    file_size = os.path.getsize(filepath)
                    if file_size > self.MAX_FILE_SIZE:
                        continue
                    if file_size == 0:
                        continue
                except OSError:
                    continue

                scanned_count += 1

                # 增量扫描：检查文件是否已修改
                should_scan, file_hash = self._should_scan_file(filepath, 'secret_scan')
                if not should_scan:
                    continue

                # 判断是否为 .env 文件
                is_env_file = fname == '.env' or fname.endswith('.env') or fname == '.env.local' or fname == '.env.production'

                file_findings = self._scan_file(filepath, is_env_file)
                # 扫描完成后更新 hash 缓存
                if file_hash:
                    try:
                        from .. import storage as _storage
                        _storage.save_file_hash(filepath, file_hash, 'secret_scan')
                    except Exception:
                        pass
                findings.extend(file_findings)

        self._log(log_fn, task_id, 'INFO',
                  f'敏感数据扫描完成，共扫描 {scanned_count}/{file_count} 个文件，发现 {len(findings)} 个问题')

        return findings

    def _scan_file(self, filepath, is_env_file=False):
        """
        扫描单个文件

        参数:
            filepath: 文件路径
            is_env_file: 是否为 .env 文件
        返回:
            该文件中发现的问题列表
        """
        findings = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, OSError):
            return findings

        # 检查文件是否为二进制（简单启发式判断）
        try:
            sample = ''.join(lines[:10])
            if '\x00' in sample:
                return findings  # 可能是二进制文件
        except Exception:
            return findings

        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # 跳过空行和纯注释行
            if not line_stripped or line_stripped.startswith('#'):
                # .env 文件的注释不跳过（注释可能包含已注释掉的真实密钥）
                if not is_env_file:
                    continue

            # 使用正则规则匹配
            for rule in self.merged_rules:
                match = rule['pattern'].search(line)
                if match:
                    # 验证：过滤掉明显是占位符或示例的值
                    matched_text = match.group(0)
                    if self._is_placeholder(matched_text):
                        continue

                    # 对标记了 entropy_check 的规则进行熵值检测
                    if rule.get('entropy_check'):
                        secret_val = match.group(1) if match.lastindex else matched_text
                        if self._shannon_entropy(secret_val) < 3.5:
                            continue  # 熵值太低，可能不是真正的密钥

                    finding = {
                        'scanner': 'secret_scan',
                        'severity': rule['severity'],
                        'category': rule['category'],
                        'title': rule['name'],
                        'description': f"{rule['description']}（第 {line_num} 行）",
                        'location': f'{filepath}:{line_num}',
                        'remediation': rule['remediation'],
                        'raw_data': {
                            'matched_rule': rule['name'],
                            'line_number': line_num,
                            'line_preview': self._redact_line(line_stripped),
                        }
                    }
                    findings.append(finding)
                    break  # 每行只报告第一个匹配的规则，避免重复

            # 针对 .env 文件的额外检测
            if is_env_file and '=' in line_stripped and not line_stripped.startswith('#'):
                key, _, value = line_stripped.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if self.ENV_SENSITIVE_PATTERNS.match(key) and value and len(value) >= 4:
                    # 检查是否已被上面的规则匹配
                    already_found = any(
                        f['location'] == f'{filepath}:{line_num}'
                        for f in findings
                    )
                    if not already_found and not self._is_placeholder(value):
                        findings.append({
                            'scanner': 'secret_scan',
                            'severity': 'HIGH',
                            'category': '.env 敏感配置',
                            'title': f'.env 文件包含敏感变量 {key}',
                            'description': f'.env 文件中的 {key} 变量包含敏感值（第 {line_num} 行）',
                            'location': f'{filepath}:{line_num}',
                            'remediation': '确保 .env 文件已加入 .gitignore，不要提交到版本控制系统',
                            'raw_data': {
                                'variable': key,
                                'line_number': line_num,
                            }
                        })

        return findings

    def _is_placeholder(self, value):
        """
        检测值是否为占位符或示例

        常见占位符模式: xxx, your_xxx, <xxx>, ${xxx}, TODO, CHANGEME 等
        """
        value_lower = value.lower()
        placeholders = [
            'xxx', 'your_', 'your-', 'example', 'changeme', 'change_me',
            'todo', 'fixme', 'placeholder', 'replace_me', 'dummy',
            'test', 'fake', 'sample', 'demo', 'default',
        ]
        for ph in placeholders:
            if ph in value_lower:
                return True

        # 检测模板变量格式
        if re.match(r'^[\$<{].*[>}]$', value.strip()):
            return True

        # 纯星号
        if set(value.strip()) <= {'*', 'x', 'X'}:
            return True

        return False

    def _shannon_entropy(self, data):
        """
        计算字符串的 Shannon 信息熵

        高熵值(>3.5)通常意味着更随机的字符串，更可能是真正的密钥
        """
        if not data:
            return 0

        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(data)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _redact_line(self, line, max_len=120):
        """
        脱敏处理：截断并遮蔽敏感值，避免在日志中暴露完整密钥

        参数:
            line: 原始行内容
            max_len: 最大显示长度
        返回:
            脱敏后的行内容
        """
        if len(line) > max_len:
            line = line[:max_len] + '...'

        # 对引号内的长字符串进行部分遮蔽
        def redact_match(m):
            quote = m.group(1)
            content = m.group(2)
            if len(content) > 8:
                return f'{quote}{content[:4]}****{content[-4:]}{quote}'
            return m.group(0)

        line = re.sub(r'([\'"])([a-zA-Z0-9+/=_\-]{8,})\1', redact_match, line)
        return line
