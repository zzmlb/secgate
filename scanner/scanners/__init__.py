"""
扫描器注册表
集中管理所有可用的扫描器实例
"""

from .sca import SCAScanner
from .secret_scan import SecretScanner
from .input_guard import InputGuardScanner
from .outconn import OutconnScanner
from .web_vuln import WebVulnScanner

# 扫描器注册表：key 为扫描类型标识，value 为扫描器实例
SCANNER_REGISTRY = {
    'sca': SCAScanner(),
    'secret_scan': SecretScanner(),
    'input_guard': InputGuardScanner(),
    'outconn': OutconnScanner(),
    'web_vuln': WebVulnScanner(),
}


def get_scanner(name):
    """
    根据名称获取扫描器实例

    参数:
        name: 扫描器标识名
    返回:
        对应的扫描器实例，不存在则返回 None
    """
    return SCANNER_REGISTRY.get(name)


def get_all_scanners():
    """
    获取所有已注册的扫描器

    返回:
        扫描器注册表字典的副本
    """
    return dict(SCANNER_REGISTRY)


# 扫描器详细描述和扫描范围配置
SCANNER_DETAILS = {
    'sca': {
        'description': '扫描项目依赖的第三方库和组件中的已知安全漏洞(CVE)，支持多语言依赖文件，基于OSV漏洞数据库进行比对',
        'scan_scope': 'static',  # 需要 target_path
        'checks': [
            '多语言依赖文件支持：Python (requirements.txt)、Node.js (package-lock.json/package.json)、Go (go.sum)、Java (pom.xml)',
            '解析包名和版本号（Python 支持 ==、>=、~= 等格式，Node.js 支持 ^、~ 等格式）',
            '使用 OSV 批量查询 API (/v1/querybatch) 高效查询漏洞，自动识别 PyPI/npm/Go/Maven 生态',
            'OSV 不可用时 fallback 到 pip-audit 本地扫描（Python 依赖）',
            '增量扫描：基于文件 hash 缓存跳过未修改的依赖文件',
        ],
        'target': '项目路径（读取依赖文件 + 调用远程 API）',
    },
    'secret_scan': {
        'description': '检测代码中硬编码的密钥、密码、API Token、数据库连接串等敏感信息，支持 YAML 外部规则热更新，防止凭证泄露',
        'scan_scope': 'static',  # 需要 target_path
        'checks': [
            '25+ 条正则规则匹配（支持 YAML 外部规则热更新）：',
            '  - 云服务密钥：AWS Key、Google API Key、Azure Storage Key、Alibaba Cloud AK、Tencent Cloud AK',
            '  - 支付/SaaS 密钥：Stripe Key、Twilio Token、SendGrid Key、Mailgun Key',
            '  - 开发平台：GitHub Token、OpenAI Key、NPM Token、PyPI Token、Heroku Key',
            '  - 通用凭据：MongoDB URI、数据库连接串、JWT Token、RSA/SSH/PEM 私钥、Docker Auth',
            'Shannon 信息熵计算，过滤低熵值（<3.5）假阳性',
            '.env 文件敏感变量专项检测（DB_*、SECRET_*、API_KEY 等）',
            '自动过滤占位符（xxx、your_、CHANGEME、TODO 等）',
            '增量扫描：基于文件 hash 缓存跳过未修改的文件',
        ],
        'target': '项目路径（遍历所有文本文件，跳过二进制和 >1MB 文件）',
    },
    'input_guard': {
        'description': '对Web接口进行SQL注入、XSS、路径穿越、SSRF等常见注入攻击的模糊测试',
        'scan_scope': 'dynamic',  # 需要 target_url
        'checks': [
            'SQL 注入：6 个载荷（OR 1=1、UNION SELECT 等），检测 9 种数据库错误特征',
            'XSS：5 个载荷（script/img/svg/event），检测反射型 XSS',
            '路径遍历：5 个载荷（../../etc/passwd 及 URL 编码变种）',
            'SSRF：4 个载荷（云元数据 169.254.169.254、内网 IP、本地服务）',
        ],
        'target': '目标 URL（自动探测 /api/search、/api/login 等 7 个端点）',
    },
    'outconn': {
        'description': '检查服务器对外暴露的端口、数据库(MongoDB/Redis/MySQL)未授权访问、服务绑定地址等安全风险',
        'scan_scope': 'system',  # 不需要特定目标
        'checks': [
            '枚举本机所有监听端口，检测 0.0.0.0 绑定（对外暴露）',
            'MongoDB (27017)：发送 isMaster 命令，测试无认证连接',
            'Redis (6379)：发送 PING/INFO，测试无密码访问',
            'MySQL (3306)：解析握手包 + 测试 root 空密码',
            'PostgreSQL (5432)：构造 StartupMessage，测试无密码登录',
            'Elasticsearch (9200)：HTTP 探测集群信息和索引列表',
            'Memcached (11211)：发送 stats 命令，测试无认证',
        ],
        'target': '本机监听端口（原始 socket 协议级探测）',
    },
    'web_vuln': {
        'description': '检测Web服务的安全响应头、SSL/TLS证书、CORS配置、敏感文件暴露、错误信息泄露等常见Web安全问题',
        'scan_scope': 'dynamic',  # 需要 target_url
        'checks': [
            'SSL/TLS 证书检测：证书过期/即将过期、自签名证书、主机名不匹配、TLSv1.0/1.1 弱协议',
            '7 项安全头检查：CSP、HSTS、X-Frame-Options、X-Content-Type-Options 等',
            'Cookie 安全检查：HttpOnly、Secure、SameSite 属性',
            '23 个敏感路径探测：.env、.git/config、phpinfo.php、wp-config.php 等',
            '错误信息泄露：发送畸形请求检测 Traceback/堆栈跟踪暴露',
            '目录列表检测：/uploads/、/static/ 等 8 个目录',
            'HTTP 危险方法检测：PUT、DELETE、TRACE 等',
            'CORS 误配置检测：任意 Origin 反射、Credentials 泄露、null Origin 信任、宽松 preflight',
        ],
        'target': '目标 URL（HTTP 请求探测）',
    },
}


def list_scanner_info():
    """
    列出所有扫描器的基本信息

    返回:
        包含每个扫描器名称、描述和扫描范围的列表
    """
    result = []
    for key, scanner in SCANNER_REGISTRY.items():
        details = SCANNER_DETAILS.get(key, {})
        result.append({
            'id': key,
            'name': scanner.name,
            'description': details.get('description', scanner.description),
            'scan_scope': details.get('scan_scope', 'unknown'),
            'checks': details.get('checks', []),
            'target': details.get('target', ''),
        })
    return result
