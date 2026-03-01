# SecGate - Linux 服务器安全网关管理平台

一站式 Linux 服务器安全管理方案，零配置开箱即用。一条命令完成部署，全部通过 Web 页面管理，无需手动编辑任何配置文件。

## 功能概览

### 1. 安全监控看板

实时展示服务器安全态势，支持 7 / 30 / 90 天数据范围切换。

- **SSH 攻击分析** — 失败登录次数统计、攻击 IP 地理位置追踪（ip-api.com）、高频攻击 IP 排行榜、成功登录记录
- **防火墙拦截** — iptables 拦截事件日志解析、拦截次数统计
- **Fail2Ban 状态** — 运行状态、活跃 jail 数量、当前封禁 IP 列表
- **服务状态监控** — 所有监听端口的进程状态、对外暴露检测、端口是否受网关保护
- **系统资源** — CPU / 内存 / 磁盘使用率实时监控、系统 uptime
- **ECharts 可视化** — 攻击趋势折线图、地理分布、端口分布饼图

### 2. 三层认证网关

保护服务器上所有 Web 服务端口，外部访问必须通过认证：

- **第一层 IP 白名单** — 白名单内的 IP 免认证直连业务端口
- **第二层 Token 认证** — 非白名单用户通过 Token 登录页验证身份
- **第三层 Cookie 会话** — Token 验证通过后颁发 7 天有效的 Cookie，期间免重复验证
- **Nginx auth_request** — 通过 Nginx 反向代理 + iptables 端口重定向实现，对业务服务零侵入

所有网关配置（Token 管理、IP 白名单、受保护端口）均在看板的「网关认证」页面操作：
- Token：创建（自动生成或自定义名称）/ 删除
- IP 白名单：添加 IP 或 CIDR 网段 / 删除
- 受保护端口：逐个添加 / 一键批量保护所有未保护端口 / 移除保护
- 未保护端口自动检测：系统自动扫描对外暴露且未受网关保护的端口，提示一键加入

### 3. 安全漏洞扫描

内置 5 个专项扫描器，通过看板「安全扫描」页面触发和管理：

| 扫描器 | 功能 | 检测范围 |
|--------|------|----------|
| SCA 依赖漏洞扫描 | 检测第三方依赖的已知漏洞 | Python / Node.js / Go / Java，对接 OSV 漏洞库 |
| 敏感信息检测 | 扫描代码和配置中的密钥泄露 | 25+ 正则规则，覆盖 AWS Key、GitHub Token、RSA 私钥、数据库连接串等 |
| 输入验证测试 | 对 API 端点进行模糊测试 | SQL 注入（6 载荷）、XSS（5 载荷）、路径穿越（5 载荷）、SSRF（4 载荷） |
| 对外连接检测 | 检测未授权的网络服务暴露 | 监听端口枚举、MongoDB / Redis / MySQL / PostgreSQL / ES / Memcached 未授权访问 |
| Web 安全检测 | 检测 Web 服务配置缺陷 | SSL/TLS 证书、7 项安全头、Cookie 属性、23 个敏感路径、HTTP 危险方法、CORS 误配置 |

扫描功能：
- 自动探测本机监听端口，智能推荐适用的扫描器
- 手动触发或设置定时扫描计划
- 扫描结果分级展示（严重 / 高 / 中 / 低）
- 支持误报标记（加入允许列表）

### 4. 安全告警通知

AlertEngine 后台引擎自动运行 8 条检测规则，每 60 秒一次检测循环：

| 规则 | 级别 | 检测频率 | 说明 |
|------|------|----------|------|
| SSH 密码登录未关闭 | warning | 5 分钟 | 检测 sshd_config 是否允许密码登录 |
| 新端口未受保护 | warning | 2 分钟 | 检测对外暴露但未加入网关的端口 |
| 新 IP SSH 登录 | info | 1 分钟 | 检测从未见过的 IP 成功 SSH 登录 |
| Fail2Ban 封禁 | info | 1 分钟 | 检测 Fail2Ban 新封禁的 IP |
| SSH 暴力破解突增 | critical | 1 分钟 | 1 小时内失败登录超过 100 次 |
| AI 服务无认证暴露 | warning | 10 分钟 | 检测 AI 服务（Chainlit 等）是否无认证对外暴露 |
| 服务异常停止 | critical | 5 分钟 | 检测已知服务进程是否异常退出 |
| 磁盘空间不足 | warning | 5 分钟 | 根分区使用率超过 90% |

告警通知按时间倒序排列，最新的在最上面。支持标记已读、忽略、一键全部已读。同一问题通过去重键避免重复告警，问题解决后自动释放（可重新触发）。

### 5. AI 安全助手（可选）

基于 Claude 的对话式安全分析助手：

- Chainlit Web UI（端口 8502），密码认证保护
- 只读权限，仅可执行 Bash 命令和读取文件，不能修改系统
- 对话式排查安全问题、分析日志、解读扫描结果
- 需要 Claude CLI 环境，未安装时不影响其他功能

## 系统要求

- Ubuntu 20.04+ / Debian 11+
- Python 3.9+
- root 权限

## 安装部署

三种方式任选其一，全部一键完成：

### 方式一：Git Clone（推荐）

```bash
git clone https://github.com/zzmlb/secgate.git /opt/secgate
cd /opt/secgate && sudo ./secgate setup
```

### 方式二：一键安装

```bash
curl -fsSL https://github.com/zzmlb/secgate/releases/latest/download/install.sh | sudo bash
```

### 方式三：pip 安装

```bash
pip install secgate
sudo secgate setup
```

### setup 自动完成的事项

`secgate setup` 一条命令自动完成全部配置，无需人工干预：

1. 检测服务器公网 IP
2. 安装系统依赖（Nginx、iptables、UFW、Fail2Ban、curl）
3. 安装 Python 依赖（Flask、psutil、requests 等）
4. 生成安全凭证（Dashboard 随机密码、网关签名密钥、Chainlit JWT 密钥）
5. 生成 Nginx 认证网关配置并启用
6. 配置 iptables 端口重定向规则
7. 配置 UFW 防火墙并放行必要端口
8. 安装 Gunicorn 生产级 WSGI 服务器
9. 生成 systemd 服务（开机自启）
10. 启动所有服务

部署完成后会输出看板地址和登录凭证。

## 使用指南

### CLI 管理命令

```bash
secgate start      # 启动所有服务
secgate stop       # 停止所有服务
secgate restart    # 重启所有服务
secgate status     # 查看运行状态
secgate creds      # 查看登录凭证
secgate version    # 查看版本号
secgate update     # 更新到最新版本（自动 git pull + 重装依赖 + 重启）
```

### 登录看板

1. 运行 `secgate creds` 获取用户名和密码
2. 浏览器访问 `http://服务器IP:5000`
3. 输入用户名 `admin` 和密码登录

### 看板页面功能

看板包含 5 个标签页，点击顶部标签切换：

**总览（Dashboard）** — 安全态势总览
- 攻击次数、封禁 IP、服务状态等核心指标卡片
- SSH 攻击趋势图（ECharts）
- 攻击来源 IP 地理位置分布
- 支持切换时间范围：7 天 / 30 天 / 90 天

**服务监控（Services）** — 服务和端口管理
- 所有监听端口列表，标注是否对外暴露、是否受网关保护
- 服务进程信息（PID、进程名、启动命令）
- 系统资源仪表盘（CPU / 内存 / 磁盘）

**网关认证（Gateway）** — 网关配置管理
- 网关运行状态（Token 数、白名单数、受保护端口数）
- Token 管理：查看已有 Token、创建新 Token、删除 Token
- IP 白名单：查看白名单列表、添加 IP/CIDR、删除
- 受保护端口：查看受保护端口列表、添加新端口、一键保护所有未保护端口、移除保护
- 未保护端口提醒：自动列出对外暴露但未受保护的端口

**安全扫描（Scanner）** — 漏洞扫描管理
- 端口探测：自动发现本机服务并推荐扫描器
- 扫描任务：触发新扫描、查看进行中/已完成的任务
- 扫描结果：按严重程度分级展示漏洞详情
- 定时计划：设置周期性自动扫描

**AI 助手（AI）** — 对话式安全分析
- 输入安全相关问题，AI 自动分析日志和系统状态
- 支持排查 SSH 攻击、分析端口暴露、解读扫描结果

### 告警通知

页面右上角的铃铛图标显示未读告警数量，点击展开通知列表：
- 按时间倒序排列，最新的在最上面
- 支持标记已读、忽略、一键全部已读
- critical 级别告警（如暴力破解突增、服务停止）需立即关注

## 使用建议

1. **部署完成后第一件事**：登录看板检查告警通知，处理所有 critical 和 warning 级别的告警
2. **添加 IP 白名单**：在「网关认证」页面添加你常用的办公网络 IP，这样访问服务不需要每次输入 Token
3. **保护所有端口**：「网关认证」页面会自动检测未保护的端口，点击「全部保护」一键加入网关
4. **运行首次扫描**：在「安全扫描」页面运行一次全量扫描，了解当前安全状态
5. **关注 SSH 安全**：如果看到「SSH 密码登录未关闭」告警，建议配置密钥登录后关闭密码认证
6. **定期检查**：建议每周登录看板查看告警和攻击趋势，每月运行一次全量扫描

## 升级

```bash
# Git Clone 方式（推荐）
cd /opt/secgate && sudo ./secgate update

# 一键安装方式（重新执行安装脚本，自动保留数据）
curl -fsSL https://github.com/zzmlb/secgate/releases/latest/download/install.sh | sudo bash

# pip 方式
pip install --upgrade secgate
```

升级时会自动备份凭证和数据文件，无需手动操作。

## 卸载

```bash
sudo bash /opt/secgate/packaging/uninstall.sh
```

卸载时会询问是否保留配置和数据文件。

## 架构

```
外部用户 → iptables 端口重定向 → Nginx (auth_request) → Gateway (:5002) 认证
                                                           ↓ 认证通过
                                                Dashboard (:5000) 安全看板
                                                Agent     (:8502) AI 助手

白名单 IP → 直连业务端口（跳过认证）
```

| 服务 | 端口 | 说明 |
|------|------|------|
| Gateway | 5002 | 认证网关服务，处理 Token 验证和 Cookie 签发 |
| Dashboard | 5000 | 安全监控看板，集成扫描器和告警引擎 |
| Agent | 8502 | AI 安全助手（Chainlit + Claude），可选 |
| Nginx | 各端口+20000 | 认证代理层，如 :5000 → :25000 |

## 目录结构

```
secgate/
├── secgate              # CLI 管理工具（start/stop/setup 等命令）
├── shared.py            # 共享模块（IP 检测、凭证管理）
├── VERSION              # 版本号
├── requirements.txt     # Python 依赖
├── gateway/             # 认证网关服务
│   ├── app.py           # Flask 认证服务 + 管理 API
│   └── templates/       # Token 登录页面
├── dashboard/           # 安全监控看板
│   ├── app.py           # Flask 看板服务 + 全部 API
│   ├── notifications.py # AlertEngine 告警引擎（8 条规则）
│   └── templates/       # 前端页面（ECharts 可视化）
├── scanner/             # 漏洞扫描模块
│   ├── __init__.py      # Flask Blueprint + REST API
│   ├── manager.py       # 扫描任务管理器
│   ├── storage.py       # SQLite 存储层
│   └── scanners/        # 5 个扫描器实现
├── agent/               # AI 安全助手
│   ├── app.py           # Chainlit 应用
│   └── CLAUDE.md        # AI 系统指令
└── packaging/           # 打包部署脚本
    ├── install.sh       # 一键安装脚本
    ├── uninstall.sh     # 卸载脚本
    ├── build.sh         # 构建 tar.gz 发布包
    └── build-pip.sh     # 构建 pip 包
```

## 许可证

MIT License
