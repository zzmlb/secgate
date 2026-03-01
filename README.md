# SecGate - Linux 服务器安全网关管理平台

一站式 Linux 服务器安全管理方案，零配置开箱即用。一条命令完成部署，全部通过 Web 页面管理，无需手动编辑任何配置文件。

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

部署完成后终端会输出看板地址和登录凭证，浏览器访问即可使用。

## CLI 管理命令

```bash
secgate start      # 启动所有服务
secgate stop       # 停止所有服务
secgate restart    # 重启所有服务
secgate status     # 查看运行状态
secgate creds      # 查看登录凭证
secgate version    # 查看版本号
secgate update     # 更新到最新版本（自动 git pull + 重装依赖 + 重启）
```

## 功能详情（按页面标签页）

登录看板后，顶部有 5 个标签页，以下逐一介绍。

页面右上角的**通知铃铛**始终可见，显示未读告警数量，点击展开通知列表（按时间倒序，最新的在最上面），支持标记已读、忽略、一键全部已读。

---

### 标签页一：安全看板

安全态势总览页面，包含 5 个子标签：

#### 综合概览

- **5 个核心指标卡片** — SSH 攻击总数、防火墙拦截数、今日威胁总数、攻击 IP 总数、系统运行时间
- **SSH 活跃连接** — 当前正在连接的 SSH 会话列表
- **攻击来源国家分布** — SSH 攻击和防火墙拦截的地理来源饼图（ECharts）
- **时间范围筛选** — 支持切换近 1 天 / 3 天 / 7 天 / 15 天 / 30 天

#### SSH 暴力破解

- **SSH 攻击趋势图** — 按天/时/分三个维度切换的折线图
- **24 小时攻击分布** — 一天中各时段的攻击热度
- **攻击来源 IP TOP 10** — 攻击次数最多的 IP 及其地理位置
- **被尝试用户名 TOP 10** — 被暴力破解的用户名排行及占比

#### 防火墙拦截

- **防火墙拦截趋势图** — 按天/时/分三个维度切换的折线图
- **被扫描端口 TOP 15** — 被外部扫描最多的端口分布
- **网络扫描来源 IP TOP 10** — 端口扫描攻击的来源 IP 排行
- **综合攻击对比** — SSH 攻击 vs 网络扫描的趋势对比图

#### 系统状态

- **安全防护总览** — 三栏展示 SSH 配置状态、防火墙状态、Fail2Ban 状态，每栏包含运行状态和安全建议
- **系统资源** — CPU / 内存 / 磁盘使用率实时监控
- **监听端口列表** — 所有端口的绑定地址、进程名、PID、对外暴露状态

#### 定时任务

- **任务统计** — 总数、用户任务数、系统任务数
- **定时任务列表** — 列出所有 cron 任务，支持按用户/系统筛选，显示调度规则、命令和来源

---

### 标签页二：服务管理

服务器上所有运行服务的全景视图：

- **统计概览** — 监听端口总数、业务服务数、网关端口数、对外暴露数、仅内部数
- **业务服务区** — 展示所有业务进程，每个服务卡片显示端口、进程名、PID、启动命令、是否对外暴露、是否受网关保护
- **网关认证层** — 展示所有认证代理端口（端口号+20000），说明 iptables 重定向和 Nginx auth_request 的工作流程
- **基础设施** — 展示 Nginx、数据库等基础组件的运行状态

---

### 标签页三：网关认证

所有网关配置都在这个页面完成，无需编辑任何文件：

#### 网关状态

- 有效 Token 数、白名单 IP 数、受保护端口数、受保护端口列表

#### Token 管理

- 查看所有 Token（名称、创建时间、脱敏显示）
- 创建新 Token（自定义名称，自动生成 64 位安全 Token）
- 删除不再使用的 Token

#### IP 白名单

- 查看当前白名单列表
- 添加 IP 地址或 CIDR 网段（白名单 IP 免认证直连所有业务端口）
- 删除白名单条目

#### 端口保护管理

- **已保护端口列表** — 查看所有受网关保护的端口及其 Nginx 代理端口
- **未保护端口检测** — 自动扫描对外暴露但未受保护的端口，列出服务名和进程信息
- **一键添加** — 逐个添加端口保护
- **批量保护** — 一键将所有未保护端口全部加入网关保护
- **移除保护** — 取消某个端口的网关保护

#### 使用说明

- 页面底部内置说明，解释白名单 IP 直连和 Token 认证的工作流程

---

### 标签页四：安全扫描

内置 5 个专项扫描器，全部通过页面操作：

#### 端口服务识别 & 扫描

- 自动探测本机所有监听端口，识别服务类型
- 根据服务类型智能推荐适用的扫描器
- 点击即可触发对应扫描

#### 5 个扫描器

| 扫描器 | 功能 | 检测范围 |
|--------|------|----------|
| SCA 依赖漏洞扫描 | 检测第三方依赖的已知漏洞 | Python / Node.js / Go / Java，对接 OSV 漏洞库 |
| 敏感信息检测 | 扫描代码和配置中的密钥泄露 | 25+ 正则规则：AWS Key、GitHub Token、RSA 私钥、数据库连接串等 |
| 输入验证测试 | 对 API 端点进行模糊测试 | SQL 注入、XSS、路径穿越、SSRF |
| 对外连接检测 | 检测未授权的网络服务暴露 | 监听端口枚举、MongoDB / Redis / MySQL / PostgreSQL / ES / Memcached 未授权访问 |
| Web 安全检测 | 检测 Web 服务配置缺陷 | SSL/TLS 证书、安全头、Cookie 属性、敏感路径、HTTP 方法、CORS |

#### 扫描进度

- 实时显示扫描任务状态（等待中 / 进行中 / 已完成 / 失败）
- 查看扫描日志

#### 定时扫描

- 设置周期性自动扫描计划

#### 扫描结果

- 按严重程度分级展示（严重 / 高 / 中 / 低）
- 查看漏洞详情和修复建议
- 支持误报标记（加入允许列表）

---

### 标签页五：AI 安全

AI 服务安全管理和对话式安全助手，包含 4 个子标签：

#### AI 服务

- **统计卡片** — AI 服务数量、SDK/框架数量、API Key 数量、安全风险数
- **运行中的 AI 服务** — 自动发现服务器上运行的 AI 服务（Chainlit、Gradio、Streamlit 等），展示端口、认证状态、是否对外暴露
- **代码中的 AI SDK 引用** — 扫描项目文件中引用的 AI SDK（OpenAI、Anthropic、LangChain 等），展示引用语句和文件位置

#### API Key

- **检测到的 API Key** — 自动扫描环境变量和配置文件中的 AI API Key，脱敏展示
- 显示提供商、类型、文件位置、权限范围、风险等级

#### 风险评估

- **风险统计** — 高危 / 中危 / 低危数量
- **风险详情列表** — 逐条展示 AI 相关安全风险，支持按等级筛选
- 覆盖：无认证暴露、API Key 泄露、SDK 版本漏洞等

#### 助手设置

- 在 Dashboard 页面直接配置 Anthropic API Key，保存后 AI 助手自动生效，无需重启服务
- 支持测试连接验证 Key 是否有效
- 也可通过 AI 助手对话框直接粘贴 Key 完成配置

#### AI 对话助手

通过看板 AI 安全页面的入口，或直接访问 `http://服务器IP:8502`，进入对话式安全助手：

- 用自然语言提问，AI 自动执行命令并分析结果
- 支持：安全状态分析、日志排查、网关配置解读、系统资源监控、安全加固建议
- 只读权限，不会修改系统任何配置
- 双层认证保护（网关 + 密码登录，与看板共用账号）
- 使用示例："分析最近的 SSH 攻击情况"、"哪些端口没有受到网关保护？"、"检查 Nginx 配置"

需要 Claude Code CLI + Anthropic API Key，未配置时不影响其他功能。

---

### 告警通知（8 条自动检测规则）

AlertEngine 后台引擎自动运行，无需配置：

| 规则 | 级别 | 频率 | 说明 |
|------|------|------|------|
| SSH 密码登录未关闭 | warning | 5 分钟 | 检测 sshd_config 是否允许密码登录 |
| 新端口未受保护 | warning | 2 分钟 | 对外暴露但未加入网关保护的端口 |
| 新 IP SSH 登录 | info | 1 分钟 | 从未见过的 IP 成功 SSH 登录 |
| Fail2Ban 封禁 | info | 1 分钟 | Fail2Ban 新封禁的 IP |
| SSH 暴力破解突增 | critical | 1 分钟 | 1 小时内失败登录超过 100 次 |
| AI 服务无认证暴露 | warning | 10 分钟 | AI 服务无认证对外暴露 |
| 服务异常停止 | critical | 5 分钟 | 已知服务进程异常退出 |
| 磁盘空间不足 | warning | 5 分钟 | 根分区使用率超过 90% |

同一问题不会重复告警，问题解决后自动释放（可重新触发）。30 天前的已处理通知自动清理。

## 使用建议

1. **部署完成后第一件事**：登录看板检查告警通知，处理所有 critical 和 warning 级别的告警
2. **添加 IP 白名单**：在「网关认证」页面添加你常用的办公网络 IP，白名单 IP 免认证直连所有服务
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
