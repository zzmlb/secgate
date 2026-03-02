# SecGate - Linux Server Security Gateway

**中文** | [English](README_EN.md)

> **One command to deploy, zero config to protect.** The only open-source tool that provides gateway authentication + attack monitoring + vulnerability scanning + AI assistant in ~120MB memory.

一条命令部署，零配置即用。唯一在 120MB 内存内提供网关认证 + 攻击监控 + 漏洞扫描 + AI 助手的开源一体化安全工具。

```bash
curl -fsSL https://github.com/zzmlb/secgate/releases/latest/download/install.sh | sudo bash
```

## Why SecGate / 为什么选择 SecGate

**填补了 Fail2Ban（太简单）和 Wazuh（太重）之间的空白。**

| | Fail2Ban | CrowdSec | **SecGate** | 1Panel/宝塔 | Wazuh |
|---|---------|----------|-------------|------------|-------|
| 内存占用 | <50 MB | ~100 MB | **~120 MB** | 500 MB-2 GB | 4 GB+ |
| 网关认证 | - | - | **任意 TCP 端口** | - | - |
| Web 看板 | - | 云端 Console | **本地全功能** | 有 | 有 |
| 漏洞扫描 | - | - | **内置 5 个** | - / 付费 | 有 |
| 攻击态势评分 | - | 有 | **四维度评分** | - | 有 |
| AI 安全助手 | - | - | **内置** | - | - |
| 告警引擎 | - | 有 | **8 条自动规则** | - | 有 |
| 部署方式 | apt install | 需装 Bouncer | **1 条命令全自动** | 一键脚本 | 多组件调优 |
| 适合 1 核 1G | Yes | 勉强 | **Yes** | No | No |
| 开源 / 价格 | MIT / 免费 | MIT / 核心免费 | **MIT / 完全免费** | GPLv3 / 专业版付费 | Apache / 免费 |

### Core Strengths / 核心优势

| 优势 | 说明 |
|------|------|
| **网关认证（独有能力）** | iptables 重定向 + Nginx auth_request，给**任意 TCP 端口**加认证层，后端服务零代码修改。调研 18 个竞品（7 个面板 + 7 个安全工具 + 4 个云方案）**无一具备** |
| **极致轻量** | 安装包 170 KB，运行内存 ~120 MB，1 核 1G VPS 流畅运行 |
| **一键全自动** | 1 条命令完成 Nginx / UFW / Fail2Ban / iptables / systemd 等 10 步配置 |
| **攻击态势评分** | SSH 暴力破解 + 端口扫描 + Web 异常请求 + 防御效果，四维度对数加权 0-100 评分，一眼判断安全状况 |
| **AI 安全模块** | 15+ AI 提供商密钥检测、14 种 AI 服务自动发现、对话式安全排查助手，开源工具中独有 |
| **纯 IP 可用** | 不需要域名，Cloudflare / Pangolin 等方案都要域名，SecGate 纯 IP 直接保护 |
| **攻击面最小** | 5000 行 Python + 4000 行前端，远小于运维面板（宝塔/CyberPanel 多次高危 RCE 和勒索软件利用） |

### Best For / 适用场景

- **个人开发者 VPS** — 不懂安全配置，装上就有基本防护
- **多服务部署** — 数据库 / API / 管理后台，统一网关认证保护所有端口
- **AI 应用部署** — Gradio / Streamlit / Chainlit 默认无认证，一键加保护
- **临时环境快速加固** — 比赛 / 演示 / POC，几分钟装好立刻有防护

### Recommended Stack / 推荐搭配

| 方案 | 说明 |
|------|------|
| **SecGate 单独** | 服务器层全覆盖，最轻量 |
| **SecGate + Cloudflare Free** | SecGate 管服务器层，Cloudflare 管 HTTP 层（WAF / DDoS），互补无重叠，全免费 |
| **SecGate + CrowdSec** | 本地防护 + 社区威胁情报，~220 MB |
| **SecGate + 1Panel** | 安全（SecGate）+ 运维（1Panel），职责分离 |

---

## 功能截图

| 安全看板 — 攻击态势总览 | 服务管理 — 端口认证网关 |
|:---:|:---:|
| ![安全看板](docs/screenshots/dashboard-overview.png) | ![服务管理](docs/screenshots/service-management.png) |

| 网关认证 — Token & IP 白名单 | 安全扫描 — 漏洞检测 |
|:---:|:---:|
| ![网关认证](docs/screenshots/gateway-auth.png) | ![安全扫描](docs/screenshots/security-scan.png) |

| AI 安全 — 服务发现 & API Key 检测 |
|:---:|
| ![AI 安全](docs/screenshots/ai-security.png) |

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

> 如果 `secgate` 命令未找到，可使用备选方式：`sudo python3 -m secgate_pkg setup`

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

- **攻击态势评分** — 页面顶部全宽面板，聚合 SSH 暴力破解、端口扫描、Web 异常请求、防御效果四个维度，通过对数归一化加权计算 0-100 威胁指数，自动映射为安全/注意/警告/严峻/危险五个等级（绿/蓝/黄/橙/红），含圆环仪表盘、较昨日趋势对比、各维度进度条，一眼判断服务器安全状况
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
sudo secgate uninstall
```

卸载程序会自动完成以下清理：
- 停止并删除 systemd 服务
- 清理 iptables / Nginx / UFW / Fail2Ban 配置
- 可选择备份凭证和数据文件到 `/tmp/secgate-backup-<时间戳>/`
- 清理日志和安装目录（Git 仓库需手动删除）

## 资源占用

SecGate 设计为轻量运行，对服务器性能影响极小。

### 内存

| 组件 | 进程 | 内存占用 | 说明 |
|------|------|----------|------|
| Dashboard | gunicorn (1+2 worker) | ~80-90 MB | 含 AlertEngine 后台告警线程 |
| Gateway | gunicorn (1+4 worker) | ~30-35 MB | 认证代理服务 |
| Nginx | master + worker | ~6-10 MB | 多数服务器已安装，非额外开销 |
| Fail2Ban | 单进程 | ~30-70 MB | 多数服务器已安装，非额外开销 |

> **实际新增内存约 120-150 MB**（不计 Nginx/Fail2Ban）。如果服务器内存紧张，可将 gunicorn worker 数量调为 1，内存降至约 80 MB。

### 磁盘

| 项目 | 大小 |
|------|------|
| 安装包 (tar.gz) | ~170 KB |
| 程序文件（部署后） | ~15 MB |
| Python 依赖 (pip) | ~50-80 MB |
| 运行时日志 | < 5 MB |
| 通知数据库 (SQLite) | < 1 MB |
| **合计** | **~100 MB** |

### CPU

所有组件空闲时 CPU 占用接近 0%。AlertEngine 每分钟执行一次告警检查，短暂占用 < 2% 单核。

### 最低配置

- **最低**：1 核 / 1 GB 内存（可运行但余量较小）
- **推荐**：2 核 / 2 GB 内存
- 网关认证代理增加约 1-2ms 请求延迟（本地 auth_request 回环）

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
