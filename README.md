# SecGate - Linux 服务器安全网关管理平台

一站式 Linux 服务器安全管理方案，开箱即用。通过 `secgate setup` 一条命令完成部署，提供安全监控、访问控制、漏洞扫描、告警通知和 AI 辅助分析。

## 功能概览

### 安全监控看板
- SSH 攻击分析 — 失败登录统计、攻击 IP 地理位置追踪、高频攻击排行
- 防火墙拦截统计 — iptables 日志解析、拦截事件可视化
- 服务状态监控 — 端口存活检测、CPU/内存/磁盘使用率
- Fail2Ban 状态 — 封禁 IP 列表、jail 运行状态
- ECharts 数据可视化 — 支持 7/30/90 天趋势图

### 三层认证网关
- 第一层：IP 白名单（CIDR 网段支持）
- 第二层：Token 签名认证（URL 安全 Token）
- 第三层：Cookie 会话（7 天有效期）
- Nginx auth_request 集成，保护任意端口的 Web 服务

### 安全漏洞扫描（5 个扫描器）
- **SCA 依赖漏洞扫描** — 支持 Python/Node.js/Go/Java，对接 OSV 漏洞库
- **敏感信息检测** — 25+ 正则规则，覆盖 AWS Key、GitHub Token、RSA 私钥等
- **输入验证测试** — SQL 注入、XSS、路径穿越、SSRF 模糊测试
- **对外连接检测** — 监听端口枚举，数据库未授权访问检测
- **Web 安全检测** — SSL/TLS、安全头、Cookie 属性、敏感路径探测、CORS 检测

### 安全告警通知（8 条自动检测规则）
- SSH 密码登录未关闭
- 新端口未受网关保护
- 新 IP SSH 登录成功
- Fail2Ban 封禁新 IP
- SSH 暴力破解突增（1 小时 > 100 次）
- AI 服务无认证暴露
- 服务异常停止
- 磁盘空间不足（> 90%）

### AI 安全助手（可选）
- Claude 集成，对话式安全分析
- 只读权限，不会修改系统配置
- Chainlit Web UI，密码认证保护

## 系统要求

- Ubuntu 20.04+ / Debian 11+（需要 root 权限）
- Python 3.9+

## 安装部署

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

`secgate setup` 会自动完成以下配置：
1. 安装系统依赖（Nginx、iptables、UFW、Fail2Ban）
2. 安装 Python 依赖
3. 生成安全凭证（随机密码、Token）
4. 配置 Nginx 认证网关
5. 配置 iptables 防火墙规则
6. 配置 UFW 并放行必要端口
7. 安装 Gunicorn 生产级服务器
8. 配置 systemd 开机自启
9. 启动所有服务

## 使用指南

### 日常管理命令

```bash
secgate start      # 启动所有服务
secgate stop       # 停止所有服务
secgate restart    # 重启所有服务
secgate status     # 查看运行状态
secgate creds      # 查看登录凭证（用户名 + 密码）
secgate version    # 查看版本号
secgate update     # 更新到最新版本
```

### 访问看板

部署完成后访问 `http://服务器IP:5000`，使用 `secgate creds` 获取的用户名密码登录。

### 全部通过页面管理

部署完成后，所有配置均在看板页面完成，无需手动编辑任何文件：

- **网关认证** — 管理 Token（创建/删除）、IP 白名单（添加/移除）、受保护端口（一键添加/批量保护）
- **漏洞扫描** — 自动探测端口并推荐扫描器，一键触发扫描，支持定时计划
- **告警通知** — 8 条规则自动运行，未读告警实时显示在页面顶部
- **AI 助手** — 点击进入对话式安全分析

## 使用建议

1. **首次部署后**：运行 `secgate creds` 获取密码，登录看板检查告警通知
2. **添加 IP 白名单**：在看板「网关认证」页面添加你的办公网络 IP，白名单 IP 免认证直连
3. **保护端口**：看板会自动检测未保护的对外端口，一键加入网关保护
4. **关注告警**：页面顶部通知铃铛显示未读告警数，critical 级别需立即处理
5. **定期扫描**：建议每周运行一次全量扫描，关注依赖漏洞和敏感信息泄露

## 升级

### Git Clone 方式
```bash
cd /opt/secgate && sudo ./secgate update
```

### 一键安装方式
```bash
curl -fsSL https://github.com/zzmlb/secgate/releases/latest/download/install.sh | sudo bash
```

### pip 安装方式
```bash
pip install --upgrade secgate
```

## 卸载

```bash
sudo bash /opt/secgate/packaging/uninstall.sh
```

## 架构

```
用户请求 → Nginx (反向代理 + auth_request) → Gateway (:5002) 认证
                                               ↓ 通过
                                    Dashboard (:5000) 安全看板
                                    Agent     (:8502) AI 助手
```

SecGate 包含三个核心服务：

| 服务 | 端口 | 说明 |
|------|------|------|
| Gateway | 5002 | Nginx 认证网关，处理 IP 白名单 / Token / Cookie 三层认证 |
| Dashboard | 5000 | 安全监控看板，集成扫描器和告警引擎 |
| Agent | 8502 | AI 安全助手（Chainlit + Claude），可选 |

## 目录结构

```
secgate/
├── secgate              # CLI 管理工具
├── shared.py            # 共享模块（IP 检测、凭证管理）
├── gateway/             # 认证网关服务
├── dashboard/           # 安全监控看板
│   └── notifications.py # 告警引擎（8 条自动检测规则）
├── scanner/             # 漏洞扫描模块（5 个扫描器）
├── agent/               # AI 安全助手
└── packaging/           # 打包和部署脚本
```

## 许可证

MIT License
