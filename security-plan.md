# 服务器安全加固方案

> 目标服务器：Ubuntu 22.04 LTS (154.36.185.178) — 雨云/RainYun QEMU 虚拟化
> 编制日期：2026-02-26
> 编制人：安全专家 (security-expert)

---

## 一、当前安全风险分析

### 1.1 威胁态势总结

| 指标 | 数值 | 风险等级 |
|------|------|----------|
| SSH 失败登录总数 | **187,338 次** | 🔴 严重 |
| 攻击来源 IP 数 | **498+** | 🔴 严重 |
| 最活跃攻击 IP | 170.64.223.98 (8,064次) | 🔴 严重 |
| 最常被尝试的用户名 | root (43,790次) | 🔴 严重 |
| 攻击者成功入侵 | **0 次** | ✅ 安全 |
| 攻击仍在进行 | **是** (最新记录刚刚) | 🟡 警告 |

### 1.2 关键风险点

| # | 风险项 | 当前状态 | 风险等级 | 说明 |
|---|--------|----------|----------|------|
| 1 | **防火墙完全开放** | iptables 全 ACCEPT，UFW 未启用 | 🔴 严重 | 所有端口对外暴露，无任何过滤 |
| 2 | **无入侵防御系统** | 未安装 fail2ban | 🔴 严重 | 攻击 IP 不会被自动封禁，持续消耗资源 |
| 3 | **允许 root 直接 SSH 登录** | PermitRootLogin yes | 🟠 高危 | 43,790 次针对 root 的暴力破解 |
| 4 | **SSH 使用默认端口** | Port 22 | 🟡 中危 | 默认端口是自动化扫描的首要目标 |
| 5 | **X11 转发已开启** | X11Forwarding yes | 🟡 中危 | 云服务器无需 X11，增加攻击面 |
| 6 | **Web 服务直接暴露** | 3000/5711/8000/8501/9000 全公网可达 | 🟠 高危 | 无反向代理、无 HTTPS、无速率限制 |
| 7 | **内核安全参数未加固** | accept_redirects=1, send_redirects=1 | 🟡 中危 | 存在 ICMP 重定向攻击风险 |
| 8 | **SSH MaxAuthTries 过高** | 默认值 6 | 🟡 中危 | 每次连接允许 6 次尝试，便于暴力破解 |
| 9 | **无 swap 空间** | 未配置 | 🟡 中危 | OOM killer 可能杀死关键服务 |

---

## 二、安全加固方案

### 2.1 防火墙策略 (UFW)

UFW 已预装但未启用。推荐使用 UFW 管理防火墙规则（比直接操作 iptables 更简洁且持久化）。

#### 2.1.1 核心规则设计

```
默认策略：
  - 入站 (incoming): DENY（拒绝所有）
  - 出站 (outgoing): ALLOW（允许所有）
  - 路由 (routed):   DENY（拒绝所有）

允许入站规则：
  - SSH (22/tcp)       → 全部允许（依赖 fail2ban 做进一步防护）
  - HTTP 应用端口      → 按需开放
```

#### 2.1.2 执行命令

```bash
# ============================
# 步骤 1: 设置默认策略
# ============================
ufw default deny incoming
ufw default allow outgoing

# ============================
# 步骤 2: 允许 SSH（必须最先配置，否则会锁死自己！）
# ============================
ufw allow 22/tcp comment 'SSH'

# ============================
# 步骤 3: 允许 Web 应用端口
# ============================
# 根据实际需要开放（建议仅开放确实需要对外访问的端口）
ufw allow 3000/tcp comment 'Node.js App'
ufw allow 5711/tcp comment 'Python App'
ufw allow 8000/tcp comment 'Chainlit App 1'
ufw allow 8501/tcp comment 'Chainlit App 2'
ufw allow 9000/tcp comment 'Python App 2'

# ============================
# 步骤 4: 启用防火墙
# ============================
ufw --force enable

# ============================
# 步骤 5: 验证规则
# ============================
ufw status verbose
```

#### 2.1.3 可选：SSH 连接速率限制

```bash
# 删除之前的 SSH 规则，替换为限速规则
# limit 规则：30秒内超过6次连接的 IP 将被临时拒绝
ufw delete allow 22/tcp
ufw limit 22/tcp comment 'SSH rate-limited'
```

> **注意**：如果启用了 fail2ban（下节），建议不要同时使用 `ufw limit`，以免规则冲突。二选一即可。推荐用 fail2ban 方式。

---

### 2.2 Fail2Ban 配置

#### 2.2.1 安装

```bash
apt update && apt install -y fail2ban
```

#### 2.2.2 配置文件

创建 `/etc/fail2ban/jail.local`（不要修改 jail.conf，升级时会被覆盖）：

```ini
# /etc/fail2ban/jail.local
# 全局默认设置

[DEFAULT]
# 封禁时间：1小时（初次）
bantime  = 3600
# 检测窗口：10分钟
findtime = 600
# 最大失败次数
maxretry = 3
# 封禁动作：使用 UFW
banaction = ufw
banaction_allports = ufw
# 启用递增封禁（重复犯罪者封禁时间翻倍）
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 604800
# 忽略本地地址
ignoreip = 127.0.0.1/8 ::1

# ============================
# SSH 防护（核心）
# ============================
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = 300
bantime  = 3600
# aggressive 模式：检测更多攻击模式
mode     = aggressive

# ============================
# SSH DDoS 防护
# ============================
[sshd-ddos]
enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 5
findtime = 60
bantime  = 7200

# ============================
# 恶意扫描器封禁（可选）
# ============================
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ufw
bantime  = 86400
findtime = 86400
maxretry = 3
```

#### 2.2.3 启动与验证

```bash
# 启动 fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# 检查状态
fail2ban-client status
fail2ban-client status sshd

# 查看已封禁 IP
fail2ban-client get sshd banned
```

#### 2.2.4 批量封禁已知攻击 IP（可选）

基于分析的 Top 攻击 IP，可以一次性封禁：

```bash
# 封禁最活跃的攻击 IP（可根据实际分析结果调整）
ATTACK_IPS="170.64.223.98 103.124.174.18 165.245.138.2 165.245.132.208 134.199.165.8 45.183.70.66 212.193.4.46 210.211.122.97 129.212.185.118 185.246.128.171"
for ip in $ATTACK_IPS; do
    ufw insert 1 deny from $ip to any comment "Known attacker"
done
```

---

### 2.3 SSH 进一步加固

#### 2.3.1 配置变更

编辑 `/etc/ssh/sshd_config`，修改/添加以下配置：

```sshd_config
# ============================
# 认证安全
# ============================
# 禁用 root 直接登录（改为 prohibit-password，仅允许密钥，或直接 no）
# 注意：请确保有其他 sudo 用户可用，否则使用 prohibit-password
PermitRootLogin prohibit-password

# 最大认证尝试次数（从默认6降到3）
MaxAuthTries 3

# 登录超时时间（从默认120秒降到30秒）
LoginGraceTime 30

# 最大同时未认证连接数（防止连接耗尽）
MaxStartups 3:50:10

# 最大会话数
MaxSessions 3

# ============================
# 关闭不需要的功能
# ============================
# 禁用 X11 转发（云服务器不需要）
X11Forwarding no

# 禁用 TCP 转发（如不需要隧道）
AllowTcpForwarding no

# 禁用 Agent 转发
AllowAgentForwarding no

# 禁用空密码
PermitEmptyPasswords no

# 禁用用户环境变量
PermitUserEnvironment no

# ============================
# 连接保活（防止僵尸连接）
# ============================
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# ============================
# 日志级别提高（便于审计）
# ============================
LogLevel VERBOSE

# ============================
# 仅允许 SSH 协议 2（现代 OpenSSH 默认已是，显式声明）
# ============================
# Protocol 2  # 较新版本已移除此选项
```

#### 2.3.2 应用变更

```bash
# 验证配置语法
sshd -t

# 如果验证通过，重启 SSH
# ⚠️ 重要：在执行前确保当前 SSH 连接不会断开，建议开一个新的 SSH 测试连接
systemctl restart sshd
```

#### 2.3.3 关于更换 SSH 端口（可选）

更换端口可以大幅减少自动化扫描噪音（减少约 99% 的暴力破解尝试），但**不是真正的安全措施**（Security through obscurity）。如果选择更换：

```bash
# 在 /etc/ssh/sshd_config 中添加：
Port 22        # 先保留 22，防止新端口不通时锁死
Port 52222     # 添加新端口（选择1024-65535之间的非常用端口）

# UFW 放行新端口
ufw allow 52222/tcp comment 'SSH alternate'

# 重启 SSH 并测试新端口连接
systemctl restart sshd

# 确认新端口可以连接后，再移除 Port 22
# 修改 sshd_config 只保留 Port 52222
# 然后：ufw delete allow 22/tcp
```

---

### 2.4 Web 服务端口防护

#### 2.4.1 当前风险

当前 5 个 Web 服务端口（3000, 5711, 8000, 8501, 9000）全部直接对外暴露，存在以下风险：
- 无 HTTPS 加密，数据明文传输
- 无速率限制，易受 DDoS/CC 攻击
- 无访问控制，任何人可访问
- 应用层漏洞直接暴露

#### 2.4.2 推荐方案：Nginx 反向代理 + HTTPS

**安装 Nginx：**
```bash
apt install -y nginx
```

**Nginx 配置示例** (`/etc/nginx/sites-available/apps`)：

```nginx
# HTTP → HTTPS 重定向（需要域名和证书）
# 如果没有域名，可跳过 HTTPS，但仍建议使用反向代理

# 速率限制区域定义
limit_req_zone $binary_remote_addr zone=app_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Node.js 应用 (3000)
server {
    listen 80;
    server_name your-domain.com;  # 替换为实际域名或 IP

    # 安全响应头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # 速率限制
    limit_req zone=app_limit burst=20 nodelay;
    limit_conn conn_limit 20;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# 其他应用类似配置，端口替换为 5711, 8000, 8501, 9000
```

**如果使用反向代理，则后端端口应仅监听 localhost：**

```bash
# 修改 UFW，关闭后端端口的直接访问
ufw delete allow 3000/tcp
ufw delete allow 5711/tcp
ufw delete allow 8000/tcp
ufw delete allow 8501/tcp
ufw delete allow 9000/tcp

# 只开放 Nginx 端口
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
```

> **注意**：使用反向代理需要修改各应用监听地址为 `127.0.0.1`。如果暂时不做反向代理，保持当前端口开放即可，但务必做好应用层的认证。

#### 2.4.3 如不使用反向代理的最低防护

如果暂时不部署 Nginx，至少做以下防护：

```bash
# 对 Web 端口启用连接速率限制（使用 iptables，UFW 不支持精细控制）
# 限制每个 IP 每分钟最多 60 个新连接
iptables -A INPUT -p tcp --dport 3000 --syn -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --dport 5711 --syn -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --dport 8000 --syn -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --dport 8501 --syn -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --dport 9000 --syn -m connlimit --connlimit-above 20 -j DROP
```

---

### 2.5 内核安全参数加固

创建 `/etc/sysctl.d/99-security.conf`：

```ini
# /etc/sysctl.d/99-security.conf
# 服务器安全加固内核参数

# ============================
# 网络安全
# ============================
# 启用 SYN Cookie 防护（已启用，显式保持）
net.ipv4.tcp_syncookies = 1

# 禁用 ICMP 重定向接受（防止 MITM）
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 禁用 ICMP 重定向发送
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 启用反向路径过滤（防 IP 欺骗）
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 忽略 ICMP 广播请求（防 Smurf 攻击）
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 忽略伪造的 ICMP 错误消息
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 禁用源路由（防攻击者指定路由）
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 记录可疑数据包（火星数据包）
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ============================
# TCP 优化与安全
# ============================
# 减少 TIME_WAIT 回收时间
net.ipv4.tcp_fin_timeout = 15

# 启用 TIME_WAIT 状态 socket 快速回收
net.ipv4.tcp_tw_reuse = 1

# 最大 SYN 队列长度
net.ipv4.tcp_max_syn_backlog = 4096

# ============================
# 防止进程信息泄露
# ============================
# 限制 dmesg 访问（仅 root 可读）
kernel.dmesg_restrict = 1

# 限制内核指针泄露
kernel.kptr_restrict = 2
```

**应用内核参数：**

```bash
sysctl --system
```

---

### 2.6 自动安全更新

当前已启用 `unattended-upgrades`，配置看起来正确（`APT::Periodic::Update-Package-Lists "1"` 和 `APT::Periodic::Unattended-Upgrade "1"`）。

验证并确保安全更新自动安装：

```bash
# 检查配置
cat /etc/apt/apt.conf.d/50unattended-upgrades | grep -E "Allowed-Origins|Automatic-Reboot"

# 如需启用自动重启（安全更新后需要重启内核时）
# 编辑 /etc/apt/apt.conf.d/50unattended-upgrades 取消注释：
# Unattended-Upgrade::Automatic-Reboot "true";
# Unattended-Upgrade::Automatic-Reboot-Time "04:00";
```

---

### 2.7 其他安全最佳实践

#### 2.7.1 配置 swap 空间（防止 OOM）

```bash
# 创建 2GB swap 文件
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# 持久化
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# 设置 swappiness（低值，仅在内存紧张时使用）
sysctl vm.swappiness=10
echo 'vm.swappiness=10' >> /etc/sysctl.d/99-security.conf
```

#### 2.7.2 安装安全审计工具

```bash
# 安装 auditd（系统审计）
apt install -y auditd

# 安装 rkhunter（rootkit 检测）
apt install -y rkhunter
rkhunter --update
rkhunter --propupd

# 安装 logwatch（日志摘要）
apt install -y logwatch
```

#### 2.7.3 设置登录通知（可选）

在 `/etc/profile.d/ssh-login-alert.sh` 中添加登录通知：

```bash
#!/bin/bash
# /etc/profile.d/ssh-login-alert.sh
# SSH 登录通知 - 记录到系统日志
if [ -n "$SSH_CLIENT" ]; then
    logger -t ssh-login "SSH login: user=$USER from=${SSH_CLIENT%% *} at=$(date)"
fi
```

```bash
chmod +x /etc/profile.d/ssh-login-alert.sh
```

#### 2.7.4 限制 cron 和 at 权限

```bash
# 仅允许 root 使用 cron 和 at
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
```

---

## 三、实施优先级与顺序

### ⚡ 紧急（立即执行）

| 序号 | 操作 | 预计影响 | 风险 |
|------|------|----------|------|
| 1 | **配置并启用 UFW 防火墙** | 阻断非必要端口访问 | 低（先放行 SSH） |
| 2 | **安装并配置 fail2ban** | 自动封禁暴力破解 IP | 低 |
| 3 | **SSH 加固**（MaxAuthTries, LoginGraceTime 等） | 减少攻击效率 | 低 |

### 🟠 高优先级（24小时内）

| 序号 | 操作 | 预计影响 | 风险 |
|------|------|----------|------|
| 4 | **内核安全参数加固** | 防止网络层攻击 | 低 |
| 5 | **配置 swap 空间** | 防止 OOM 导致服务宕机 | 低 |
| 6 | **批量封禁已知攻击 IP** | 立即减少攻击流量 | 低 |

### 🟡 推荐（一周内）

| 序号 | 操作 | 预计影响 | 风险 |
|------|------|----------|------|
| 7 | **部署 Nginx 反向代理** | Web 服务安全显著提升 | 中（需要调整应用配置） |
| 8 | **安装安全审计工具** | 增强安全可见性 | 低 |
| 9 | **更换 SSH 端口（可选）** | 减少 99% 自动化扫描 | 中（需更新所有客户端） |

---

## 四、快速实施脚本

以下是一个一键执行的综合加固脚本。**请在执行前仔细阅读并确认**：

```bash
#!/bin/bash
# security-harden.sh - 服务器安全加固脚本
# ⚠️ 请确保有备用访问方式（如VNC控制台）再执行
# 使用方式: sudo bash security-harden.sh

set -e

echo "========================================="
echo "  服务器安全加固脚本 - Ubuntu 22.04"
echo "========================================="

# ---------- 1. UFW 防火墙 ----------
echo "[1/6] 配置 UFW 防火墙..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 3000/tcp comment 'Node.js App'
ufw allow 5711/tcp comment 'Python App'
ufw allow 8000/tcp comment 'Chainlit App 1'
ufw allow 8501/tcp comment 'Chainlit App 2'
ufw allow 9000/tcp comment 'Python App 2'
ufw --force enable
echo "[1/6] ✅ UFW 防火墙已启用"

# ---------- 2. Fail2Ban ----------
echo "[2/6] 安装配置 Fail2Ban..."
apt update -qq && apt install -y -qq fail2ban

cat > /etc/fail2ban/jail.local << 'JAILEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = ufw
banaction_allports = ufw
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 604800
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = 300
bantime  = 3600
mode     = aggressive

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ufw
bantime  = 86400
findtime = 86400
maxretry = 3
JAILEOF

systemctl enable fail2ban
systemctl restart fail2ban
echo "[2/6] ✅ Fail2Ban 已启用"

# ---------- 3. SSH 加固 ----------
echo "[3/6] 加固 SSH 配置..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)

# 使用 sed 修改配置（保留原有结构）
sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#LoginGraceTime 2m/LoginGraceTime 30/' /etc/ssh/sshd_config
sed -i 's/^#MaxStartups 10:30:100/MaxStartups 3:50:10/' /etc/ssh/sshd_config
sed -i 's/^#MaxSessions 10/MaxSessions 3/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^#AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# 验证配置
if sshd -t; then
    systemctl restart sshd
    echo "[3/6] ✅ SSH 配置已加固"
else
    echo "[3/6] ❌ SSH 配置验证失败，已回滚"
    cp /etc/ssh/sshd_config.bak.$(date +%Y%m%d) /etc/ssh/sshd_config
fi

# ---------- 4. 内核参数加固 ----------
echo "[4/6] 加固内核安全参数..."
cat > /etc/sysctl.d/99-security.conf << 'SYSEOF'
# 网络安全
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 4096
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
# Swap 优化
vm.swappiness = 10
SYSEOF
sysctl --system > /dev/null 2>&1
echo "[4/6] ✅ 内核参数已加固"

# ---------- 5. Swap 配置 ----------
echo "[5/6] 配置 swap 空间..."
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    echo "[5/6] ✅ 2GB Swap 已创建"
else
    echo "[5/6] ⏭️  Swap 文件已存在，跳过"
fi

# ---------- 6. 封禁已知攻击 IP ----------
echo "[6/6] 封禁已知攻击 IP..."
ATTACK_IPS="170.64.223.98 103.124.174.18 165.245.138.2 165.245.132.208 134.199.165.8 45.183.70.66 212.193.4.46 210.211.122.97 129.212.185.118 185.246.128.171"
for ip in $ATTACK_IPS; do
    ufw insert 1 deny from $ip to any comment "Known attacker" 2>/dev/null || true
done
echo "[6/6] ✅ 已封禁 10 个已知攻击 IP"

echo ""
echo "========================================="
echo "  安全加固完成！"
echo "========================================="
echo ""
echo "已完成："
echo "  ✅ UFW 防火墙已启用（默认拒绝入站）"
echo "  ✅ Fail2Ban 已安装并运行"
echo "  ✅ SSH 已加固（限制认证次数、禁用多余功能）"
echo "  ✅ 内核安全参数已优化"
echo "  ✅ Swap 空间已配置"
echo "  ✅ 已知攻击 IP 已封禁"
echo ""
echo "建议后续操作："
echo "  1. 部署 Nginx 反向代理保护 Web 服务"
echo "  2. 安装审计工具: apt install auditd rkhunter logwatch"
echo "  3. 考虑更换 SSH 端口减少扫描噪音"
echo "  4. 定期检查 fail2ban-client status sshd"
```

---

## 五、验证清单

加固完成后，使用以下命令验证：

```bash
# 1. 防火墙状态
ufw status verbose

# 2. Fail2Ban 状态
fail2ban-client status
fail2ban-client status sshd

# 3. SSH 配置验证
sshd -T | grep -E 'permitrootlogin|maxauthtries|x11forwarding|logingracetime|maxstartups'

# 4. 内核参数验证
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.all.rp_filter

# 5. Swap 状态
swapon --show

# 6. 开放端口确认
ss -tlnp

# 7. 从外部扫描确认（可使用另一台服务器）
# nmap -sS -p- 154.36.185.178
```

---

## 六、应急回滚方案

如果加固后出现连接问题：

```bash
# 通过雨云控制台的 VNC 访问服务器，然后：

# 临时关闭防火墙
ufw disable

# 恢复 SSH 配置
cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config
systemctl restart sshd

# 停止 fail2ban
systemctl stop fail2ban
```

> **关键提醒**：在执行任何防火墙或 SSH 变更之前，**务必确保可以通过雨云控制台的 VNC 功能访问服务器**，作为紧急备用通道。
