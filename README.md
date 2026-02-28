# SecGate - Linux 服务器安全网关管理平台

## 功能
- 安全监控看板（SSH 攻击、防火墙、服务状态、ECharts 可视化）
- 三层认证网关（IP 白名单 + Token + Cookie）
- 安全漏洞扫描（SCA、密钥泄露、Web 漏洞、异常连接）
- 站内安全通知（8 条自动检测规则）
- AI 安全助手（Claude 集成，可选）

## 系统要求
- Ubuntu 20.04+ / Debian 11+（需要 root 权限）
- Python 3.9+

## 安装方式

### 方式一：Git Clone（推荐）
```bash
git clone https://github.com/user/secgate.git /opt/secgate
cd /opt/secgate && sudo ./secgate setup
```

### 方式二：一键安装
```bash
curl -fsSL https://github.com/user/secgate/releases/latest/download/install.sh | sudo bash
```

### 方式三：pip 安装
```bash
pip install secgate
sudo secgate setup
```

## 日常管理
```bash
secgate start      # 启动所有服务
secgate stop       # 停止所有服务
secgate restart    # 重启所有服务
secgate status     # 查看运行状态
secgate creds      # 查看登录凭证
secgate version    # 查看版本号
secgate update     # 更新到最新版本
```

## 升级

### Git Clone 方式
```bash
cd /opt/secgate && sudo ./secgate stop
git pull && sudo ./secgate start
```

### 一键安装方式
```bash
curl -fsSL https://github.com/user/secgate/releases/latest/download/install.sh | sudo bash
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
SecGate 包含三个核心服务：
- Gateway (端口 5002) - Nginx 认证网关
- Dashboard (端口 5000) - 安全监控看板
- Agent (端口 8502) - AI 安全助手 (Chainlit)

## 许可证
MIT License
