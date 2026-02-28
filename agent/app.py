"""SecGate AI 安全助手 - Chainlit + Claude Code CLI（stream-json 模式）

双层认证：
  第一层：网关 iptables + Nginx auth_request（gw_token cookie，非白名单 IP 必须通过）
  第二层：Chainlit 密码登录（所有用户都需要，和 Dashboard 共用账号密码）
"""

import os
import sys
import json
import asyncio

import chainlit as cl

# 项目根目录
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_DIR)

from shared import get_or_create_credential

# Claude Code CLI 路径
CLAUDE_CMD = "claude"

# 工作目录：项目根目录
WORK_DIR = PROJECT_DIR
CLAUDE_MD_PATH = os.path.join(os.path.dirname(__file__), "CLAUDE.md")

# 登录凭证（和 Dashboard 共用）
ADMIN_USER = "admin"
ADMIN_PASS = get_or_create_credential(
    "dashboard_password", lambda: __import__("secrets").token_urlsafe(12)
)

# 工具名称中文映射
TOOL_NAMES = {
    "Bash": "执行命令",
    "Read": "读取文件",
    "Glob": "搜索文件",
    "Grep": "搜索内容",
}


def _build_env() -> dict:
    """构建子进程环境变量"""
    env = os.environ.copy()
    env["DISABLE_CLAUDE_TELEMETRY"] = "1"
    env.pop("CLAUDECODE", None)
    return env


def _load_system_prompt() -> str:
    """读取 CLAUDE.md 作为系统指令"""
    if os.path.exists(CLAUDE_MD_PATH):
        with open(CLAUDE_MD_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


def _truncate(text: str, max_len: int = 500) -> str:
    """截断过长文本"""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (共 {len(text)} 字符)"


async def call_claude(prompt: str, reply: cl.Message):
    """调用 Claude Code CLI，解析 stream-json 事件流，展示思考过程"""
    system_prompt = _load_system_prompt()
    cmd = [
        CLAUDE_CMD,
        "--print",
        "--verbose",
        "--output-format", "stream-json",
        "--max-turns", "10",
        "--allowedTools", "Bash", "Read", "Glob", "Grep",
        "--disallowedTools", "Write", "Edit", "MultiEdit",
    ]
    if system_prompt:
        cmd.extend(["--system-prompt", system_prompt])
    cmd.append(prompt)

    env = _build_env()

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=WORK_DIR,
        env=env,
    )

    # 跟踪活跃的 tool_use Step，key = tool_use_id
    active_steps = {}
    line_buffer = b""

    while True:
        chunk = await process.stdout.read(4096)
        if not chunk:
            break
        line_buffer += chunk

        # 按行解析 JSON
        while b"\n" in line_buffer:
            line, line_buffer = line_buffer.split(b"\n", 1)
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                event = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            await _handle_event(event, reply, active_steps)

    # 处理缓冲区剩余数据
    if line_buffer:
        line_str = line_buffer.decode("utf-8", errors="replace").strip()
        if line_str:
            try:
                event = json.loads(line_str)
                await _handle_event(event, reply, active_steps)
            except json.JSONDecodeError:
                pass

    await process.wait()

    # 如果执行失败，追加错误信息
    if process.returncode != 0:
        stderr_data = await process.stderr.read()
        stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
        if stderr_text and "Trace:" not in stderr_text:
            error_lines = stderr_text.split("\n")[-10:]
            await reply.stream_token(
                f"\n\n---\n**执行异常** (exit {process.returncode}):\n```\n{''.join(error_lines)}\n```"
            )


async def _handle_event(event: dict, reply: cl.Message, active_steps: dict):
    """处理单个 stream-json 事件"""
    evt_type = event.get("type", "")

    if evt_type == "assistant":
        contents = event.get("message", {}).get("content", [])
        for block in contents:
            if block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    await reply.stream_token(text)

    elif evt_type == "result":
        pass


def _format_tool_input(tool_name: str, tool_input: dict) -> str:
    """格式化工具输入为可读文本"""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        desc = tool_input.get("description", "")
        if desc:
            return f"{desc}\n```bash\n{cmd}\n```"
        return f"```bash\n{cmd}\n```"

    elif tool_name == "Read":
        return f"`{tool_input.get('file_path', '')}`"

    elif tool_name == "Glob":
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", "")
        return f"`{pattern}`" + (f" in `{path}`" if path else "")

    elif tool_name == "Grep":
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", "")
        return f"`{pattern}`" + (f" in `{path}`" if path else "")

    return f"```json\n{json.dumps(tool_input, ensure_ascii=False, indent=2)}\n```"


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    """密码认证（和 Dashboard 共用账号密码）"""
    if username == ADMIN_USER and password == ADMIN_PASS:
        return cl.User(identifier=username, metadata={"role": "admin"})
    return None


@cl.on_chat_start
async def on_start():
    """对话开始时的欢迎信息"""
    await cl.Message(
        content=(
            "你好！我是 **SecGate AI 安全助手**。\n\n"
            "我可以帮你：\n"
            "- 分析服务器安全状态（SSH 攻击、防火墙拦截）\n"
            "- 查看网关认证配置和端口保护\n"
            "- 排查服务异常和日志分析\n"
            "- 检查系统资源使用情况\n"
            "- 提供安全加固建议\n\n"
            "请问有什么可以帮你的？"
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    """处理用户消息"""
    user_input = message.content.strip()
    if not user_input:
        return

    reply = cl.Message(content="")
    await reply.send()

    await call_claude(user_input, reply)

    await reply.update()
