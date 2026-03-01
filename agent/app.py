"""SecGate AI 安全助手 - Chainlit 双模式（Claude CLI / OpenAI 兼容 API）

模式一：检测到 Claude CLI + Anthropic API Key → 使用 Claude Code CLI（完整 Agent 能力）
模式二：Dashboard 配置了 LLM（千问/DeepSeek/OpenAI 等）→ 使用 OpenAI 兼容 API（纯对话）

双层认证：
  第一层：网关 iptables + Nginx auth_request（gw_token cookie，非白名单 IP 必须通过）
  第二层：Chainlit 密码登录（所有用户都需要，和 Dashboard 共用账号密码）
"""

import os
import sys
import json
import asyncio

import httpx
import chainlit as cl

# 项目根目录
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_DIR)

from shared import get_or_create_credential, load_credentials

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

# 对话历史最大轮数（OpenAI 兼容模式使用）
MAX_HISTORY = 20


# ============ 通用函数 ============

def _load_system_prompt() -> str:
    """读取 CLAUDE.md 作为系统指令"""
    if os.path.exists(CLAUDE_MD_PATH):
        with open(CLAUDE_MD_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


def _check_claude_cli() -> bool:
    """检查 claude CLI 是否可用"""
    import shutil
    return shutil.which(CLAUDE_CMD) is not None


def _get_anthropic_key() -> str:
    """获取 Anthropic API Key（环境变量或凭证文件）"""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        creds = load_credentials()
        key = creds.get("anthropic_api_key", "")
    return key


def _get_llm_config() -> dict | None:
    """从 .credentials.json 读取 LLM 配置（Dashboard 设置的 OpenAI 兼容 API）"""
    creds = load_credentials()
    api_base = creds.get("llm_api_base", "")
    api_key = creds.get("llm_api_key", "")
    model = creds.get("llm_model", "")
    if api_base and api_key and model:
        return {"api_base": api_base.rstrip("/"), "api_key": api_key, "model": model}
    return None


def _detect_mode() -> str:
    """检测当前可用模式：'claude_cli' / 'openai_api' / 'none'"""
    if _check_claude_cli() and _get_anthropic_key():
        return "claude_cli"
    if _get_llm_config():
        return "openai_api"
    return "none"


# ============ 模式一：Claude Code CLI ============

def _build_env() -> dict:
    """构建 Claude CLI 子进程环境变量"""
    env = os.environ.copy()
    env["DISABLE_CLAUDE_TELEMETRY"] = "1"
    env.pop("CLAUDECODE", None)
    api_key = _get_anthropic_key()
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
    return env


async def call_claude(prompt: str, reply: cl.Message):
    """调用 Claude Code CLI，解析 stream-json 事件流"""
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

    line_buffer = b""

    while True:
        chunk = await process.stdout.read(4096)
        if not chunk:
            break
        line_buffer += chunk

        while b"\n" in line_buffer:
            line, line_buffer = line_buffer.split(b"\n", 1)
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                event = json.loads(line_str)
            except json.JSONDecodeError:
                continue
            await _handle_cli_event(event, reply)

    if line_buffer:
        line_str = line_buffer.decode("utf-8", errors="replace").strip()
        if line_str:
            try:
                event = json.loads(line_str)
                await _handle_cli_event(event, reply)
            except json.JSONDecodeError:
                pass

    await process.wait()

    if process.returncode != 0:
        stderr_data = await process.stderr.read()
        stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
        if stderr_text and "Trace:" not in stderr_text:
            error_lines = stderr_text.split("\n")[-10:]
            await reply.stream_token(
                f"\n\n---\n**执行异常** (exit {process.returncode}):\n```\n{''.join(error_lines)}\n```"
            )


async def _handle_cli_event(event: dict, reply: cl.Message):
    """处理 Claude CLI stream-json 事件"""
    evt_type = event.get("type", "")
    if evt_type == "assistant":
        contents = event.get("message", {}).get("content", [])
        for block in contents:
            if block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    await reply.stream_token(text)


# ============ 模式二：OpenAI 兼容 API ============

async def call_openai_api(messages: list, reply: cl.Message):
    """调用 OpenAI 兼容 API，SSE 流式输出"""
    config = _get_llm_config()
    if not config:
        await reply.stream_token("**LLM 未配置**，请前往 Dashboard > AI 安全 > 助手设置 配置。")
        return

    url = config["api_base"] + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config["model"],
        "messages": messages,
        "stream": True,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15)) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    err_text = body.decode("utf-8", errors="replace")[:300]
                    await reply.stream_token(f"**LLM 请求失败** (HTTP {resp.status_code})\n```\n{err_text}\n```")
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        await reply.stream_token(content)

    except httpx.ConnectError:
        await reply.stream_token("\n\n**连接失败**，请检查 API 地址是否正确。")
    except httpx.ReadTimeout:
        await reply.stream_token("\n\n**响应超时**，请稍后重试。")
    except Exception as e:
        await reply.stream_token(f"\n\n**调用异常**: {e}")


# ============ Chainlit 事件 ============

@cl.password_auth_callback
def auth_callback(username: str, password: str):
    """密码认证（和 Dashboard 共用账号密码）"""
    if username == ADMIN_USER and password == ADMIN_PASS:
        return cl.User(identifier=username, metadata={"role": "admin"})
    return None


@cl.on_chat_start
async def on_start():
    """对话开始时检测模式并欢迎"""
    mode = _detect_mode()
    cl.user_session.set("mode", mode)

    if mode == "none":
        await cl.Message(
            content=(
                "## AI 助手尚未配置\n\n"
                "请选择以下任一方式激活：\n\n"
                "**方式一：Dashboard 页面配置（推荐）**\n"
                "前往 **Dashboard > AI 安全 > 助手设置**，填入 API 地址、密钥和模型名。\n"
                "支持通义千问、DeepSeek、OpenAI 等 OpenAI 兼容 API。\n\n"
                "**方式二：Claude Code CLI**\n"
                "安装 Claude CLI 并配置 Anthropic API Key，可获得完整 Agent 能力（执行命令、读取文件）。"
            )
        ).send()
        return

    cl.user_session.set("history", [])

    mode_label = "Claude Code CLI" if mode == "claude_cli" else "OpenAI 兼容 API"
    await cl.Message(
        content=(
            f"你好！我是 **SecGate AI 安全助手**（{mode_label}）。\n\n"
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

    # 重新检测模式（配置可能在对话中途更新）
    mode = _detect_mode()
    if mode == "none":
        await cl.Message(
            content="**AI 助手未配置**\n\n请前往 Dashboard > AI 安全 > 助手设置 配置 LLM 后刷新页面。"
        ).send()
        return

    reply = cl.Message(content="")
    await reply.send()

    if mode == "claude_cli":
        await call_claude(user_input, reply)
    else:
        # OpenAI 兼容 API 模式：维护对话历史
        history = cl.user_session.get("history")
        if history is None:
            history = []
            cl.user_session.set("history", history)

        system_prompt = _load_system_prompt()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.extend(history)
        messages.append({"role": "user", "content": user_input})

        await call_openai_api(messages, reply)

        # 更新对话历史
        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": reply.content})
        if len(history) > MAX_HISTORY * 2:
            history[:] = history[-(MAX_HISTORY * 2):]
        cl.user_session.set("history", history)

    await reply.update()
