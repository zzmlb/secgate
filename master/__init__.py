"""节点管理 Blueprint - SSH 连接管理 + SecGate 检测

认证方式（参考 pj35/ssh-file-manager）：
  - password: 密码
  - key_file: 本机密钥文件（自动检测，无需指定路径）
  - key: 粘贴私钥内容
"""

import os
import json
import uuid
import base64
import threading
from flask import Blueprint, request, jsonify

from .ssh_manager import SSHConnection, get_pool, check_secgate

# 数据文件路径
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
NODES_FILE = os.path.join(DATA_DIR, 'nodes.json')
_lock = threading.Lock()

# ---------- 简单加密（XOR + Base64）----------

_encrypt_key = None
MASK = '••••••'


def _get_encrypt_key():
    global _encrypt_key
    if _encrypt_key:
        return _encrypt_key
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from shared import get_or_create_credential
    _encrypt_key = get_or_create_credential(
        'master_encrypt_key',
        lambda: uuid.uuid4().hex,
        env_var='SECGATE_MASTER_KEY'
    )
    return _encrypt_key


def _xor_encrypt(plaintext):
    if not plaintext:
        return ''
    key = _get_encrypt_key()
    encrypted = bytes([ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(plaintext)])
    return base64.b64encode(encrypted).decode()


def _xor_decrypt(ciphertext):
    if not ciphertext:
        return ''
    key = _get_encrypt_key()
    data = base64.b64decode(ciphertext)
    return ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(data))


# ---------- nodes.json 读写 ----------

def _load_nodes():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(NODES_FILE):
        return []
    try:
        with open(NODES_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def _save_nodes(nodes):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(NODES_FILE, 'w') as f:
        json.dump(nodes, f, ensure_ascii=False, indent=2)


def _sanitize_node(node):
    """脱敏返回：密码/私钥用掩码替代"""
    r = {
        'id': node.get('id'),
        'name': node.get('name', ''),
        'host': node.get('host', ''),
        'port': node.get('port', 22),
        'username': node.get('username', 'root'),
        'auth_type': node.get('auth_type', 'password'),
        'status': node.get('status', 'unknown'),
        'secgate': node.get('secgate'),
        'last_check': node.get('last_check'),
        'created_at': node.get('created_at'),
    }
    # 掩码化敏感字段（让前端知道有值）
    r['password'] = MASK if node.get('_password') else ''
    r['private_key'] = MASK if node.get('_private_key') else ''
    return r


# ---------- 输入校验 ----------

import re as _re

# 合法主机名/IP：字母、数字、点、连字符、冒号（IPv6）
_HOST_RE = _re.compile(r'^[a-zA-Z0-9._:\-]+$')
_NAME_RE = _re.compile(r'^[^<>&\'"]{0,128}$')
_ALLOWED_AUTH = {'password', 'key_file', 'key'}


def _validate_node_input(data):
    """校验节点输入，返回错误信息或 None"""
    host = data.get('host', '').strip()
    if not host or not _HOST_RE.match(host):
        return '主机地址格式无效（仅允许 IP / 域名）'
    port = int(data.get('port', 22))
    if port < 1 or port > 65535:
        return '端口范围 1-65535'
    name = data.get('name', '').strip()
    if name and not _NAME_RE.match(name):
        return '名称包含非法字符'
    auth = data.get('auth_type', 'password')
    if auth not in _ALLOWED_AUTH:
        return f'认证方式无效，允许: {", ".join(_ALLOWED_AUTH)}'
    return None


# ---------- Blueprint ----------

def create_master_blueprint():
    bp = Blueprint('master', __name__, url_prefix='/api/master')

    # ---- 节点列表 ----

    @bp.route('/nodes', methods=['GET'])
    def list_nodes():
        with _lock:
            nodes = _load_nodes()
        return jsonify({
            'success': True,
            'nodes': [_sanitize_node(n) for n in nodes],
            'count': len(nodes),
        })

    # ---- 获取单个节点（编辑用）----

    @bp.route('/nodes/<node_id>', methods=['GET'])
    def get_node(node_id):
        with _lock:
            nodes = _load_nodes()
            node = _find_node(nodes, node_id)
        if not node:
            return jsonify({'success': False, 'error': '节点不存在'}), 404
        return jsonify({'success': True, 'node': _sanitize_node(node)})

    # ---- 添加节点 ----

    @bp.route('/nodes', methods=['POST'])
    def add_node():
        data = request.get_json()
        if not data or not data.get('host'):
            return jsonify({'success': False, 'error': '主机地址不能为空'}), 400
        err = _validate_node_input(data)
        if err:
            return jsonify({'success': False, 'error': err}), 400

        node = {
            'id': uuid.uuid4().hex[:12],
            'name': data.get('name', data['host']).strip(),
            'host': data['host'].strip(),
            'port': int(data.get('port', 22)),
            'username': data.get('username', 'root').strip(),
            'auth_type': data.get('auth_type', 'password'),
            'status': 'unknown',
            'secgate': None,
            'last_check': None,
            'created_at': _now_str(),
        }
        # 加密存储敏感字段
        if data.get('password'):
            node['_password'] = _xor_encrypt(data['password'])
        if data.get('private_key'):
            node['_private_key'] = _xor_encrypt(data['private_key'])

        with _lock:
            nodes = _load_nodes()
            for n in nodes:
                if n['host'] == node['host'] and n['port'] == node['port']:
                    return jsonify({'success': False, 'error': f"节点 {node['host']}:{node['port']} 已存在"}), 409
            nodes.append(node)
            _save_nodes(nodes)

        return jsonify({'success': True, 'node': _sanitize_node(node), 'message': '节点添加成功'})

    # ---- 更新节点（参考 pj35 掩码处理）----

    @bp.route('/nodes/<node_id>', methods=['PUT'])
    def update_node(node_id):
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400
        err = _validate_node_input(data)
        if err:
            return jsonify({'success': False, 'error': err}), 400

        with _lock:
            nodes = _load_nodes()
            node = _find_node(nodes, node_id)
            if not node:
                return jsonify({'success': False, 'error': '节点不存在'}), 404

            for field in ('name', 'host', 'username', 'auth_type'):
                if field in data and data[field]:
                    node[field] = data[field].strip()
            if 'port' in data:
                node['port'] = int(data['port'])

            # 密码：掩码则不更新，空则清除，其他则加密存储
            if 'password' in data:
                if data['password'] == MASK:
                    pass  # 不更新
                elif data['password']:
                    node['_password'] = _xor_encrypt(data['password'])
                else:
                    node.pop('_password', None)

            # 私钥：同上
            if 'private_key' in data:
                if data['private_key'] == MASK:
                    pass
                elif data['private_key']:
                    node['_private_key'] = _xor_encrypt(data['private_key'])
                else:
                    node.pop('_private_key', None)

            _save_nodes(nodes)

        # 清除连接池缓存
        get_pool().remove(node_id)
        return jsonify({'success': True, 'node': _sanitize_node(node), 'message': '节点已更新'})

    # ---- 删除节点 ----

    @bp.route('/nodes/<node_id>', methods=['DELETE'])
    def delete_node(node_id):
        with _lock:
            nodes = _load_nodes()
            before = len(nodes)
            nodes = [n for n in nodes if n.get('id') != node_id]
            if len(nodes) == before:
                return jsonify({'success': False, 'error': '节点不存在'}), 404
            _save_nodes(nodes)
        get_pool().remove(node_id)
        return jsonify({'success': True, 'message': '节点已删除'})

    # ---- 测试连接（已有节点）----

    @bp.route('/nodes/<node_id>/test', methods=['POST'])
    def test_connection(node_id):
        with _lock:
            nodes = _load_nodes()
            node = _find_node(nodes, node_id)
        if not node:
            return jsonify({'success': False, 'error': '节点不存在'}), 404

        try:
            conn = _build_connection(node)
            conn.connect()
            _, out, _ = conn.exec_command('hostname')
            conn.close()
            with _lock:
                nodes = _load_nodes()
                n = _find_node(nodes, node_id)
                if n:
                    n['status'] = 'online'
                    n['last_check'] = _now_str()
                    _save_nodes(nodes)
            return jsonify({'success': True, 'message': f'连接成功，主机名: {out}', 'hostname': out})
        except Exception as e:
            with _lock:
                nodes = _load_nodes()
                n = _find_node(nodes, node_id)
                if n:
                    n['status'] = 'offline'
                    n['last_check'] = _now_str()
                    _save_nodes(nodes)
            return jsonify({'success': False, 'error': f'连接失败: {str(e)}'}), 400

    # ---- 临时测试连接（添加前测试）----

    @bp.route('/test-connection', methods=['POST'])
    def test_connection_adhoc():
        data = request.get_json()
        if not data or not data.get('host'):
            return jsonify({'success': False, 'error': '主机地址不能为空'}), 400
        err = _validate_node_input(data)
        if err:
            return jsonify({'success': False, 'error': err}), 400
        try:
            conn = SSHConnection(
                host=data['host'].strip(),
                port=int(data.get('port', 22)),
                username=data.get('username', 'root').strip(),
                auth_type=data.get('auth_type', 'password'),
                password=data.get('password', ''),
                private_key=data.get('private_key', ''),
                timeout=10,
            )
            conn.connect()
            _, out, _ = conn.exec_command('hostname')
            conn.close()
            return jsonify({'success': True, 'message': f'连接成功，主机名: {out}', 'hostname': out})
        except Exception as e:
            return jsonify({'success': False, 'error': f'连接失败: {str(e)}'}), 400

    # ---- SecGate 检测 ----

    @bp.route('/nodes/<node_id>/check-secgate', methods=['POST'])
    def check_secgate_route(node_id):
        with _lock:
            nodes = _load_nodes()
            node = _find_node(nodes, node_id)
        if not node:
            return jsonify({'success': False, 'error': '节点不存在'}), 404

        try:
            conn = _build_connection(node)
            conn.connect()
            sg_info = check_secgate(conn)
            conn.close()
            with _lock:
                nodes = _load_nodes()
                n = _find_node(nodes, node_id)
                if n:
                    n['secgate'] = sg_info
                    n['status'] = 'online'
                    n['last_check'] = _now_str()
                    _save_nodes(nodes)
            return jsonify({'success': True, 'secgate': sg_info})
        except Exception as e:
            return jsonify({'success': False, 'error': f'检测失败: {str(e)}'}), 400

    return bp


# ---------- 工具函数 ----------

def _find_node(nodes, node_id):
    for n in nodes:
        if n.get('id') == node_id:
            return n
    return None


def _build_connection(node):
    """从节点数据构建 SSH 连接对象"""
    password = _xor_decrypt(node.get('_password', '')) if node.get('_password') else ''
    private_key = _xor_decrypt(node.get('_private_key', '')) if node.get('_private_key') else ''
    return SSHConnection(
        host=node['host'],
        port=node.get('port', 22),
        username=node.get('username', 'root'),
        auth_type=node.get('auth_type', 'password'),
        password=password,
        private_key=private_key,
        timeout=10,
    )


def _now_str():
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
