"""
安全扫描模块
Flask Blueprint，提供安全扫描相关的 REST API
集成到 Dashboard (port 5000)
"""

import os
import json
import psutil
from flask import Blueprint, request, jsonify
from . import storage
from .manager import ScanManager
from .scanners import list_scanner_info, SCANNER_DETAILS


# 全局任务管理器实例（延迟初始化）
_manager = None


def _get_manager():
    """获取或创建全局任务管理器实例"""
    global _manager
    if _manager is None:
        _manager = ScanManager(max_workers=2)
    return _manager


# ========== 端口探测相关逻辑 ==========

# 服务类型判断规则：进程名 → service_type
_PROCESS_SERVICE_MAP = {
    'mongod': ('database', 'MongoDB 数据库'),
    'redis-server': ('database', 'Redis 缓存'),
    'mysqld': ('database', 'MySQL 数据库'),
    'nginx': ('proxy', 'Nginx 代理'),
    'sshd': ('system', 'SSH 服务'),
    'docker-proxy': ('web', 'Docker 容器服务'),
    'chainlit': ('web', 'Chainlit AI 应用'),
    'uvicorn': ('web', 'Uvicorn Web 服务'),
    'gunicorn': ('web', 'Gunicorn Web 服务'),
}

# Web 应用常见进程名
_WEB_PROCESSES = {'python', 'python3', 'node', 'java', 'go', 'uvicorn', 'gunicorn', 'chainlit'}

# 各服务类型推荐的扫描器
_SERVICE_SCANNER_RECOMMENDATIONS = {
    'web': {
        'sca': '项目包含依赖文件',
        'secret_scan': '代码中可能存在硬编码凭证',
        'web_vuln': '检测到 Web 服务',
        'input_guard': '检测到 Web 服务',
        'outconn': '始终推荐',
    },
    'database': {
        'outconn': '检测到数据库服务',
    },
    'proxy': {
        'web_vuln': '检测到代理服务',
        'outconn': '始终推荐',
    },
    'system': {
        'outconn': '始终推荐',
    },
    'unknown': {
        'outconn': '始终推荐',
    },
}


def _detect_port_service(port):
    """
    探测指定端口上运行的服务信息

    参数:
        port: 要探测的端口号 (int)

    返回:
        (service_info, error) 元组
        成功时 service_info 为字典, error 为 None
        失败时 service_info 为 None, error 为错误信息字符串
    """
    port = int(port)

    # 1. 遍历网络连接，找到监听该端口的进程
    target_pid = None
    bind_address = None

    try:
        connections = psutil.net_connections('inet')
    except (psutil.AccessDenied, PermissionError):
        return None, '权限不足，无法读取网络连接信息'

    for conn in connections:
        # 只关注 LISTEN 状态的连接
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            target_pid = conn.pid
            bind_address = conn.laddr.ip
            break

    if target_pid is None:
        return None, f'未找到监听端口 {port} 的服务，请确认该端口上有服务正在运行'

    # 2. 获取进程详细信息
    try:
        proc = psutil.Process(target_pid)
        proc_name = proc.name()
        cmdline_parts = proc.cmdline()
        cmdline = ' '.join(cmdline_parts)
        try:
            exe_path_raw = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe_path_raw = ''
        try:
            cwd = proc.cwd()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cwd = ''
    except psutil.NoSuchProcess:
        return None, f'进程 (PID={target_pid}) 已不存在'
    except psutil.AccessDenied:
        return None, f'权限不足，无法读取进程 (PID={target_pid}) 信息'

    # 3. 判断 service_type
    # 去掉进程名可能的路径前缀，取基本名
    base_process_name = os.path.basename(proc_name).lower()

    if base_process_name in _PROCESS_SERVICE_MAP:
        service_type, service_name = _PROCESS_SERVICE_MAP[base_process_name]
    elif base_process_name in _WEB_PROCESSES:
        service_type = 'web'
        lang_name_map = {
            'python': 'Python', 'python3': 'Python',
            'node': 'Node.js', 'java': 'Java', 'go': 'Go',
        }
        service_name = f'{lang_name_map.get(base_process_name, base_process_name)} Web 服务'
    else:
        service_type = 'unknown'
        service_name = f'未知服务 ({proc_name})'

    # 4. 推断 exe_path (从 cmdline 中提取脚本路径)
    exe_path = ''
    if len(cmdline_parts) > 1:
        # 通常第二个参数是脚本文件路径 (如 python3 /path/to/app.py)
        candidate = cmdline_parts[1]
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            # 绝对路径直接使用
            exe_path = candidate
        elif cwd and os.path.isfile(os.path.join(cwd, candidate)):
            # 相对路径用目标进程的 cwd 拼接（而非当前进程的 cwd）
            exe_path = os.path.join(cwd, candidate)
    if not exe_path:
        exe_path = exe_path_raw

    # 5. 推断 target_path（项目根目录）
    target_path = ''
    if exe_path and os.path.isfile(exe_path):
        target_path = os.path.dirname(exe_path)
    elif cwd:
        target_path = cwd

    # 6. 拼接 target_url
    target_url = ''
    if service_type == 'web':
        target_url = f'http://127.0.0.1:{port}'

    service_info = {
        'port': port,
        'pid': target_pid,
        'process': proc_name,
        'cmdline': cmdline,
        'exe_path': exe_path,
        'working_dir': cwd,
        'bind_address': bind_address or '',
        'service_type': service_type,
        'service_name': service_name,
        'target_path': target_path,
        'target_url': target_url,
    }

    return service_info, None


def _build_scanner_recommendations(service_type):
    """
    根据服务类型构建扫描器推荐列表

    参数:
        service_type: 服务类型字符串 (web/database/proxy/system/unknown)

    返回:
        (recommended_ids, all_scanners) 元组
        recommended_ids: 推荐的扫描器 ID 列表
        all_scanners: 包含推荐原因的完整扫描器信息列表
    """
    recommendations = _SERVICE_SCANNER_RECOMMENDATIONS.get(service_type, _SERVICE_SCANNER_RECOMMENDATIONS['unknown'])

    scanner_infos = list_scanner_info()
    recommended_ids = list(recommendations.keys())
    all_scanners = []

    for info in scanner_infos:
        sid = info['id']
        is_recommended = sid in recommendations
        reason = recommendations.get(sid, '')
        all_scanners.append({
            'id': sid,
            'name': info['name'],
            'description': info['description'],
            'recommended': is_recommended,
            'reason': reason if is_recommended else '',
        })

    return recommended_ids, all_scanners


def _get_all_exposed_ports():
    """获取所有绑定在 0.0.0.0 / [::] 上的 LISTEN 端口（排除系统常见端口）"""
    EXCLUDE_PORTS = {22, 25000, 25001, 25711, 28000, 28501}  # 排除 SSH 和网关代理端口
    ports = set()
    try:
        for conn in psutil.net_connections('inet'):
            if conn.status == psutil.CONN_LISTEN:
                addr = conn.laddr.ip
                port = conn.laddr.port
                if addr in ('0.0.0.0', '::', '[::]') and port not in EXCLUDE_PORTS:
                    ports.add(port)
    except Exception:
        pass
    return sorted(ports)


def create_scanner_blueprint():
    """
    创建并返回安全扫描模块的 Flask Blueprint

    路由前缀: /api/scan
    提供以下 API:
        POST   /api/scan/trigger      - 触发新的扫描任务
        POST   /api/scan/detect-port  - 探测端口对应的服务并推荐扫描器
        GET    /api/scan/tasks        - 获取任务列表
        GET    /api/scan/task/<id>    - 获取任务详情
        DELETE /api/scan/task/<id>    - 取消任务
        GET    /api/scan/results      - 获取漏洞扫描结果
        GET    /api/scan/summary      - 获取统计摘要
        GET    /api/scan/logs/<id>    - 获取任务日志
        GET    /api/scan/scanners     - 获取可用扫描器列表
    """

    bp = Blueprint('scanner', __name__, url_prefix='/api/scan')

    # 初始化数据库
    storage.init_db()

    @bp.route('/detect-port', methods=['POST'])
    def detect_port():
        """
        探测指定端口（或多端口）的服务信息并推荐适合的扫描器

        请求体（JSON）:
        {
            "port": 5711,                  // 单端口（向后兼容）
            "ports": [5711, 5001],         // 多端口
            "all_exposed": true            // 自动探测所有对外暴露端口
        }

        返回:
        {
            "success": true,
            "services": [ ... ],
            "service": { ... },            // 单端口时兼容旧格式
            "recommended_scanners": ["sca", "secret_scan", ...],
            "all_scanners": [ ... ]
        }
        """
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400

        all_exposed = data.get('all_exposed', False)
        ports = data.get('ports') or []
        single_port = data.get('port')
        if single_port:
            ports = [single_port]

        if all_exposed:
            # 获取所有绑定 0.0.0.0 的端口
            ports = _get_all_exposed_ports()

        if not ports:
            return jsonify({'success': False, 'error': '缺少 port / ports 参数，或未探测到对外暴露端口'}), 400

        # 校验端口范围
        validated_ports = []
        for p in ports:
            try:
                p = int(p)
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': f'port {p} 必须是有效的整数'}), 400
            if p < 1 or p > 65535:
                return jsonify({'success': False, 'error': f'端口号 {p} 必须在 1-65535 范围内'}), 400
            validated_ports.append(p)

        services = []
        all_recommended = set()
        combined_scanners = {}

        for p in validated_ports:
            service_info, error = _detect_port_service(int(p))
            if service_info:
                rec_ids, sc_list = _build_scanner_recommendations(service_info['service_type'])
                service_info['recommended_scanners'] = rec_ids
                services.append(service_info)
                all_recommended.update(rec_ids)
                for sc in sc_list:
                    if sc['id'] not in combined_scanners or sc['recommended']:
                        combined_scanners[sc['id']] = sc

        if not services:
            return jsonify({'success': False, 'error': '未能探测到任何端口上的服务'}), 404

        return jsonify({
            'success': True,
            'services': services,
            'service': services[0] if len(services) == 1 else None,  # 兼容单端口
            'recommended_scanners': list(all_recommended),
            'all_scanners': list(combined_scanners.values()),
        })

    @bp.route('/trigger', methods=['POST'])
    def trigger_scan():
        """
        触发新的扫描任务

        请求体（JSON）:
        {
            "scan_types": ["sca", "secret_scan", "web_vuln"],  // 必填，扫描类型列表
            "target_path": "/path/to/project",                  // 可选，静态扫描目标路径
            "target_url": "http://localhost:5000",              // 可选，动态扫描目标URL
            "port": 5711,                                       // 可选，单端口号（自动探测目标）
            "ports": [5711, 5001],                              // 可选，多端口（自动探测目标）
            "triggered_by": "manual"                            // 可选，触发方式
        }

        返回:
        {
            "success": true,
            "task_id": "scan_20260226_143000_abcd1234",
            "message": "扫描任务已创建"
        }
        """
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400

        scan_types = data.get('scan_types')
        if not scan_types or not isinstance(scan_types, list):
            return jsonify({'success': False, 'error': 'scan_types 必须是非空列表'}), 400

        target_path = data.get('target_path')
        target_url = data.get('target_url')
        port = data.get('port')
        ports = data.get('ports') or []
        triggered_by = data.get('triggered_by', 'manual')

        # 兼容单端口和多端口
        if port is not None and not ports:
            ports = [port]

        # 如果提供了端口列表，自动探测服务信息来补充 target_path 和 target_url
        if ports:
            paths = set()
            urls = set()
            for p in ports:
                try:
                    p = int(p)
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'error': f'port {p} 必须是有效的整数'}), 400

                service_info, error = _detect_port_service(p)
                if error:
                    continue  # 多端口模式下跳过探测失败的端口

                if service_info.get('target_path'):
                    paths.add(service_info['target_path'])
                if service_info.get('target_url'):
                    urls.add(service_info['target_url'])

            # 仅在用户未手动指定时，用探测结果填充
            if not target_path and paths:
                target_path = list(paths)[0]
            if not target_url and urls:
                target_url = list(urls)[0]

        # 至少需要提供一个扫描目标
        if not target_path and not target_url:
            return jsonify({
                'success': False,
                'error': '至少需要提供 target_path、target_url 或 port/ports'
            }), 400

        try:
            manager = _get_manager()
            task_id = manager.create_task(
                scan_types=scan_types,
                target_path=target_path,
                target_url=target_url,
                triggered_by=triggered_by
            )
            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': '扫描任务已创建'
            })
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': f'创建任务失败: {str(e)}'}), 500

    @bp.route('/tasks', methods=['GET'])
    def get_tasks():
        """
        获取任务列表

        查询参数:
            status: 按状态过滤（可选）
            limit: 每页数量，默认 50
            offset: 偏移量，默认 0

        返回:
        {
            "success": true,
            "tasks": [...]
        }
        """
        status = request.args.get('status')
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        tasks = storage.get_tasks(status=status, limit=limit, offset=offset)
        return jsonify({
            'success': True,
            'tasks': tasks,
            'count': len(tasks)
        })

    @bp.route('/task/<task_id>', methods=['GET'])
    def get_task(task_id):
        """
        获取单个任务的详细信息

        返回:
        {
            "success": true,
            "task": { ... },
            "findings_summary": { ... }
        }
        """
        task = storage.get_task(task_id)
        if not task:
            return jsonify({'success': False, 'error': '任务不存在'}), 404

        findings_summary = storage.get_task_findings_summary(task_id)
        return jsonify({
            'success': True,
            'task': task,
            'findings_summary': findings_summary
        })

    @bp.route('/task/<task_id>', methods=['DELETE'])
    def cancel_task(task_id):
        """
        取消一个扫描任务

        返回:
        {
            "success": true,
            "message": "任务已取消"
        }
        """
        manager = _get_manager()
        result = manager.cancel_task(task_id)

        if result:
            return jsonify({
                'success': True,
                'message': '任务取消请求已发送'
            })
        else:
            task = storage.get_task(task_id)
            if not task:
                return jsonify({'success': False, 'error': '任务不存在'}), 404
            return jsonify({
                'success': False,
                'error': f'任务当前状态为 {task["status"]}，无法取消'
            }), 400

    @bp.route('/results', methods=['GET'])
    def get_results():
        """
        获取漏洞扫描结果

        查询参数:
            task_id: 按任务ID过滤（可选）
            severity: 按严重等级过滤（可选）
            scanner: 按扫描器过滤（可选）
            limit: 每页数量，默认 100
            offset: 偏移量，默认 0

        返回:
        {
            "success": true,
            "findings": [...],
            "count": 42
        }
        """
        task_id = request.args.get('task_id')
        severity = request.args.get('severity')
        scanner = request.args.get('scanner')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)

        findings = storage.get_findings(
            task_id=task_id,
            severity=severity,
            scanner=scanner,
            limit=limit,
            offset=offset
        )
        return jsonify({
            'success': True,
            'findings': findings,
            'count': len(findings)
        })

    @bp.route('/summary', methods=['GET'])
    def get_summary():
        """
        获取扫描统计摘要

        返回:
        {
            "success": true,
            "summary": {
                "tasks": {"total": 10, "completed": 8, ...},
                "findings": {"total": 42, "CRITICAL": 3, ...},
                "by_scanner": {"sca": 10, "web_vuln": 15, ...},
                "last_task": { ... }
            },
            "deduped": { ... },
            "trend": [ ... ]
        }
        """
        summary = storage.get_summary()
        deduped = storage.get_deduped_summary()
        trend = storage.get_trend_data(30)
        return jsonify({
            'success': True,
            'summary': summary,
            'deduped': deduped,
            'trend': trend,
        })

    @bp.route('/logs/<task_id>', methods=['GET'])
    def get_logs(task_id):
        """
        获取指定任务的运行日志

        查询参数:
            limit: 返回日志条数上限，默认 200

        返回:
        {
            "success": true,
            "logs": [...]
        }
        """
        task = storage.get_task(task_id)
        if not task:
            return jsonify({'success': False, 'error': '任务不存在'}), 404

        limit = request.args.get('limit', 200, type=int)
        logs = storage.get_logs(task_id, limit=limit)
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })

    @bp.route('/scanners', methods=['GET'])
    def get_scanners():
        """
        获取所有可用扫描器的信息

        返回:
        {
            "success": true,
            "scanners": [
                {"id": "sca", "name": "SCA 依赖漏洞扫描", "description": "..."},
                ...
            ]
        }
        """
        scanners = list_scanner_info()
        return jsonify({
            'success': True,
            'scanners': scanners
        })

    # ========== 白名单管理 API ==========

    @bp.route('/allowlist', methods=['GET'])
    def get_allowlist():
        """获取白名单列表"""
        items = storage.get_allowlist()
        return jsonify({'success': True, 'allowlist': items, 'count': len(items)})

    @bp.route('/allowlist', methods=['POST'])
    def add_allowlist():
        """
        添加白名单

        请求体:
        {
            "scanner": "secret_scan",
            "title": "漏洞标题",
            "location": "漏洞位置",
            "reason": "误报原因"
        }
        """
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400

        scanner_name = data.get('scanner', '')
        title = data.get('title', '')
        location = data.get('location', '')
        reason = data.get('reason', '')

        if not scanner_name or not title:
            return jsonify({'success': False, 'error': '缺少 scanner 或 title 参数'}), 400

        import hashlib
        fp_raw = f'{scanner_name}|{title}|{location}'
        fingerprint = hashlib.sha256(fp_raw.encode('utf-8')).hexdigest()

        storage.add_allowlist(fingerprint, scanner_name, title, reason)
        return jsonify({
            'success': True,
            'fingerprint': fingerprint,
            'message': '白名单已添加'
        })

    @bp.route('/allowlist/<fingerprint>', methods=['DELETE'])
    def remove_allowlist(fingerprint):
        """删除白名单"""
        storage.remove_allowlist(fingerprint)
        return jsonify({'success': True, 'message': '白名单已删除'})

    # ========== 定时扫描计划 API ==========

    @bp.route('/schedule', methods=['POST'])
    def create_schedule():
        """
        创建定时扫描计划

        请求体（JSON）:
        {
            "name": "每日全端口扫描",
            "ports": [5711, 5001] 或 "all_exposed",
            "scan_types": ["sca", "secret_scan"],
            "interval_hours": 24
        }
        """
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400

        name = data.get('name')
        ports = data.get('ports')
        scan_types = data.get('scan_types')
        interval_hours = data.get('interval_hours', 24)

        if not name:
            return jsonify({'success': False, 'error': '缺少 name 参数'}), 400
        if not ports:
            return jsonify({'success': False, 'error': '缺少 ports 参数'}), 400
        if not scan_types or not isinstance(scan_types, list):
            return jsonify({'success': False, 'error': 'scan_types 必须是非空列表'}), 400

        schedule_id = storage.create_schedule(name, ports, scan_types, interval_hours)
        return jsonify({
            'success': True,
            'schedule_id': schedule_id,
            'message': '定时扫描计划已创建'
        })

    @bp.route('/schedules', methods=['GET'])
    def get_schedules():
        """获取所有定时扫描计划"""
        schedules = storage.get_schedules()
        return jsonify({
            'success': True,
            'schedules': schedules
        })

    @bp.route('/schedule/<int:schedule_id>', methods=['PUT'])
    def update_schedule(schedule_id):
        """更新定时扫描计划"""
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求体不能为空'}), 400

        result = storage.update_schedule(schedule_id, **data)
        if result:
            return jsonify({'success': True, 'message': '计划已更新'})
        else:
            return jsonify({'success': False, 'error': '无有效字段可更新'}), 400

    @bp.route('/schedule/<int:schedule_id>', methods=['DELETE'])
    def delete_schedule(schedule_id):
        """删除定时扫描计划"""
        storage.delete_schedule(schedule_id)
        return jsonify({'success': True, 'message': '计划已删除'})

    @bp.route('/schedule/<int:schedule_id>/run', methods=['POST'])
    def run_schedule(schedule_id):
        """立即执行某定时扫描计划"""
        schedules = storage.get_schedules()
        sch = None
        for s in schedules:
            if s['id'] == schedule_id:
                sch = s
                break
        if not sch:
            return jsonify({'success': False, 'error': '计划不存在'}), 404

        ports = sch['ports']
        scan_types = sch['scan_types']

        # 解析端口
        if ports == 'all_exposed' or (isinstance(ports, list) and ports == ['all_exposed']):
            actual_ports = _get_all_exposed_ports()
        else:
            actual_ports = [int(p) for p in (ports if isinstance(ports, list) else [ports])]

        # 从端口探测目标
        paths = set()
        urls = set()
        for p in actual_ports:
            svc, _ = _detect_port_service(p)
            if svc:
                if svc.get('target_path'):
                    paths.add(svc['target_path'])
                if svc.get('target_url'):
                    urls.add(svc['target_url'])

        target_path = list(paths)[0] if paths else None
        target_url = list(urls)[0] if urls else None

        if not target_path and not target_url:
            return jsonify({'success': False, 'error': '无法从端口探测到扫描目标'}), 400

        try:
            manager = _get_manager()
            task_id = manager.create_task(
                scan_types=scan_types if isinstance(scan_types, list) else json.loads(scan_types),
                target_path=target_path,
                target_url=target_url,
                triggered_by='schedule'
            )

            # 更新计划执行时间
            from datetime import datetime, timedelta
            now = datetime.now()
            interval = sch.get('interval_hours', 24)
            next_time = now + timedelta(hours=interval)
            storage.update_schedule_run(schedule_id, now.isoformat(), next_time.isoformat())

            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': '计划已立即执行'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': f'执行失败: {str(e)}'}), 500

    # ========== 暴露端口查询 API ==========

    @bp.route('/exposed-ports', methods=['GET'])
    def get_exposed_ports():
        """返回所有对外暴露的端口列表"""
        ports_info = []
        for port in _get_all_exposed_ports():
            service_info, _ = _detect_port_service(port)
            if service_info:
                ports_info.append({
                    'port': port,
                    'process': service_info['process'],
                    'service_name': service_info['service_name'],
                    'service_type': service_info['service_type'],
                    'bind_address': service_info['bind_address']
                })
        return jsonify({'success': True, 'ports': ports_info})

    # ========== 定时调度器后台线程 ==========

    import threading
    import time
    from datetime import datetime, timedelta

    def _scheduler_loop():
        """后台定时调度循环"""
        while True:
            try:
                schedules = storage.get_schedules()
                now = datetime.now()
                for sch in schedules:
                    if not sch.get('enabled'):
                        continue
                    next_run = sch.get('next_run')
                    if next_run and datetime.fromisoformat(next_run) > now:
                        continue
                    # 到时间了，执行扫描
                    ports = sch['ports']
                    scan_types = sch['scan_types']

                    # 解析端口获取目标
                    target_path = None
                    target_url = None
                    if ports == 'all_exposed' or (isinstance(ports, list) and ports == ['all_exposed']):
                        actual_ports = _get_all_exposed_ports()
                    else:
                        actual_ports = [int(p) for p in (ports if isinstance(ports, list) else [ports])]

                    # 从端口探测目标
                    paths = set()
                    urls = set()
                    for p in actual_ports:
                        svc, _ = _detect_port_service(p)
                        if svc:
                            if svc.get('target_path'):
                                paths.add(svc['target_path'])
                            if svc.get('target_url'):
                                urls.add(svc['target_url'])

                    if paths:
                        target_path = list(paths)[0]  # 取第一个
                    if urls:
                        target_url = list(urls)[0]

                    if target_path or target_url:
                        manager = _get_manager()
                        manager.create_task(
                            scan_types=scan_types if isinstance(scan_types, list) else json.loads(scan_types),
                            target_path=target_path,
                            target_url=target_url,
                            triggered_by='schedule'
                        )

                    # 更新计划执行时间
                    interval = sch.get('interval_hours', 24)
                    next_time = now + timedelta(hours=interval)
                    storage.update_schedule_run(sch['id'], now.isoformat(), next_time.isoformat())

            except Exception as e:
                print(f'[WARN] 调度器异常: {e}')

            time.sleep(60)  # 每分钟检查一次

    # 启动调度器线程
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()

    return bp
