"""
安全扫描模块 - SQLite 存储层
负责扫描任务、发现结果、日志的持久化存储
"""

import sqlite3
import json
import os
import threading
from datetime import datetime

# 数据库文件路径
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'scanner.db')

# 线程本地存储，保证每个线程使用独立的数据库连接
_local = threading.local()


def _get_conn():
    """获取当前线程的数据库连接（线程安全）"""
    if not hasattr(_local, 'conn') or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        # 启用 WAL 模式以提高并发性能
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """初始化数据库，创建所有必要的表"""
    conn = _get_conn()
    cursor = conn.cursor()

    # 扫描任务表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_tasks (
            task_id TEXT PRIMARY KEY,
            scan_types TEXT NOT NULL,
            target_path TEXT,
            target_url TEXT,
            status TEXT DEFAULT 'pending',
            progress INTEGER DEFAULT 0,
            current_scanner TEXT,
            finding_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            triggered_by TEXT DEFAULT 'manual',
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            error_msg TEXT
        )
    """)

    # 扫描发现结果表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            scanner TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            remediation TEXT,
            cve TEXT,
            cvss_score REAL,
            raw_data TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # 扫描日志表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            level TEXT DEFAULT 'INFO',
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # 定时扫描计划表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ports TEXT NOT NULL,
            scan_types TEXT NOT NULL,
            interval_hours INTEGER DEFAULT 24,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # 文件 hash 缓存表（增量扫描用）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_hashes (
            file_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            scanner TEXT NOT NULL,
            last_scanned TEXT NOT NULL,
            PRIMARY KEY (file_path, scanner)
        )
    """)

    # 扫描白名单表（误报管理）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT UNIQUE NOT NULL,
            scanner TEXT NOT NULL,
            title TEXT NOT NULL,
            reason TEXT,
            created_by TEXT DEFAULT 'manual',
            created_at TEXT NOT NULL
        )
    """)

    # 为常用查询创建索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_task_id ON scan_findings(task_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_task_id ON scan_logs(task_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON scan_tasks(status)")

    conn.commit()


def create_task(task_id, scan_types, target_path=None, target_url=None, triggered_by='manual'):
    """
    创建新的扫描任务

    参数:
        task_id: 任务唯一标识
        scan_types: 扫描类型列表，如 ['sca', 'secret_scan']
        target_path: 扫描目标路径（静态扫描用）
        target_url: 扫描目标URL（动态扫描用）
        triggered_by: 触发方式，manual 或 schedule
    """
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        """INSERT INTO scan_tasks
           (task_id, scan_types, target_path, target_url, status, progress,
            finding_count, critical_count, high_count, triggered_by, created_at)
           VALUES (?, ?, ?, ?, 'pending', 0, 0, 0, 0, ?, ?)""",
        (task_id, json.dumps(scan_types), target_path, target_url, triggered_by, now)
    )
    conn.commit()
    return task_id


def update_task_status(task_id, status, error_msg=None):
    """
    更新任务状态

    参数:
        task_id: 任务ID
        status: 新状态 (pending|running|completed|failed|cancelled)
        error_msg: 错误信息（仅 failed 状态时使用）
    """
    conn = _get_conn()
    now = datetime.now().isoformat()

    if status == 'running':
        conn.execute(
            "UPDATE scan_tasks SET status=?, started_at=? WHERE task_id=?",
            (status, now, task_id)
        )
    elif status in ('completed', 'failed', 'cancelled'):
        conn.execute(
            "UPDATE scan_tasks SET status=?, completed_at=?, error_msg=? WHERE task_id=?",
            (status, now, error_msg, task_id)
        )
    else:
        conn.execute(
            "UPDATE scan_tasks SET status=? WHERE task_id=?",
            (status, task_id)
        )
    conn.commit()


def update_task_progress(task_id, progress, current_scanner=None):
    """
    更新任务进度

    参数:
        task_id: 任务ID
        progress: 进度百分比 (0-100)
        current_scanner: 当前正在运行的扫描器名称
    """
    conn = _get_conn()
    conn.execute(
        "UPDATE scan_tasks SET progress=?, current_scanner=? WHERE task_id=?",
        (progress, current_scanner, task_id)
    )
    conn.commit()


def save_findings(task_id, findings):
    """
    批量保存扫描发现结果，并更新任务的统计计数

    参数:
        task_id: 任务ID
        findings: 发现结果字典列表
    """
    if not findings:
        return

    conn = _get_conn()
    now = datetime.now().isoformat()

    # 批量插入发现结果
    rows = []
    for f in findings:
        rows.append((
            task_id,
            f.get('scanner', ''),
            f.get('severity', 'INFO'),
            f.get('category', ''),
            f.get('title', ''),
            f.get('description', ''),
            f.get('location', ''),
            f.get('remediation', ''),
            f.get('cve', ''),
            f.get('cvss_score'),
            json.dumps(f.get('raw_data')) if f.get('raw_data') else None,
            now
        ))

    conn.executemany(
        """INSERT INTO scan_findings
           (task_id, scanner, severity, category, title, description,
            location, remediation, cve, cvss_score, raw_data, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows
    )

    # 更新任务的统计计数
    critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
    total_count = len(findings)

    conn.execute(
        """UPDATE scan_tasks SET
           finding_count = finding_count + ?,
           critical_count = critical_count + ?,
           high_count = high_count + ?
           WHERE task_id = ?""",
        (total_count, critical_count, high_count, task_id)
    )
    conn.commit()


def get_task(task_id):
    """
    获取单个任务的详细信息

    参数:
        task_id: 任务ID
    返回:
        任务字典，不存在则返回 None
    """
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scan_tasks WHERE task_id=?", (task_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_tasks(status=None, limit=50, offset=0):
    """
    获取任务列表，支持按状态过滤和分页

    参数:
        status: 按状态过滤（可选）
        limit: 每页数量，默认50
        offset: 偏移量，默认0
    返回:
        任务字典列表
    """
    conn = _get_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM scan_tasks WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (status, limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_findings(task_id=None, severity=None, scanner=None, limit=100, offset=0):
    """
    获取扫描发现结果，支持多条件过滤

    参数:
        task_id: 按任务ID过滤（可选）
        severity: 按严重等级过滤（可选）
        scanner: 按扫描器过滤（可选）
        limit: 每页数量
        offset: 偏移量
    返回:
        发现结果字典列表
    """
    conn = _get_conn()
    query = "SELECT * FROM scan_findings WHERE 1=1"
    params = []

    if task_id:
        query += " AND task_id=?"
        params.append(task_id)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if scanner:
        query += " AND scanner=?"
        params.append(scanner)

    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at DESC"
    query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_summary():
    """
    获取扫描统计摘要，包括任务总数、各状态计数、漏洞分布等

    返回:
        统计摘要字典
    """
    conn = _get_conn()

    # 任务统计
    task_stats = {}
    for status in ['pending', 'running', 'completed', 'failed', 'cancelled']:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM scan_tasks WHERE status=?", (status,)
        ).fetchone()
        task_stats[status] = row['cnt']
    task_stats['total'] = sum(task_stats.values())

    # 漏洞统计
    finding_stats = {}
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM scan_findings WHERE severity=?", (sev,)
        ).fetchone()
        finding_stats[sev] = row['cnt']
    finding_stats['total'] = sum(finding_stats.values())

    # 按扫描器分类的统计
    scanner_stats = {}
    rows = conn.execute(
        "SELECT scanner, COUNT(*) as cnt FROM scan_findings GROUP BY scanner"
    ).fetchall()
    for r in rows:
        scanner_stats[r['scanner']] = r['cnt']

    # 最近的任务
    last_task = conn.execute(
        "SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT 1"
    ).fetchone()

    return {
        'tasks': task_stats,
        'findings': finding_stats,
        'by_scanner': scanner_stats,
        'last_task': _row_to_dict(last_task) if last_task else None
    }


def add_log(task_id, level, message):
    """
    添加扫描日志

    参数:
        task_id: 任务ID
        level: 日志级别 (INFO|WARN|ERROR|DEBUG)
        message: 日志消息
    """
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO scan_logs (task_id, level, message, created_at) VALUES (?, ?, ?, ?)",
        (task_id, level, message, now)
    )
    conn.commit()


def get_logs(task_id, limit=200):
    """
    获取指定任务的日志

    参数:
        task_id: 任务ID
        limit: 返回的日志条数上限
    返回:
        日志字典列表
    """
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scan_logs WHERE task_id=? ORDER BY id ASC LIMIT ?",
        (task_id, limit)
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_deduped_summary():
    """去重后的服务器整体安全状态（按 title+location+scanner 去重）"""
    conn = _get_conn()

    # 去重漏洞统计
    row = conn.execute("""
        SELECT severity, COUNT(*) as cnt FROM (
            SELECT DISTINCT title, location, scanner, severity FROM scan_findings
        ) GROUP BY severity
    """).fetchall()
    finding_stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for r in row:
        finding_stats[r['severity']] = r['cnt']
    finding_stats['total'] = sum(finding_stats.values())

    # 去重后按扫描器分组
    rows = conn.execute("""
        SELECT scanner, COUNT(*) as cnt FROM (
            SELECT DISTINCT title, location, scanner FROM scan_findings
        ) GROUP BY scanner
    """).fetchall()
    by_scanner = {r['scanner']: r['cnt'] for r in rows}

    return {'findings': finding_stats, 'by_scanner': by_scanner}


def get_trend_data(days=30):
    """获取漏洞发现趋势数据，按日聚合"""
    conn = _get_conn()
    # 按天+severity统计
    rows = conn.execute("""
        SELECT DATE(created_at) as scan_date, severity, COUNT(*) as cnt
        FROM scan_findings
        WHERE created_at >= datetime('now', ?)
        GROUP BY scan_date, severity
        ORDER BY scan_date
    """, (f'-{days} days',)).fetchall()

    # 组装：[{date: '2026-02-27', CRITICAL: 5, HIGH: 2, ...}, ...]
    from collections import OrderedDict
    by_date = OrderedDict()
    for r in rows:
        d = r['scan_date']
        if d not in by_date:
            by_date[d] = {'date': d, 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        by_date[d][r['severity']] = r['cnt']

    return list(by_date.values())


def get_task_findings_summary(task_id):
    """获取单个任务的 findings 统计摘要"""
    conn = _get_conn()
    finding_stats = {}
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM scan_findings WHERE task_id=? AND severity=?",
            (task_id, sev)
        ).fetchone()
        finding_stats[sev] = row['cnt']
    finding_stats['total'] = sum(finding_stats.values())

    by_scanner = {}
    rows = conn.execute(
        "SELECT scanner, COUNT(*) as cnt FROM scan_findings WHERE task_id=? GROUP BY scanner",
        (task_id,)
    ).fetchall()
    for r in rows:
        by_scanner[r['scanner']] = r['cnt']

    return {'findings': finding_stats, 'by_scanner': by_scanner}


def create_schedule(name, ports, scan_types, interval_hours=24):
    """创建定时扫描计划"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    from datetime import timedelta
    next_run = (datetime.now() + timedelta(hours=interval_hours)).isoformat()
    cursor = conn.execute(
        """INSERT INTO scan_schedules
           (name, ports, scan_types, interval_hours, enabled, next_run, created_at)
           VALUES (?, ?, ?, ?, 1, ?, ?)""",
        (name, json.dumps(ports), json.dumps(scan_types), interval_hours, next_run, now)
    )
    conn.commit()
    return cursor.lastrowid


def get_schedules():
    """获取所有定时扫描计划"""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scan_schedules ORDER BY created_at DESC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_schedule(schedule_id, **kwargs):
    """更新定时扫描计划（enabled, interval_hours, ports, scan_types等）"""
    conn = _get_conn()
    allowed_fields = {'name', 'ports', 'scan_types', 'interval_hours', 'enabled'}
    updates = []
    params = []
    for key, value in kwargs.items():
        if key in allowed_fields:
            if key in ('ports', 'scan_types') and isinstance(value, (list, dict)):
                value = json.dumps(value)
            updates.append(f"{key}=?")
            params.append(value)
    if not updates:
        return False
    params.append(schedule_id)
    conn.execute(
        f"UPDATE scan_schedules SET {', '.join(updates)} WHERE id=?",
        params
    )
    conn.commit()
    return True


def delete_schedule(schedule_id):
    """删除定时扫描计划"""
    conn = _get_conn()
    conn.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))
    conn.commit()
    return True


def update_schedule_run(schedule_id, last_run, next_run):
    """更新计划的 last_run 和 next_run"""
    conn = _get_conn()
    conn.execute(
        "UPDATE scan_schedules SET last_run=?, next_run=? WHERE id=?",
        (last_run, next_run, schedule_id)
    )
    conn.commit()


# ========== 文件 Hash 缓存（增量扫描） ==========

def get_file_hash(file_path, scanner):
    """查询缓存的文件 hash"""
    conn = _get_conn()
    row = conn.execute(
        "SELECT file_hash FROM file_hashes WHERE file_path=? AND scanner=?",
        (file_path, scanner)
    ).fetchone()
    return row['file_hash'] if row else None


def save_file_hash(file_path, file_hash, scanner):
    """保存文件 hash（INSERT OR REPLACE）"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        """INSERT OR REPLACE INTO file_hashes (file_path, file_hash, scanner, last_scanned)
           VALUES (?, ?, ?, ?)""",
        (file_path, file_hash, scanner, now)
    )
    conn.commit()


def clear_file_hashes(scanner=None):
    """清除 hash 缓存，可指定仅清除某个扫描器的缓存"""
    conn = _get_conn()
    if scanner:
        conn.execute("DELETE FROM file_hashes WHERE scanner=?", (scanner,))
    else:
        conn.execute("DELETE FROM file_hashes")
    conn.commit()


# ========== 白名单管理 ==========

def add_allowlist(fingerprint, scanner, title, reason='', created_by='manual'):
    """添加白名单"""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        """INSERT OR IGNORE INTO scan_allowlist
           (fingerprint, scanner, title, reason, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (fingerprint, scanner, title, reason, created_by, now)
    )
    conn.commit()


def remove_allowlist(fingerprint):
    """删除白名单"""
    conn = _get_conn()
    conn.execute("DELETE FROM scan_allowlist WHERE fingerprint=?", (fingerprint,))
    conn.commit()


def get_allowlist():
    """获取所有白名单"""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scan_allowlist ORDER BY created_at DESC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def is_allowlisted(fingerprint):
    """检查某个 fingerprint 是否在白名单中"""
    conn = _get_conn()
    row = conn.execute(
        "SELECT 1 FROM scan_allowlist WHERE fingerprint=?", (fingerprint,)
    ).fetchone()
    return row is not None


def _row_to_dict(row):
    """将 sqlite3.Row 对象转换为普通字典"""
    if row is None:
        return None
    d = dict(row)
    # 将 scan_types 从 JSON 字符串还原为列表
    if 'scan_types' in d and d['scan_types']:
        try:
            d['scan_types'] = json.loads(d['scan_types'])
        except (json.JSONDecodeError, TypeError):
            pass
    # 将 ports 从 JSON 字符串还原
    if 'ports' in d and d['ports']:
        try:
            d['ports'] = json.loads(d['ports'])
        except (json.JSONDecodeError, TypeError):
            pass
    return d
