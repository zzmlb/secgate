"""
扫描器抽象基类
所有扫描器必须继承此基类并实现 run() 方法
"""

import hashlib
import os
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """
    扫描器抽象基类

    子类必须设置 name 和 description 属性，并实现 run() 方法。
    run() 方法应当返回 finding 字典列表，每个 finding 包含以下字段:
        - scanner: 扫描器标识
        - severity: 严重等级 (CRITICAL|HIGH|MEDIUM|LOW|INFO)
        - category: 漏洞类别
        - title: 漏洞标题
        - description: 漏洞描述
        - location: 漏洞位置（文件路径或URL）
        - remediation: 修复建议
        - cve: CVE 编号（可选）
        - cvss_score: CVSS 评分（可选）
        - raw_data: 原始数据（可选）
    """

    # 扫描器名称，子类必须覆盖
    name = ""
    # 扫描器描述，子类必须覆盖
    description = ""

    @abstractmethod
    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行扫描

        参数:
            target_path: 扫描目标路径（用于静态扫描）
            target_url: 扫描目标URL（用于动态扫描）
            task_id: 关联的任务ID（用于日志记录）
            cancel_flag: threading.Event 取消标志，定期检查以支持任务取消
            log_fn: 日志回调函数，签名为 log_fn(task_id, level, message)

        返回:
            finding 字典列表
        """
        pass

    def _log(self, log_fn, task_id, level, message):
        """
        辅助方法：安全地调用日志回调

        参数:
            log_fn: 日志回调函数（可能为 None）
            task_id: 任务ID
            level: 日志级别
            message: 日志消息
        """
        if log_fn and task_id:
            try:
                log_fn(task_id, level, message)
            except Exception:
                pass  # 日志写入失败不应影响扫描流程

    def _is_cancelled(self, cancel_flag):
        """
        辅助方法：检查任务是否已被取消

        参数:
            cancel_flag: threading.Event 对象
        返回:
            True 表示已取消，False 表示未取消
        """
        if cancel_flag and cancel_flag.is_set():
            return True
        return False

    def _compute_file_hash(self, filepath):
        """
        计算文件的 SHA256 hash

        参数:
            filepath: 文件路径
        返回:
            文件的 hex digest 字符串，失败返回 None
        """
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, OSError):
            return None

    def _should_scan_file(self, filepath, scanner_name):
        """
        判断文件是否需要扫描（增量扫描支持）

        比较当前文件 hash 与缓存的 hash，不同则需要扫描

        参数:
            filepath: 文件路径
            scanner_name: 扫描器名称标识
        返回:
            (should_scan, current_hash) 元组
        """
        from .. import storage
        current_hash = self._compute_file_hash(filepath)
        if current_hash is None:
            return True, None

        cached_hash = storage.get_file_hash(filepath, scanner_name)
        if cached_hash == current_hash:
            return False, current_hash

        return True, current_hash

    def _compute_finding_fingerprint(self, scanner, title, location):
        """
        计算 finding 的 fingerprint（用于白名单匹配）

        fingerprint = sha256(scanner + title + location)

        参数:
            scanner: 扫描器标识
            title: 漏洞标题
            location: 漏洞位置
        返回:
            fingerprint hex 字符串
        """
        raw = f'{scanner}|{title}|{location}'
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()
