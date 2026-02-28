"""
扫描任务管理器
使用 ThreadPoolExecutor 管理扫描任务的创建、执行和取消
"""

import hashlib
import uuid
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import storage
from .scanners import get_scanner


class ScanManager:
    """
    扫描任务管理器

    负责:
    - 创建扫描任务并提交到线程池执行
    - 管理任务的生命周期（创建 -> 运行 -> 完成/失败/取消）
    - 提供任务取消功能
    - 协调多个扫描器的串行执行和进度更新
    """

    def __init__(self, max_workers=2):
        """
        初始化任务管理器

        参数:
            max_workers: 线程池最大并发数，默认 2
        """
        # 线程池执行器
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        # 取消标志字典: task_id -> threading.Event
        self._cancel_flags = {}
        # 保护取消标志字典的锁
        self._lock = threading.Lock()

        # 初始化数据库
        storage.init_db()

    def create_task(self, scan_types, target_path=None, target_url=None, triggered_by='manual'):
        """
        创建并启动一个新的扫描任务

        参数:
            scan_types: 扫描类型列表，如 ['sca', 'secret_scan', 'web_vuln']
            target_path: 扫描目标路径（静态扫描用）
            target_url: 扫描目标URL（动态扫描用）
            triggered_by: 触发方式，'manual' 或 'schedule'

        返回:
            task_id: 新创建的任务ID
        """
        # 生成唯一的任务ID
        task_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        # 验证扫描类型
        valid_types = []
        for scan_type in scan_types:
            scanner = get_scanner(scan_type)
            if scanner:
                valid_types.append(scan_type)
            else:
                storage.add_log(task_id, 'WARN', f'未知的扫描类型: {scan_type}，已忽略')

        if not valid_types:
            raise ValueError('没有有效的扫描类型')

        # 创建数据库记录
        storage.create_task(
            task_id=task_id,
            scan_types=valid_types,
            target_path=target_path,
            target_url=target_url,
            triggered_by=triggered_by
        )

        # 创建取消标志
        cancel_flag = threading.Event()
        with self._lock:
            self._cancel_flags[task_id] = cancel_flag

        # 记录日志
        storage.add_log(task_id, 'INFO',
                        f'任务已创建，扫描类型: {valid_types}，目标路径: {target_path}，目标URL: {target_url}')

        # 提交到线程池执行
        self._executor.submit(
            self._run_task,
            task_id, valid_types, target_path, target_url, cancel_flag
        )

        return task_id

    def cancel_task(self, task_id):
        """
        取消一个正在运行的扫描任务

        参数:
            task_id: 要取消的任务ID

        返回:
            True 表示取消请求已发出，False 表示任务不存在或不在运行状态
        """
        task = storage.get_task(task_id)
        if not task:
            return False

        if task['status'] not in ('pending', 'running'):
            return False

        # 设置取消标志
        with self._lock:
            cancel_flag = self._cancel_flags.get(task_id)
            if cancel_flag:
                cancel_flag.set()

        storage.add_log(task_id, 'WARN', '收到取消请求')
        storage.update_task_status(task_id, 'cancelled')

        return True

    def _run_task(self, task_id, scan_types, target_path, target_url, cancel_flag):
        """
        在线程池中执行扫描任务

        依次运行每个扫描器，收集发现结果，更新进度

        参数:
            task_id: 任务ID
            scan_types: 要运行的扫描类型列表
            target_path: 扫描目标路径
            target_url: 扫描目标URL
            cancel_flag: threading.Event 取消标志
        """
        try:
            # 更新任务状态为运行中
            storage.update_task_status(task_id, 'running')
            storage.add_log(task_id, 'INFO', '任务开始执行')

            total_scanners = len(scan_types)
            all_findings = []

            for index, scan_type in enumerate(scan_types):
                # 检查取消标志
                if cancel_flag.is_set():
                    storage.add_log(task_id, 'WARN', '任务已被取消，停止执行')
                    storage.update_task_status(task_id, 'cancelled')
                    return

                # 获取扫描器实例
                scanner = get_scanner(scan_type)
                if not scanner:
                    storage.add_log(task_id, 'ERROR', f'扫描器 {scan_type} 不存在')
                    continue

                # 更新进度
                progress = int((index / total_scanners) * 100)
                storage.update_task_progress(task_id, progress, scanner.name)
                storage.add_log(task_id, 'INFO',
                                f'开始运行扫描器 [{index + 1}/{total_scanners}]: {scanner.name}')

                try:
                    # 执行扫描
                    findings = scanner.run(
                        target_path=target_path,
                        target_url=target_url,
                        task_id=task_id,
                        cancel_flag=cancel_flag,
                        log_fn=self._log_callback
                    )

                    if findings:
                        # 过滤白名单中的 findings
                        filtered_findings = []
                        allowlist_count = 0
                        for f in findings:
                            fp_raw = f"{f.get('scanner', '')}|{f.get('title', '')}|{f.get('location', '')}"
                            fp = hashlib.sha256(fp_raw.encode('utf-8')).hexdigest()
                            if storage.is_allowlisted(fp):
                                allowlist_count += 1
                                continue
                            filtered_findings.append(f)

                        all_findings.extend(filtered_findings)
                        if filtered_findings:
                            storage.save_findings(task_id, filtered_findings)

                        msg = f'扫描器 {scanner.name} 完成，发现 {len(filtered_findings)} 个问题'
                        if allowlist_count > 0:
                            msg += f'（已过滤 {allowlist_count} 个白名单项）'
                        storage.add_log(task_id, 'INFO', msg)
                    else:
                        storage.add_log(task_id, 'INFO',
                                        f'扫描器 {scanner.name} 完成，未发现问题')

                except Exception as e:
                    error_detail = traceback.format_exc()
                    storage.add_log(task_id, 'ERROR',
                                    f'扫描器 {scanner.name} 执行异常: {str(e)}\n{error_detail}')

            # 再次检查取消标志
            if cancel_flag.is_set():
                storage.update_task_status(task_id, 'cancelled')
                return

            # 所有扫描器执行完毕
            storage.update_task_progress(task_id, 100, None)
            storage.update_task_status(task_id, 'completed')
            storage.add_log(task_id, 'INFO',
                            f'任务执行完毕，共发现 {len(all_findings)} 个问题')

        except Exception as e:
            error_detail = traceback.format_exc()
            storage.add_log(task_id, 'ERROR', f'任务执行异常: {str(e)}\n{error_detail}')
            storage.update_task_status(task_id, 'failed', error_msg=str(e))

        finally:
            # 清理取消标志
            with self._lock:
                self._cancel_flags.pop(task_id, None)

    def _log_callback(self, task_id, level, message):
        """
        日志回调函数，传递给各扫描器使用

        参数:
            task_id: 任务ID
            level: 日志级别
            message: 日志消息
        """
        storage.add_log(task_id, level, message)

    def shutdown(self, wait=True):
        """
        关闭任务管理器

        参数:
            wait: 是否等待所有任务完成
        """
        # 取消所有进行中的任务
        with self._lock:
            for flag in self._cancel_flags.values():
                flag.set()

        self._executor.shutdown(wait=wait)
