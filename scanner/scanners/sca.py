"""
SCA（Software Composition Analysis）依赖漏洞扫描器
扫描项目依赖文件（Python/Node.js/Go/Java），通过 OSV API 查询已知漏洞
如果 API 不可用，则 fallback 到本地 pip-audit
"""

import os
import re
import json
import subprocess
import requests
from .base import BaseScanner


class SCAScanner(BaseScanner):
    name = "SCA 依赖漏洞扫描"
    description = "扫描项目依赖的已知安全漏洞（支持 Python/Node.js/Go/Java，基于 OSV 数据库）"

    # OSV API 地址
    OSV_API_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"
    # 请求超时（秒）
    REQUEST_TIMEOUT = 10

    def run(self, target_path=None, target_url=None, task_id=None,
            cancel_flag=None, log_fn=None):
        """
        执行依赖漏洞扫描

        扫描流程:
        1. 查找目标路径下所有依赖文件（requirements.txt/package.json/go.sum/pom.xml）
        2. 解析每个文件中的依赖包名和版本
        3. 调用 OSV 批量 API 查询漏洞信息
        4. API 不可用时 fallback 到 pip-audit
        """
        findings = []

        if not target_path:
            self._log(log_fn, task_id, 'WARN', 'SCA 扫描需要目标路径，已跳过')
            return findings

        if not os.path.isdir(target_path):
            self._log(log_fn, task_id, 'ERROR', f'目标路径不存在: {target_path}')
            return findings

        self._log(log_fn, task_id, 'INFO', f'开始 SCA 依赖漏洞扫描，目标路径: {target_path}')

        all_deps = []

        # 1. Python requirements.txt
        req_files = self._find_requirements(target_path)
        if req_files:
            self._log(log_fn, task_id, 'INFO', f'找到 {len(req_files)} 个 requirements.txt 文件')
            for req_file in req_files:
                if self._is_cancelled(cancel_flag):
                    return findings
                should_scan, file_hash = self._should_scan_file(req_file, 'sca')
                if not should_scan:
                    self._log(log_fn, task_id, 'INFO', f'文件未变更，跳过: {req_file}')
                    continue
                deps = self._parse_requirements(req_file)
                for dep in deps:
                    dep['source_file'] = req_file
                    dep['ecosystem'] = 'PyPI'
                all_deps.extend(deps)
                if file_hash:
                    try:
                        from .. import storage as _storage
                        _storage.save_file_hash(req_file, file_hash, 'sca')
                    except Exception:
                        pass

        # 2. Node.js package-lock.json / package.json
        pkg_files = self._find_package_files(target_path)
        if pkg_files:
            self._log(log_fn, task_id, 'INFO', f'找到 {len(pkg_files)} 个 Node.js 依赖文件')
            for pkg_file in pkg_files:
                if self._is_cancelled(cancel_flag):
                    return findings
                should_scan, file_hash = self._should_scan_file(pkg_file, 'sca')
                if not should_scan:
                    self._log(log_fn, task_id, 'INFO', f'文件未变更，跳过: {pkg_file}')
                    continue
                deps = self._parse_package_lock(pkg_file)
                for dep in deps:
                    dep['source_file'] = pkg_file
                all_deps.extend(deps)
                if file_hash:
                    try:
                        from .. import storage as _storage
                        _storage.save_file_hash(pkg_file, file_hash, 'sca')
                    except Exception:
                        pass

        # 3. Go go.sum
        go_files = self._find_go_sum(target_path)
        if go_files:
            self._log(log_fn, task_id, 'INFO', f'找到 {len(go_files)} 个 go.sum 文件')
            for go_file in go_files:
                if self._is_cancelled(cancel_flag):
                    return findings
                should_scan, file_hash = self._should_scan_file(go_file, 'sca')
                if not should_scan:
                    self._log(log_fn, task_id, 'INFO', f'文件未变更，跳过: {go_file}')
                    continue
                deps = self._parse_go_sum(go_file)
                for dep in deps:
                    dep['source_file'] = go_file
                all_deps.extend(deps)
                if file_hash:
                    try:
                        from .. import storage as _storage
                        _storage.save_file_hash(go_file, file_hash, 'sca')
                    except Exception:
                        pass

        # 4. Maven pom.xml
        pom_files = self._find_pom_xml(target_path)
        if pom_files:
            self._log(log_fn, task_id, 'INFO', f'找到 {len(pom_files)} 个 pom.xml 文件')
            for pom_file in pom_files:
                if self._is_cancelled(cancel_flag):
                    return findings
                should_scan, file_hash = self._should_scan_file(pom_file, 'sca')
                if not should_scan:
                    self._log(log_fn, task_id, 'INFO', f'文件未变更，跳过: {pom_file}')
                    continue
                deps = self._parse_pom_xml(pom_file)
                for dep in deps:
                    dep['source_file'] = pom_file
                all_deps.extend(deps)
                if file_hash:
                    try:
                        from .. import storage as _storage
                        _storage.save_file_hash(pom_file, file_hash, 'sca')
                    except Exception:
                        pass

        if not all_deps:
            self._log(log_fn, task_id, 'INFO', '未找到任何依赖文件')
            return findings

        self._log(log_fn, task_id, 'INFO', f'共解析到 {len(all_deps)} 个依赖包，开始查询漏洞')

        # 优先使用 OSV 批量查询 API
        osv_success = False
        try:
            findings = self._query_osv_batch(all_deps, task_id, cancel_flag, log_fn)
            osv_success = True
            self._log(log_fn, task_id, 'INFO', f'OSV API 查询完成，发现 {len(findings)} 个漏洞')
        except Exception as e:
            self._log(log_fn, task_id, 'WARN', f'OSV API 查询失败: {str(e)}，尝试 fallback 到 pip-audit')

        # OSV 不可用则 fallback 到 pip-audit（仅限 Python 依赖）
        if not osv_success:
            try:
                findings = self._fallback_pip_audit(target_path, task_id, log_fn)
                self._log(log_fn, task_id, 'INFO', f'pip-audit 扫描完成，发现 {len(findings)} 个漏洞')
            except Exception as e:
                self._log(log_fn, task_id, 'ERROR', f'pip-audit 也失败了: {str(e)}')

        return findings

    def _query_osv_batch(self, deps, task_id, cancel_flag, log_fn):
        """使用 OSV 批量查询 API，每批最多 1000 个"""
        findings = []
        batch_size = 1000

        for i in range(0, len(deps), batch_size):
            if self._is_cancelled(cancel_flag):
                break

            batch = deps[i:i + batch_size]
            queries = []
            for dep in batch:
                ecosystem = dep.get('ecosystem', 'PyPI')
                queries.append({
                    "package": {
                        "name": dep['name'],
                        "ecosystem": ecosystem
                    },
                    "version": dep['version']
                })

            try:
                resp = requests.post(
                    self.OSV_BATCH_API_URL,
                    json={"queries": queries},
                    timeout=30
                )
                resp.raise_for_status()
                data = resp.json()

                results = data.get('results', [])
                for idx, result in enumerate(results):
                    vulns = result.get('vulns', [])
                    if not vulns:
                        continue
                    dep = batch[idx]
                    pkg_name = dep['name']
                    version = dep['version']
                    source_file = dep.get('source_file', '')

                    self._log(log_fn, task_id, 'WARN',
                              f'依赖 {pkg_name}=={version} 发现 {len(vulns)} 个漏洞')

                    for vuln in vulns:
                        severity = self._extract_severity(vuln)
                        cve = self._extract_cve(vuln)
                        cvss_score = self._extract_cvss(vuln)

                        finding = {
                            'scanner': 'sca',
                            'severity': severity,
                            'category': '依赖漏洞',
                            'title': f'{pkg_name}=={version} 存在已知漏洞 ({vuln.get("id", "未知")})',
                            'description': vuln.get('summary', vuln.get('details', '无详细描述')),
                            'location': source_file,
                            'remediation': self._build_remediation(vuln, pkg_name),
                            'cve': cve,
                            'cvss_score': cvss_score,
                            'raw_data': {
                                'vuln_id': vuln.get('id'),
                                'package': pkg_name,
                                'version': version,
                                'ecosystem': dep.get('ecosystem', 'PyPI'),
                                'aliases': vuln.get('aliases', []),
                            }
                        }
                        findings.append(finding)

            except requests.RequestException as e:
                raise RuntimeError(f'OSV 批量 API 请求失败: {str(e)}')

        return findings

    def _find_requirements(self, target_path):
        """
        递归查找目标路径下的所有 requirements.txt 文件
        跳过 .git, __pycache__, node_modules, .venv 等目录
        """
        skip_dirs = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', '.tox', '.eggs'}
        req_files = []

        for root, dirs, files in os.walk(target_path):
            # 过滤掉需要跳过的目录
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname == 'requirements.txt' or fname.startswith('requirements') and fname.endswith('.txt'):
                    req_files.append(os.path.join(root, fname))

        return req_files

    def _parse_requirements(self, filepath):
        """
        解析 requirements.txt 文件，提取包名和版本号

        支持的格式:
        - package==1.0.0
        - package>=1.0.0
        - package~=1.0.0
        - package（不含版本号的将被跳过）
        """
        deps = []
        # 匹配 包名==版本 或 包名>=版本 等格式
        pattern = re.compile(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([a-zA-Z0-9\.\-\*]+)')

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # 跳过注释和空行
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    match = pattern.match(line)
                    if match:
                        pkg_name = match.group(1)
                        version = match.group(2)
                        deps.append({
                            'name': pkg_name,
                            'version': version,
                        })
        except (IOError, OSError):
            pass

        return deps

    def _find_package_files(self, target_path):
        """查找 package-lock.json 或 package.json"""
        skip_dirs = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', '.tox', '.eggs'}
        pkg_files = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname in ('package-lock.json', 'package.json'):
                    pkg_files.append(os.path.join(root, fname))
        return pkg_files

    def _parse_package_lock(self, filepath):
        """解析 Node.js package-lock.json 或 package.json，提取依赖名和版本"""
        deps = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            return deps

        basename = os.path.basename(filepath)
        if basename == 'package-lock.json':
            # lockfileVersion 2/3
            packages = data.get('packages', {})
            if packages:
                for pkg_path, info in packages.items():
                    if not pkg_path:  # root package
                        continue
                    # Extract package name from path (node_modules/xxx or node_modules/@scope/xxx)
                    name = pkg_path.replace('node_modules/', '').split('node_modules/')[-1]
                    version = info.get('version', '')
                    if name and version:
                        deps.append({'name': name, 'version': version, 'ecosystem': 'npm'})
            else:
                # lockfileVersion 1
                dependencies = data.get('dependencies', {})
                for name, info in dependencies.items():
                    version = info.get('version', '') if isinstance(info, dict) else ''
                    if name and version:
                        deps.append({'name': name, 'version': version, 'ecosystem': 'npm'})
        else:
            # package.json - get from dependencies + devDependencies
            for dep_key in ('dependencies', 'devDependencies'):
                dep_dict = data.get(dep_key, {})
                for name, ver_spec in dep_dict.items():
                    # Clean version spec: ^1.0.0 -> 1.0.0, ~2.0.0 -> 2.0.0
                    version = re.sub(r'^[\^~>=<]+', '', str(ver_spec)).strip()
                    if name and version and version != '*':
                        deps.append({'name': name, 'version': version, 'ecosystem': 'npm'})
        return deps

    def _find_go_sum(self, target_path):
        """查找 go.sum 文件"""
        skip_dirs = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'vendor'}
        go_files = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname == 'go.sum':
                    go_files.append(os.path.join(root, fname))
        return go_files

    def _parse_go_sum(self, filepath):
        """解析 go.sum 文件，提取模块名和版本"""
        deps = []
        seen = set()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].split('/')[0]  # Remove /go.mod suffix
                        version = version.lstrip('v')  # Remove v prefix
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            deps.append({'name': name, 'version': version, 'ecosystem': 'Go'})
        except (IOError, OSError):
            pass
        return deps

    def _find_pom_xml(self, target_path):
        """查找 pom.xml 文件"""
        skip_dirs = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'target', '.m2'}
        pom_files = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname == 'pom.xml':
                    pom_files.append(os.path.join(root, fname))
        return pom_files

    def _parse_pom_xml(self, filepath):
        """解析 Maven pom.xml 文件，提取依赖坐标"""
        deps = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(filepath)
            root = tree.getroot()
            # Handle namespace
            ns = ''
            if root.tag.startswith('{'):
                ns = root.tag.split('}')[0] + '}'

            for dep in root.iter(f'{ns}dependency'):
                group_id = dep.find(f'{ns}groupId')
                artifact_id = dep.find(f'{ns}artifactId')
                version_elem = dep.find(f'{ns}version')
                if group_id is not None and artifact_id is not None and version_elem is not None:
                    group = group_id.text or ''
                    artifact = artifact_id.text or ''
                    version = version_elem.text or ''
                    # Skip property references like ${xxx}
                    if version and not version.startswith('${') and group and artifact:
                        name = f'{group}:{artifact}'
                        deps.append({'name': name, 'version': version, 'ecosystem': 'Maven'})
        except Exception:
            pass
        return deps

    def _query_osv(self, deps, task_id, cancel_flag, log_fn):
        """
        使用 OSV API 批量查询依赖包漏洞

        每个包单独发送一个 POST 请求到 OSV API
        """
        findings = []

        for dep in deps:
            if self._is_cancelled(cancel_flag):
                break

            pkg_name = dep['name']
            version = dep['version']
            source_file = dep.get('source_file', '')

            try:
                payload = {
                    "package": {
                        "name": pkg_name,
                        "ecosystem": "PyPI"
                    },
                    "version": version
                }

                resp = requests.post(
                    self.OSV_API_URL,
                    json=payload,
                    timeout=self.REQUEST_TIMEOUT
                )
                resp.raise_for_status()
                data = resp.json()

                vulns = data.get('vulns', [])
                if vulns:
                    self._log(log_fn, task_id, 'WARN',
                              f'依赖 {pkg_name}=={version} 发现 {len(vulns)} 个漏洞')

                for vuln in vulns:
                    # 从漏洞信息中提取严重等级
                    severity = self._extract_severity(vuln)
                    # 提取 CVE 编号
                    cve = self._extract_cve(vuln)
                    # 提取 CVSS 分数
                    cvss_score = self._extract_cvss(vuln)

                    finding = {
                        'scanner': 'sca',
                        'severity': severity,
                        'category': '依赖漏洞',
                        'title': f'{pkg_name}=={version} 存在已知漏洞 ({vuln.get("id", "未知")})',
                        'description': vuln.get('summary', vuln.get('details', '无详细描述')),
                        'location': source_file,
                        'remediation': self._build_remediation(vuln, pkg_name),
                        'cve': cve,
                        'cvss_score': cvss_score,
                        'raw_data': {
                            'vuln_id': vuln.get('id'),
                            'package': pkg_name,
                            'version': version,
                            'aliases': vuln.get('aliases', []),
                        }
                    }
                    findings.append(finding)

            except requests.RequestException as e:
                # 单个包查询失败时抛出异常，让外层走 fallback 逻辑
                raise RuntimeError(f'OSV API 请求失败 ({pkg_name}): {str(e)}')

        return findings

    def _extract_severity(self, vuln):
        """从 OSV 漏洞信息中提取严重等级"""
        # 尝试从 database_specific 或 severity 字段获取
        severity_list = vuln.get('severity', [])
        for sev in severity_list:
            score_str = sev.get('score', '')
            # CVSS v3 的评分字符串中提取分数
            if 'CVSS' in sev.get('type', ''):
                try:
                    # 尝试解析 CVSS 向量中的分数
                    parts = score_str.split('/')
                    for part in parts:
                        try:
                            score = float(part)
                            if score >= 9.0:
                                return 'CRITICAL'
                            elif score >= 7.0:
                                return 'HIGH'
                            elif score >= 4.0:
                                return 'MEDIUM'
                            else:
                                return 'LOW'
                        except ValueError:
                            continue
                except Exception:
                    pass

        # 如果没有 CVSS 信息，根据漏洞关键字猜测
        details = (vuln.get('summary', '') + vuln.get('details', '')).lower()
        if any(kw in details for kw in ['remote code execution', 'rce', 'critical', 'arbitrary code']):
            return 'CRITICAL'
        elif any(kw in details for kw in ['sql injection', 'xss', 'authentication bypass']):
            return 'HIGH'
        elif any(kw in details for kw in ['denial of service', 'dos', 'information disclosure']):
            return 'MEDIUM'

        return 'MEDIUM'  # 默认中等

    def _extract_cve(self, vuln):
        """从 OSV 漏洞信息中提取 CVE 编号"""
        # 优先从 aliases 中找 CVE
        aliases = vuln.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                return alias
        # 漏洞 ID 本身可能是 CVE
        vuln_id = vuln.get('id', '')
        if vuln_id.startswith('CVE-'):
            return vuln_id
        return ''

    def _extract_cvss(self, vuln):
        """从 OSV 漏洞信息中提取 CVSS 评分"""
        severity_list = vuln.get('severity', [])
        for sev in severity_list:
            score_str = sev.get('score', '')
            if 'CVSS' in sev.get('type', ''):
                # 尝试从向量字符串中提取数值
                parts = score_str.split('/')
                for part in parts:
                    try:
                        score = float(part)
                        if 0 <= score <= 10:
                            return score
                    except ValueError:
                        continue
        return None

    def _build_remediation(self, vuln, pkg_name):
        """构建修复建议"""
        # 检查漏洞信息中是否有修复版本
        affected = vuln.get('affected', [])
        for aff in affected:
            ranges_list = aff.get('ranges', [])
            for r in ranges_list:
                events = r.get('events', [])
                for event in events:
                    fixed = event.get('fixed')
                    if fixed:
                        return f'升级 {pkg_name} 到版本 {fixed} 或更高版本'

        return f'请检查 {pkg_name} 的最新版本并升级，或查阅官方安全公告'

    def _fallback_pip_audit(self, target_path, task_id, log_fn):
        """
        使用 pip-audit 作为 fallback 方案

        通过 subprocess 调用 pip-audit 并解析 JSON 输出
        """
        findings = []
        self._log(log_fn, task_id, 'INFO', '使用 pip-audit 进行 fallback 扫描')

        # 查找 requirements.txt 进行扫描
        req_files = self._find_requirements(target_path)

        for req_file in req_files:
            try:
                # 调用 pip-audit，以 JSON 格式输出
                result = subprocess.run(
                    ['pip-audit', '-r', req_file, '--format', 'json', '--progress-spinner', 'off'],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=target_path
                )

                # pip-audit 在发现漏洞时退出码为 1
                output = result.stdout
                if not output:
                    output = result.stderr

                try:
                    audit_data = json.loads(output)
                except json.JSONDecodeError:
                    self._log(log_fn, task_id, 'WARN',
                              f'pip-audit 输出解析失败: {output[:200]}')
                    continue

                # 解析 pip-audit 的 JSON 输出
                dependencies = audit_data.get('dependencies', [])
                for dep in dependencies:
                    vulns = dep.get('vulns', [])
                    if not vulns:
                        continue

                    pkg_name = dep.get('name', '未知')
                    version = dep.get('version', '未知')

                    for vuln in vulns:
                        vuln_id = vuln.get('id', '未知')
                        fix_versions = vuln.get('fix_versions', [])
                        description = vuln.get('description', '无详细描述')

                        # 确定严重等级
                        aliases = vuln.get('aliases', [])
                        severity = 'MEDIUM'  # 默认中等

                        remediation = f'请升级 {pkg_name}'
                        if fix_versions:
                            remediation = f'升级 {pkg_name} 到版本 {fix_versions[0]} 或更高'

                        cve = ''
                        for alias in aliases:
                            if alias.startswith('CVE-'):
                                cve = alias
                                break

                        finding = {
                            'scanner': 'sca',
                            'severity': severity,
                            'category': '依赖漏洞',
                            'title': f'{pkg_name}=={version} 存在已知漏洞 ({vuln_id})',
                            'description': description[:500] if description else '无详细描述',
                            'location': req_file,
                            'remediation': remediation,
                            'cve': cve,
                            'cvss_score': None,
                            'raw_data': {
                                'vuln_id': vuln_id,
                                'package': pkg_name,
                                'version': version,
                                'fix_versions': fix_versions,
                            }
                        }
                        findings.append(finding)

            except FileNotFoundError:
                self._log(log_fn, task_id, 'ERROR', 'pip-audit 未安装，请运行: pip install pip-audit')
                break
            except subprocess.TimeoutExpired:
                self._log(log_fn, task_id, 'WARN', f'pip-audit 扫描超时: {req_file}')
            except Exception as e:
                self._log(log_fn, task_id, 'ERROR', f'pip-audit 扫描异常: {str(e)}')

        return findings
