"""
YAML 规则加载器
从 YAML 文件加载安全扫描规则，编译正则表达式
"""
import os
import re
import logging
import yaml

logger = logging.getLogger(__name__)


def load_rules(yaml_path):
    """
    加载 YAML 规则文件，返回规则列表

    参数:
        yaml_path: YAML 文件路径
    返回:
        规则字典列表，加载失败返回空列表
    """
    if not os.path.isfile(yaml_path):
        logger.warning(f'规则文件不存在: {yaml_path}')
        return []

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)
        if not isinstance(rules, list):
            logger.warning(f'规则文件格式错误（应为列表）: {yaml_path}')
            return []
        return rules
    except yaml.YAMLError as e:
        logger.warning(f'YAML 解析失败: {yaml_path}, 错误: {e}')
        return []
    except Exception as e:
        logger.warning(f'规则文件加载失败: {yaml_path}, 错误: {e}')
        return []


def compile_patterns(rules):
    """
    将规则中的 pattern 字符串编译为 re.compile 对象

    参数:
        rules: 从 YAML 加载的规则列表
    返回:
        编译后的规则列表（每条规则增加 compiled_pattern 字段）
    """
    compiled = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        pattern_str = rule.get('pattern')
        if not pattern_str:
            logger.warning(f'规则缺少 pattern 字段: {rule.get("name", "未知")}')
            continue
        try:
            compiled_pattern = re.compile(pattern_str, re.IGNORECASE if rule.get('case_insensitive') else 0)
            compiled_rule = dict(rule)
            compiled_rule['compiled_pattern'] = compiled_pattern
            compiled.append(compiled_rule)
        except re.error as e:
            logger.warning(f'正则编译失败: {rule.get("name", "未知")}, pattern={pattern_str}, 错误: {e}')
    return compiled
