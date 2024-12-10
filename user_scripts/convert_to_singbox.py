#!/usr/bin/env python3
import yaml
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

def merge_rules(clash_rules: List[str]) -> Dict[str, List[str]]:
    """将相同类型的规则合并在一起"""
    rule_groups = defaultdict(list)
    
    for rule in clash_rules:
        parts = rule.split(',')
        rule_type = parts[0].lower()
        value = parts[1].strip()
        
        if rule_type == 'domain-suffix':
            rule_groups['domain_suffix'].append(value)
        elif rule_type == 'domain-keyword':
            rule_groups['domain_keyword'].append(value)
        elif rule_type == 'domain':
            rule_groups['domain'].append(value)
        elif rule_type in ['ip-cidr', 'ip-cidr6']:
            rule_groups['ip_cidr'].append(value)
        elif rule_type == 'geoip':
            rule_groups['geoip'].append(value)
    
    return dict(rule_groups)

def convert_clash_to_singbox(clash_rules: List[str]) -> Dict[str, Any]:
    """Convert Clash configuration to sing-box configuration."""
    merged_rules = merge_rules(clash_rules)
    rules = {}
    
    # 将每种类型的规则添加到相应的类别中
    for rule_type, values in merged_rules.items():
        if values:
            rules[rule_type] = sorted(values)  # 对值进行排序以保持一致性

    # 从环境变量获取 version，如果没有设置则使用默认值 2
    version = int(os.getenv('RULESET_VERSION', '2'))
    
    return {
        "version": version,
        "rules": rules
    }

def process_directory():
    """Process all YAML files in the Clash directory."""
    clash_dir = Path("rule/Clash")
    singbox_dir = Path("rule/Singbox")
    
    # 遍历所有yaml文件
    for yaml_file in clash_dir.rglob("*.y*ml"):
        relative_path = yaml_file.relative_to(clash_dir)
        
        # 创建对应的输出目录
        json_output = singbox_dir / relative_path.parent / relative_path.stem
        json_output.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with yaml_file.open('r', encoding='utf-8') as f:
                clash_config = yaml.safe_load(f)
            
            if not clash_config or "payload" not in clash_config:
                print(f"Warning: No payload found in {yaml_file}")
                continue
                
            # 转换规则并保存为 JSON
            singbox_config = convert_clash_to_singbox(clash_config["payload"])
            json_file = f"{json_output}.json"
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, ensure_ascii=False, indent=2)
            
            # 使用 sing-box 命令生成 SRS 文件
            srs_file = f"{json_output}.srs"
            result = subprocess.run(
                ["sing-box", "rule-set", "compile", "--output", srs_file, json_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"Processed {yaml_file} -> {json_output}.json and {json_output}.srs")
            else:
                print(f"Error generating SRS for {yaml_file}: {result.stderr}")
            
        except Exception as e:
            print(f"Error processing {yaml_file}: {e}")

if __name__ == "__main__":
    process_directory()
