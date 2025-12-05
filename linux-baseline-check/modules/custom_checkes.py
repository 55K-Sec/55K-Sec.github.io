import yaml
import os

def check_custom_rules(checker):
    if os.path.exists('custom_rules.yaml'):
        with open('custom_rules.yaml', 'r') as f:
            rules = yaml.safe_load(f)
        for rule in rules:
            code, out, _ = checker.run_command(rule['command'])
            status = 'PASS' if code == 0 else 'FAIL'
            checker.add_result(
                rule['category'], 
                rule['item'], 
                status, 
                out.strip() or f"命令执行结果: {'成功' if status == 'PASS' else '失败'}",
                rule.get('risk', 'medium')
            )
    else:
        checker.add_result('自定义检查', '规则文件', 'INFO', '未找到custom_rules.yaml', 'info')
