import os
import sys
import datetime
from typing import Dict, Any
from utils.host_collector import collect_host_info
from utils.command_runner import run_command
from utils.common import COMPLIANCE_MAPPING, COMMON_SUID_FILES, RISK_LEVELS
from reporters.json_reporter import generate_json_report
from reporters.text_reporter import generate_text_report
from reporters.csv_reporter import generate_csv_report
from reporters.html_reporter import generate_html_report

# 导入所有检查模块
from modules.account_security import check_account_security
from modules.ssh_security import check_ssh_security
from modules.file_permissions import check_file_permissions
from modules.services import check_services
from modules.firewall import check_firewall
from modules.system_updates import check_system_updates
from modules.audit_logging import check_audit_logging
from modules.kernel_security import check_kernel_security
from modules.system_hardening import check_system_hardening
from modules.malware_protection import check_malware_protection
from modules.sudo_security import check_sudo_security
from modules.network_security import check_network_security


class SecurityBaselineChecker:
    def __init__(self, args):
        self.args = args
        self.results = []
        self.stats = {'total': 0, 'passed': 0, 'failed': 0, 'warning': 0, 'critical': 0}
        self.host_info = {}
        self.compliance_mapping = COMPLIANCE_MAPPING
        self.risk_levels = RISK_LEVELS
        self.common_suid_files = COMMON_SUID_FILES

    def run_command(self, cmd: str, capture_output: bool = True):
        return run_command(cmd, capture_output)

    def add_result(self, category: str, item: str, status: str, details: str, risk: str = 'medium', standards: dict = None):
        result = {
            'id': len(self.results) + 1,
            'category': category,
            'item': item,
            'status': status,
            'details': details,
            'risk': risk,
            'timestamp': datetime.datetime.now().isoformat(),
            'standards': standards or {}
        }
        self.results.append(result)
        self.stats['total'] += 1
        if status == 'PASS':
            self.stats['passed'] += 1
        elif status == 'FAIL':
            if risk == 'critical':
                self.stats['critical'] += 1
            self.stats['failed'] += 1
        elif status == 'WARNING':
            self.stats['warning'] += 1

    def collect_host_info(self):
        self.host_info = collect_host_info()
        print(f"[+] 主机名: {self.host_info.get('hostname', 'Unknown')}")

    def run_all_checks(self):
        print("\n🔍 Linux系统安全基线检查工具 v3.0 - 开始检查...\n")
        self.collect_host_info()

        # 所有检查项列表
        checks = [
            ("账户安全", check_account_security),
            ("SSH安全", check_ssh_security),
            ("文件权限", check_file_permissions),
            ("服务安全", check_services),
            ("防火墙", check_firewall),
            ("系统更新", check_system_updates),
            ("审计日志", check_audit_logging),
            ("内核安全", check_kernel_security),
            ("系统加固", check_system_hardening),
            ("恶意软件防护", check_malware_protection),
            ("Sudo安全", check_sudo_security),
            ("网络安全", check_network_security),
        ]

        skip_list = set()
        if self.args.skip:
            skip_list = {s.strip() for s in self.args.skip.split(',')}

        for name, func in checks:
            if name in skip_list:
                print(f"[-] 跳过检查: {name}")
                continue
            print(f"[*] 正在检查: {name}")
            try:
                func(self)
            except Exception as e:
                self.add_result(name, "检查异常", "FAIL", f"模块执行出错: {str(e)}", "high")

        self._print_summary()
        self._generate_reports()
        return 2 if self.stats['critical'] > 0 else (1 if self.stats['failed'] > 0 else 0)

    def _print_summary(self):
        print("\n✅ 检查完成！摘要:")
        print(f"  总计: {self.stats['total']}")
        print(f"  通过: {self.stats['passed']}")
        print(f"  警告: {self.stats['warning']}")
        print(f"  失败: {self.stats['failed']} (其中严重: {self.stats['critical']})")

    def _generate_reports(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.args.output
        os.makedirs(report_dir, exist_ok=True)

        metadata = {
            'tool_version': '3.0',
            'generated_at': datetime.datetime.now().isoformat(),
            'command_line': ' '.join(sys.argv)
        }

        generate_json_report(report_dir, timestamp, metadata, self.host_info, self.stats, self.results)
        generate_text_report(report_dir, timestamp, self.host_info, self.stats, self.results)
        generate_csv_report(report_dir, timestamp, self.results)
        generate_html_report(report_dir, timestamp, self.host_info, self.stats, self.results)

        print(f"\n📄 报告已生成至: {report_dir}/")