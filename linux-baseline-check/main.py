#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import argparse
from core.checker import SecurityBaselineChecker

def main():
    parser = argparse.ArgumentParser(description='Linux系统安全基线检查工具 v3.0')
    parser.add_argument('-o', '--output', default='security_reports', help='报告输出目录')
    parser.add_argument('--skip', help='跳过检查项(逗号分隔，如:账户安全,SSH安全)')
    parser.add_argument('--check-suid', action='store_true', help='执行完整SUID/SGID检查')
    parser.add_argument('--check-world-writable', action='store_true', help='检查全局可写文件')
    parser.add_argument('--version', action='store_true', help='显示版本')

    args = parser.parse_args()

    if args.version:
        print("Linux系统安全基线检查工具 v3.0 - 综合增强版 (2025-12-05)")
        return

    if os.geteuid() != 0:
        print("[!] 警告: 建议以 root 权限运行以获取完整检查结果")
        if input("是否继续? (y/N): ").lower() != 'y':
            sys.exit(1)

    checker = SecurityBaselineChecker(args)
    exit_code = checker.run_all_checks()
    sys.exit(exit_code)

if __name__ == '__main__':
    main()