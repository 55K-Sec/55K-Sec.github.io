#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux系统安全基线检查工具 v3.0 - 综合增强版
=======================================

版本：v3.0
更新日期：2025年12月05日
适用系统：RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+
维护团队：55K-学安全
联系方式：通过"公众号、博客留言"

更新说明：
--------
v3.0 (2025-12-05)
  - 整合v2.1和v1.0版本所有优点
  - 新增12个增强检查功能（来自v2.1）
  - 优化HTML报告样式（采用v1.0的美观设计）
  - 增强检查逻辑和性能优化
  - 统一代码结构和命名规范

新增功能：
--------
1. 账户登录失败锁定策略检查
2. SSH公钥认证和配置验证检查
3. 全局可写文件深度检查
4. Sudo语法验证和近期使用记录
5. 明文高危服务专项检查
6. ICMP重定向和ARP安全参数检查
7. 隐藏进程和可疑进程检查
8. 日志轮转配置检查
9. 可疑计划任务检查
10. 完整SUID/SGID文件分析
11. 网络监听端口进程关联检查
12. 系统最后更新时间检查

架构说明：
--------
本工具采用模块化设计，包含以下主要组件：
1. SecurityBaselineChecker: 主检查器类
2. 检查模块: 12个安全检查类别
3. 报告模块: JSON/文本/CSV/HTML四种格式报告生成
4. 工具模块: 命令执行、结果收集、风险评估
5. 修复模块: 自动生成修复命令和建议

设计原则：
--------
1. 模块化: 每个检查功能独立，便于扩展和维护
2. 可配置: 支持命令行参数，可定制检查项
3. 安全性: 需root权限执行，但会进行权限检查
4. 兼容性: 支持主流Linux发行版
5. 性能优化: 提供快速检查模式，智能性能控制
6. 用户体验: 美观的报告输出，清晰的修复建议
"""

import os
import sys
import re
import json
import subprocess
import platform
import argparse
import datetime
import socket
import stat
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import hashlib
import csv
import collections

class SecurityBaselineChecker:
    """主安全检查器类"""
    
    def __init__(self, args):
        """初始化安全检查器"""
        self.args = args
        self.results = []
        self.stats = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'warning': 0,
            'critical': 0
        }
        self.host_info = {}
        self.compliance_mapping = self.load_compliance_mapping()
        self.risk_levels = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        self.common_suid_files = [
            '/bin/su', '/bin/ping', '/bin/mount', '/bin/umount',
            '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh',
            '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp',
            '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/chage',
            '/usr/bin/at', '/usr/bin/crontab', '/usr/bin/wall'
        ]
    
    def load_compliance_mapping(self):
        """加载合规性标准映射"""
        return {
            'account_policy': {
                'cis': ['5.2.1', '5.3.1', '5.4.1'],
                'stig': ['V-719', 'V-720'],
                'dengbao': ['8.1.4.2'],
                'iso27001': ['A.9.2.1']
            },
            'ssh_security': {
                'cis': ['5.2.8', '5.2.9'],
                'stig': ['V-722'],
                'dengbao': ['8.1.4.5'],
                'iso27001': ['A.13.1.1']
            },
            'file_permissions': {
                'cis': ['6.1.2', '6.1.3'],
                'stig': ['V-779', 'V-780'],
                'dengbao': ['8.1.4.3'],
                'iso27001': ['A.12.1.1']
            },
            'firewall': {
                'cis': ['3.5.1', '3.5.2'],
                'stig': ['V-722', 'V-723'],
                'dengbao': ['8.1.5.1'],
                'iso27001': ['A.13.1.3']
            },
            'audit': {
                'cis': ['4.1.1', '4.1.2'],
                'stig': ['V-810', 'V-811'],
                'dengbao': ['8.1.7.1'],
                'iso27001': ['A.12.4.1']
            }
        }
    
    def run_command(self, cmd: str, capture_output: bool = True) -> Tuple[int, str, str]:
        """执行系统命令并返回结果"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=capture_output,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "命令超时"
        except Exception as e:
            return -1, "", str(e)
    
    def add_result(self, category: str, item: str, status: str, 
                   details: str, risk: str = 'medium', standards: dict = None):
        """添加检查结果到结果列表"""
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
        """收集主机系统信息"""
        print("[*] 收集系统信息...")
        
        self.host_info = {
            'hostname': socket.gethostname(),
            'timestamp': datetime.datetime.now().isoformat(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
        
        # 获取IP地址
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.host_info['ip_address'] = s.getsockname()[0]
            s.close()
        except:
            self.host_info['ip_address'] = "Unknown"
        
        # 获取发行版信息
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        self.host_info['os_name'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION_ID='):
                        self.host_info['os_version'] = line.split('=')[1].strip().strip('"')
        
        # 获取内核版本
        code, output, _ = self.run_command("uname -r")
        if code == 0:
            self.host_info['kernel'] = output.strip()
        
        # 获取系统运行时间
        code, output, _ = self.run_command("uptime -p")
        if code == 0:
            self.host_info['uptime'] = output.strip()
        
        # 显示收集的信息
        print("[+] 系统信息:")
        print(f"  主机名: {self.host_info['hostname']}")
        print(f"  IP地址: {self.host_info['ip_address']}")
        print(f"  操作系统: {self.host_info.get('os_name', 'Unknown')}")
        print(f"  内核版本: {self.host_info.get('kernel', 'Unknown')}")
        print(f"  运行时间: {self.host_info.get('uptime', 'Unknown')}")
    
    # ================ 账户安全检查模块 ================
    def check_account_security(self):
        """账户安全检查 - 增强版"""
        print("[*] 检查账户安全策略...")
        
        # 1. 检查空密码账户
        if os.path.exists('/etc/shadow'):
            with open('/etc/shadow', 'r') as f:
                empty_password_found = False
                locked_accounts_found = []
                
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) > 1:
                        password_field = parts[1]
                        
                        # 真正的空密码 - 密码字段为空
                        if password_field == '':
                            empty_password_found = True
                            self.add_result(
                                '账户安全', '空密码账户检查', 'FAIL',
                                f"发现真正空密码账户: {parts[0]}",
                                'critical',
                                {'cis': ['5.4.2'], 'stig': ['V-719']}
                            )
                        # 被锁定的账户 - 密码字段为 !!、*、! 等
                        elif password_field in ['!!', '*', '!']:
                            locked_accounts_found.append(parts[0])
                        # 密码为"!"的变体，表示账户被锁定
                        elif password_field.startswith('!'):
                            locked_accounts_found.append(parts[0])
                
                if not empty_password_found:
                    self.add_result(
                        '账户安全', '空密码账户检查', 'PASS',
                        '未发现空密码账户',
                        'low'
                    )
                
                # 显示被锁定的系统账户信息
                if locked_accounts_found:
                    # 过滤出常见的系统账户
                    system_accounts = ['bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 
                                      'halt', 'mail', 'operator', 'games', 'ftp', 'nobody',
                                      'systemd-network', 'dbus', 'polkitd', 'sshd', 'postfix']
                    
                    locked_system_accounts = []
                    locked_user_accounts = []
                    
                    for account in locked_accounts_found:
                        if account in system_accounts:
                            locked_system_accounts.append(account)
                        else:
                            locked_user_accounts.append(account)
                    
                    if locked_system_accounts:
                        self.add_result(
                            '账户安全', '系统账户锁定状态', 'INFO',
                            f'系统账户已锁定(正常): {", ".join(sorted(locked_system_accounts)[:5])}',
                            'info'
                        )
                    
                    if locked_user_accounts:
                        self.add_result(
                            '账户安全', '用户账户锁定状态', 'WARNING',
                            f'用户账户被锁定: {", ".join(sorted(locked_user_accounts)[:5])}',
                            'medium'
                        )
        
        # 2. 检查UID为0的非root账户
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                non_root_uid0_found = False
                for line in f:
                    parts = line.strip().split(':')
                    if parts[2] == '0' and parts[0] != 'root':
                        non_root_uid0_found = True
                        self.add_result(
                            '账户安全', 'UID为0账户检查', 'FAIL',
                            f"发现非root的UID为0账户: {parts[0]}",
                            'critical',
                            {'cis': ['5.4.3'], 'stig': ['V-720']}
                        )
                
                if not non_root_uid0_found:
                    self.add_result(
                        '账户安全', 'UID为0账户检查', 'PASS',
                        '除root外无其他UID为0的账户',
                        'low'
                    )
        
        # 3. 检查密码策略
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs', 'r') as f:
                content = f.read()
                pass_max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                pass_min_days = re.search(r'PASS_MIN_DAYS\s+(\d+)', content)
                pass_warn_age = re.search(r'PASS_WARN_AGE\s+(\d+)', content)
                
                if pass_max_days:
                    days = int(pass_max_days.group(1))
                    if days <= 90:
                        self.add_result(
                            '账户安全', '密码最长有效期', 'PASS',
                            f'密码最长有效期设置合理: {days}天',
                            'low'
                        )
                    else:
                        self.add_result(
                            '账户安全', '密码最长有效期', 'FAIL',
                            f'密码最长有效期过长: {days}天 (建议≤90天)',
                            'medium',
                            {'cis': ['5.4.1.1'], 'dengbao': ['8.1.4.2']}
                        )
                
                if pass_min_days:
                    days = int(pass_min_days.group(1))
                    if days >= 1:
                        self.add_result(
                            '账户安全', '密码最短有效期', 'PASS',
                            f'密码最短有效期设置合理: {days}天',
                            'low'
                        )
                    else:
                        self.add_result(
                            '账户安全', '密码最短有效期', 'FAIL',
                            f'密码最短有效期应≥1天',
                            'low'
                        )
        
        # 4. 检查密码强度配置
        if os.path.exists('/etc/pam.d/system-auth') or os.path.exists('/etc/pam.d/common-password'):
            if os.path.exists('/etc/security/pwquality.conf'):
                with open('/etc/security/pwquality.conf', 'r') as f:
                    content = f.read()
                    minlen = re.search(r'minlen\s*=\s*(\d+)', content)
                    if minlen and int(minlen.group(1)) >= 8:
                        self.add_result(
                            '账户安全', '密码最小长度', 'PASS',
                            f'密码最小长度设置合理: {minlen.group(1)}位',
                            'low'
                        )
                    else:
                        self.add_result(
                            '账户安全', '密码最小长度', 'FAIL',
                            '密码最小长度不足8位',
                            'medium'
                        )
        
        # 5. 检查账户登录失败锁定策略
        self.check_account_lockout_policy()
    
    def check_account_lockout_policy(self):
        """检查账户登录失败锁定策略"""
        print("[*] 检查账户登录失败锁定策略...")
        
        pam_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', 
                    '/etc/pam.d/common-auth']
        
        lockout_configured = False
        
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                with open(pam_file, 'r') as f:
                    content = f.read()
                    if re.search(r'pam_(tally2|faillock)', content):
                        lockout_configured = True
                        
                        if 'pam_tally2' in content:
                            deny_match = re.search(r'deny=(\d+)', content)
                            unlock_time_match = re.search(r'unlock_time=(\d+)', content)
                            
                            if deny_match and unlock_time_match:
                                self.add_result(
                                    '账户安全', '登录失败锁定策略', 'PASS',
                                    f'已配置登录失败锁定: 失败{deny_match.group(1)}次后锁定{unlock_time_match.group(1)}秒',
                                    'low'
                                )
                            else:
                                self.add_result(
                                    '账户安全', '登录失败锁定策略', 'WARNING',
                                    f'pam_tally2已配置但参数不完整',
                                    'medium'
                                )
                        elif 'pam_faillock' in content:
                            self.add_result(
                                '账户安全', '登录失败锁定策略', 'PASS',
                                '已配置pam_faillock登录失败锁定策略',
                                'low'
                            )
                        break
        
        if not lockout_configured:
            self.add_result(
                '账户安全', '登录失败锁定策略', 'FAIL',
                '未配置账户登录失败锁定策略，存在暴力破解风险',
                'high'
            )
    
    # ================ SSH安全检查模块 ================
    def check_ssh_security(self):
        """SSH安全配置检查 - 增强版"""
        print("[*] 检查SSH安全配置...")
        
        sshd_config = '/etc/ssh/sshd_config'
        if not os.path.exists(sshd_config):
            self.add_result('SSH安全', 'SSH配置文件', 'FAIL', 'SSH配置文件不存在', 'medium')
            return
        
        with open(sshd_config, 'r') as f:
            content = f.read()
        
        original_content = content
        content_lower = content.lower()
        
        # 1. 检查Protocol版本
        protocol_match = re.search(r'(?i)Protocol\s+(\d+)', original_content)
        if protocol_match:
            if protocol_match.group(1) == '2':
                self.add_result(
                    'SSH安全', 'SSH协议版本', 'PASS',
                    'SSH协议版本为2',
                    'low',
                    {'cis': ['5.2.1'], 'stig': ['V-722']}
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH协议版本', 'FAIL',
                    f'SSH协议版本不安全: {protocol_match.group(1)} (应使用2)',
                    'critical',
                    {'cis': ['5.2.1'], 'stig': ['V-722']}
                )
        else:
            self.add_result(
                'SSH安全', 'SSH协议版本', 'WARNING',
                '未明确配置SSH协议版本(默认使用2)',
                'low'
            )
        
        # 2. 检查Root登录配置
        root_login_match = re.search(r'(?i)PermitRootLogin\s+(yes|no|prohibit-password|without-password)', original_content)
        if root_login_match:
            value = root_login_match.group(1)
            if value.lower() in ['no', 'prohibit-password', 'without-password']:
                self.add_result(
                    'SSH安全', 'SSH Root登录', 'PASS',
                    f'SSH Root登录已限制: {value}',
                    'low',
                    {'cis': ['5.2.8'], 'dengbao': ['8.1.4.5']}
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH Root登录', 'FAIL',
                    f'SSH允许Root密码登录: {value}',
                    'high',
                    {'cis': ['5.2.8'], 'dengbao': ['8.1.4.5']}
                )
        else:
            self.add_result(
                'SSH安全', 'SSH Root登录', 'FAIL',
                '未配置SSH Root登录限制(默认允许)',
                'high'
            )
        
        # 3. 检查空密码登录配置
        empty_passwords = re.search(r'(?i)PermitEmptyPasswords\s+(yes|no)', original_content)
        if empty_passwords:
            if empty_passwords.group(1).lower() == 'no':
                self.add_result(
                    'SSH安全', 'SSH空密码限制', 'PASS',
                    'SSH禁止空密码登录',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH空密码限制', 'FAIL',
                    'SSH允许空密码登录',
                    'critical'
                )
        
        # 4. 检查密码认证配置
        password_auth = re.search(r'(?i)PasswordAuthentication\s+(yes|no)', original_content)
        if password_auth:
            if password_auth.group(1).lower() == 'no':
                self.add_result(
                    'SSH安全', 'SSH密码认证', 'PASS',
                    'SSH密码认证已禁用',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH密码认证', 'WARNING',
                    'SSH密码认证已启用(建议禁用，使用密钥认证)',
                    'medium'
                )
        
        # 5. 检查公钥认证配置
        pubkey_auth = re.search(r'(?i)PubkeyAuthentication\s+(yes|no)', original_content)
        if pubkey_auth:
            if pubkey_auth.group(1).lower() == 'yes':
                self.add_result(
                    'SSH安全', 'SSH公钥认证', 'PASS',
                    'SSH公钥认证已启用',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH公钥认证', 'FAIL',
                    'SSH公钥认证未启用',
                    'medium'
                )
        else:
            self.add_result(
                'SSH安全', 'SSH公钥认证', 'INFO',
                '未配置SSH公钥认证(默认启用)',
                'low'
            )
        
        # 6. 检查最大尝试次数
        max_auth_tries = re.search(r'(?i)MaxAuthTries\s+(\d+)', original_content)
        if max_auth_tries:
            tries = int(max_auth_tries.group(1))
            if tries <= 3:
                self.add_result(
                    'SSH安全', 'SSH最大尝试次数', 'PASS',
                    f'SSH最大认证尝试次数设置合理: {tries}',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH最大尝试次数', 'FAIL',
                    f'SSH最大认证尝试次数过多: {tries} (建议≤3)',
                    'medium'
                )
        
        # 7. 检查空闲超时配置
        client_alive = re.search(r'(?i)ClientAliveInterval\s+(\d+)', original_content)
        if client_alive:
            interval = int(client_alive.group(1))
            if interval <= 300:
                self.add_result(
                    'SSH安全', 'SSH空闲超时', 'PASS',
                    f'SSH空闲超时设置合理: {interval}秒',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH空闲超时', 'WARNING',
                    f'SSH空闲超时过长: {interval}秒 (建议≤300秒)',
                    'low'
                )
        else:
            self.add_result(
                'SSH安全', 'SSH空闲超时', 'WARNING',
                '未配置SSH空闲超时设置',
                'low'
            )
        
        # 8. 检查SSH服务状态和配置验证
        self.check_ssh_service_status()
    
    def check_ssh_service_status(self):
        """检查SSH服务状态和配置验证"""
        code, output, _ = self.run_command("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null")
        if code == 0 and output.strip() == 'active':
            self.add_result(
                'SSH安全', 'SSH服务状态', 'PASS',
                'SSH服务运行正常',
                'low'
            )
            
            code, output, _ = self.run_command("sshd -t 2>&1")
            if code == 0:
                self.add_result(
                    'SSH安全', 'SSH配置语法', 'PASS',
                    'SSH配置文件语法正确',
                    'low'
                )
            else:
                self.add_result(
                    'SSH安全', 'SSH配置语法', 'FAIL',
                    f'SSH配置文件语法错误: {output.strip()}',
                    'high'
                )
    
    # ================ 文件权限检查模块 ================
    def check_file_permissions(self):
        """文件权限检查 - 增强版"""
        print("[*] 检查文件权限...")
        
        critical_files = [
            ('/etc/passwd', 0o644, 'root', 'root'),
            ('/etc/shadow', 0o000, 'root', 'root'),
            ('/etc/group', 0o644, 'root', 'root'),
            ('/etc/gshadow', 0o000, 'root', 'root'),
            ('/etc/ssh/sshd_config', 0o600, 'root', 'root'),
            ('/etc/sudoers', 0o440, 'root', 'root'),
            ('/etc/crontab', 0o600, 'root', 'root'),
            ('/etc/hosts.allow', 0o644, 'root', 'root'),
            ('/etc/hosts.deny', 0o644, 'root', 'root')
        ]
        
        for file_path, expected_mode, expected_owner, expected_group in critical_files:
            if os.path.exists(file_path):
                try:
                    st = os.stat(file_path)
                    actual_mode = stat.S_IMODE(st.st_mode)
                    
                    try:
                        owner_name = pwd.getpwuid(st.st_uid).pw_name
                    except:
                        owner_name = str(st.st_uid)
                    
                    try:
                        group_name = grp.getgrgid(st.st_gid).gr_name
                    except:
                        group_name = str(st.st_gid)
                    
                    if file_path in ['/etc/shadow', '/etc/gshadow']:
                        if st.st_uid == 0 and (st.st_mode & 0o777) <= 0o640:
                            self.add_result(
                                '文件权限', f'{file_path}权限',
                                'PASS', f'权限正确: {oct(actual_mode)}, 所有者: {owner_name}, 组: {group_name}',
                                'low',
                                {'cis': ['6.1.2'], 'stig': ['V-779']}
                            )
                        else:
                            self.add_result(
                                '文件权限', f'{file_path}权限',
                                'FAIL', f'权限不安全: {oct(actual_mode)}, 所有者: {owner_name}, 组: {group_name}',
                                'critical',
                                {'cis': ['6.1.2'], 'stig': ['V-779']}
                            )
                    elif (actual_mode == expected_mode and 
                          owner_name == expected_owner and 
                          group_name == expected_group):
                        self.add_result(
                            '文件权限', f'{file_path}权限',
                            'PASS', f'权限正确: {oct(actual_mode)}, 所有者: {owner_name}, 组: {group_name}',
                            'low'
                        )
                    else:
                        self.add_result(
                            '文件权限', f'{file_path}权限',
                            'WARNING', f'权限非标准: {oct(actual_mode)} (期望: {oct(expected_mode)}), '
                                     f'所有者: {owner_name} (期望: {expected_owner}), '
                                     f'组: {group_name} (期望: {expected_group})',
                            'medium'
                        )
                except Exception as e:
                    self.add_result(
                        '文件权限', f'{file_path}权限',
                        'FAIL', f'检查失败: {str(e)}',
                        'medium'
                    )
            else:
                self.add_result(
                    '文件权限', f'{file_path}权限',
                    'WARNING', '文件不存在',
                    'low'
                )
        
        # 检查全局可写文件
        if self.args.check_world_writable:
            self.check_world_writable_files()
        
        # 检查SUID/SGID文件
        if self.args.check_suid:
            self.check_suid_sgid_files_detailed()
        else:
            self.check_suid_sgid_files_basic()
    
    def check_world_writable_files(self):
        """检查全局可写文件"""
        print("[*] 检查全局可写文件...")
        
        try:
            cmd = "find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | head -50"
            code, output, _ = self.run_command(cmd)
            
            if code == 0 and output.strip():
                files = output.strip().split('\n')
                world_writable_files = [f for f in files if f]
                
                if world_writable_files:
                    suspicious_files = []
                    tmp_files = []
                    
                    for filepath in world_writable_files:
                        if '/tmp/' in filepath or '/var/tmp/' in filepath:
                            tmp_files.append(filepath)
                        else:
                            suspicious_files.append(filepath)
                    
                    if suspicious_files:
                        self.add_result(
                            '文件权限', '全局可写文件检查', 'FAIL',
                            f'发现 {len(suspicious_files)} 个可疑的全局可写文件(非/tmp目录)',
                            'high'
                        )
                        
                        for i, filepath in enumerate(suspicious_files[:5]):
                            self.add_result(
                                '文件权限', f'全局可写文件 {i+1}', 'INFO',
                                f'全局可写: {filepath}',
                                'info'
                            )
                    
                    if tmp_files:
                        self.add_result(
                            '文件权限', '临时目录全局可写文件', 'WARNING',
                            f'临时目录有 {len(tmp_files)} 个全局可写文件',
                            'low'
                        )
                else:
                    self.add_result(
                        '文件权限', '全局可写文件检查', 'PASS',
                        '未发现全局可写文件',
                        'low'
                    )
            else:
                self.add_result(
                    '文件权限', '全局可写文件检查', 'INFO',
                    '未发现全局可写文件',
                    'info'
                )
        except Exception as e:
            self.add_result(
                '文件权限', '全局可写文件检查', 'FAIL',
                f'检查过程出错: {str(e)}',
                'medium'
            )
    
    def check_suid_sgid_files_basic(self):
        """基本SUID/SGID文件检查"""
        try:
            suid_count = 0
            suspicious_suid = []
            
            for filepath in self.common_suid_files:
                if os.path.exists(filepath):
                    try:
                        st = os.stat(filepath)
                        if st.st_mode & stat.S_ISUID:
                            suid_count += 1
                            if st.st_uid != 0:
                                suspicious_suid.append(filepath)
                    except:
                        continue
            
            self.add_result(
                '文件权限', '常见SUID文件检查', 'INFO',
                f'检查了 {len(self.common_suid_files)} 个常见SUID文件，发现 {suid_count} 个SUID位设置',
                'info'
            )
            
            if suspicious_suid:
                self.add_result(
                    '文件权限', '可疑SUID文件', 'WARNING',
                    f'发现非root所有的常见SUID文件: {", ".join(suspicious_suid[:3])}',
                    'medium'
                )
        except Exception as e:
            self.add_result(
                '文件权限', 'SUID文件检查', 'FAIL',
                f'检查过程出错: {str(e)}',
                'medium'
            )
    
    def check_suid_sgid_files_detailed(self):
        """详细SUID/SGID文件分析"""
        print("[*] 详细分析SUID/SGID文件...")
        
        suid_files = []
        sgid_files = []
        
        try:
            cmd = "find / -xdev -type f -perm -4000 2>/dev/null | head -100"
            code, output, _ = self.run_command(cmd)
            if code == 0 and output.strip():
                suid_files = [f for f in output.strip().split('\n') if f]
            
            cmd = "find / -xdev -type f -perm -2000 2>/dev/null | head -100"
            code, output, _ = self.run_command(cmd)
            if code == 0 and output.strip():
                sgid_files = [f for f in output.strip().split('\n') if f]
            
            if suid_files:
                suspicious_suid = []
                unknown_suid = []
                
                for filepath in suid_files:
                    try:
                        st = os.stat(filepath)
                        is_common = filepath in self.common_suid_files
                        is_root_owned = st.st_uid == 0
                        
                        if not is_common:
                            unknown_suid.append({
                                'path': filepath,
                                'owner': st.st_uid,
                                'size': st.st_size,
                                'mtime': datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                        
                        if not is_root_owned:
                            suspicious_suid.append(filepath)
                            
                    except:
                        continue
                
                self.add_result(
                    '文件权限', 'SUID文件总数', 'INFO',
                    f'发现 {len(suid_files)} 个SUID文件',
                    'info'
                )
                
                if suspicious_suid:
                    self.add_result(
                        '文件权限', '非root所有SUID文件', 'WARNING',
                        f'发现 {len(suspicious_suid)} 个非root所有的SUID文件',
                        'medium'
                    )
                
                if unknown_suid:
                    self.add_result(
                        '文件权限', '不常见SUID文件', 'WARNING',
                        f'发现 {len(unknown_suid)} 个不常见的SUID文件',
                        'medium'
                    )
                    
                    for i, file_info in enumerate(unknown_suid[:3]):
                        self.add_result(
                            '文件权限', f'不常见SUID文件 {i+1}', 'INFO',
                            f'文件: {file_info["path"]}, 所有者ID: {file_info["owner"]}, '
                            f'大小: {file_info["size"]}字节, 修改时间: {file_info["mtime"]}',
                            'info'
                        )
            
            if sgid_files:
                self.add_result(
                    '文件权限', 'SGID文件总数', 'INFO',
                    f'发现 {len(sgid_files)} 个SGID文件',
                    'info'
                )
                
                for i, filepath in enumerate(sgid_files[:3]):
                    self.add_result(
                        '文件权限', f'SGID文件 {i+1}', 'INFO',
                        f'SGID文件: {filepath}',
                        'info'
                    )
            
        except Exception as e:
            self.add_result(
                '文件权限', 'SUID/SGID详细检查', 'FAIL',
                f'检查过程出错: {str(e)}',
                'medium'
            )
    
    # ================ 服务安全检查模块 ================
    def check_services(self):
        """服务安全检查 - 增强版"""
        print("[*] 检查系统服务...")
        
        dangerous_services = [
            'telnet', 'rlogin', 'rsh', 'rexec', 'ypbind',
            'ypserv', 'tftp', 'chargen', 'echo', 'discard',
            'xinetd', 'inetd', 'vsftpd', 'proftpd', 'nfs',
            'nfs-server', 'nfs-lock', 'nfs-idmap', 'rpcbind',
            'portmap', 'dhcpd', 'slapd', 'named', 'dovecot',
            'sendmail', 'postfix', 'exim', 'smb', 'nmb',
            'winbind', 'squid', 'vnc', 'x11', 'xdm'
        ]
        
        plaintext_services = ['telnet', 'ftp', 'rlogin', 'rsh', 'rexec']
        
        # 1. 检查网络服务监听端口
        try:
            code, output, _ = self.run_command("ss -tulnp 2>/dev/null")
            if code != 0:
                code, output, _ = self.run_command("netstat -tulnp 2>/dev/null")
            
            if code == 0:
                lines = output.strip().split('\n')[1:]
                listening_services = {}
                
                for line in lines:
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            addr_port = parts[3]
                            if ':' in addr_port:
                                port = addr_port.split(':')[-1]
                                protocol = parts[0]
                                process_info = parts[-1]
                                listening_services[port] = {
                                    'protocol': protocol,
                                    'process': process_info
                                }
                
                dangerous_ports = {
                    '23': ('telnet', '明文传输，不安全'),
                    '21': ('ftp', '明文传输，不安全'),
                    '22': ('ssh', '安全，但需检查配置'),
                    '25': ('smtp', '邮件服务，可能不安全'),
                    '53': ('dns', '需检查是否开放'),
                    '80': ('http', 'web服务'),
                    '443': ('https', 'web服务，加密'),
                    '111': ('rpcbind', '远程过程调用，不安全'),
                    '139': ('netbios', 'Windows文件共享'),
                    '445': ('smb', 'Windows文件共享'),
                    '512': ('exec', '远程执行，不安全'),
                    '513': ('login', '远程登录，不安全'),
                    '514': ('shell', '远程shell，不安全'),
                    '2049': ('nfs', '网络文件系统，不安全'),
                    '3306': ('mysql', '数据库'),
                    '5432': ('postgresql', '数据库'),
                    '6379': ('redis', '数据库，常被攻击'),
                    '27017': ('mongodb', '数据库，常无认证')
                }
                
                found_dangerous = []
                found_plaintext = []
                
                for port, (service, description) in dangerous_ports.items():
                    if port in listening_services:
                        service_info = listening_services[port]
                        status = f"{service}({port}/{service_info['protocol']}) - {description}"
                        
                        if service in plaintext_services:
                            found_plaintext.append(status)
                        elif '不安全' in description:
                            found_dangerous.append(status)
                
                if found_plaintext:
                    self.add_result(
                        '服务安全', '明文传输服务', 'FAIL',
                        f'发现明文传输高危服务: {", ".join(found_plaintext[:3])}',
                        'critical',
                        {'cis': ['2.1.1'], 'stig': ['V-724']}
                    )
                
                if found_dangerous:
                    self.add_result(
                        '服务安全', '高危端口检查', 'FAIL',
                        f'发现高危服务端口: {", ".join(found_dangerous[:3])}',
                        'high',
                        {'cis': ['2.1.1'], 'stig': ['V-724']}
                    )
                
                if not found_plaintext and not found_dangerous:
                    self.add_result(
                        '服务安全', '高危端口检查', 'PASS',
                        '未发现高危服务端口监听',
                        'low'
                    )
                
                if listening_services:
                    self.add_result(
                        '服务安全', '监听端口统计', 'INFO',
                        f'系统共监听 {len(listening_services)} 个端口',
                        'info'
                    )
                    
                    for i, (port, info) in enumerate(list(listening_services.items())[:5]):
                        self.add_result(
                            '服务安全', f'监听端口 {i+1}', 'INFO',
                            f'端口 {port}/{info["protocol"]}: {info["process"]}',
                            'info'
                        )
        except Exception as e:
            self.add_result(
                '服务安全', '网络服务检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
        
        # 2. 检查明文传输高危服务
        self.check_plaintext_services(plaintext_services)
        
        # 3. 检查开机自启动服务
        self.check_auto_start_services()
    
    def check_plaintext_services(self, plaintext_services):
        """检查明文传输高危服务"""
        print("[*] 检查明文传输高危服务...")
        
        found_services = []
        
        for service in plaintext_services:
            code, output, _ = self.run_command(f"systemctl is-active {service} 2>/dev/null")
            if code == 0 and output.strip() == 'active':
                found_services.append(service)
            
            code, output, _ = self.run_command(f"systemctl list-unit-files | grep -i {service}")
            if code == 0 and output.strip():
                if service not in found_services:
                    self.add_result(
                        '服务安全', f'{service}服务安装状态', 'WARNING',
                        f'明文传输服务 {service} 已安装但未运行',
                        'medium'
                    )
        
        if found_services:
            self.add_result(
                '服务安全', '明文传输服务运行状态', 'FAIL',
                f'发现运行的明文传输服务: {", ".join(found_services)}',
                'critical'
            )
        else:
            self.add_result(
                '服务安全', '明文传输服务运行状态', 'PASS',
                '未发现运行的明文传输服务',
                'low'
            )
    
    def check_auto_start_services(self):
        """检查开机自启动服务"""
        print("[*] 检查开机自启动服务...")
        
        try:
            code, output, _ = self.run_command("systemctl list-unit-files --state=enabled | grep -v '^UNIT FILE' | grep -v '^$' | wc -l")
            if code == 0:
                enabled_count = int(output.strip())
                self.add_result(
                    '服务安全', '开机自启动服务数量', 'INFO',
                    f'系统有 {enabled_count} 个开机自启动服务',
                    'info'
                )
                
                code, output, _ = self.run_command("systemctl list-unit-files --state=enabled | grep -v '^UNIT FILE' | head -10")
                if code == 0 and output.strip():
                    services = output.strip().split('\n')
                    service_list = []
                    
                    for service_line in services:
                        parts = service_line.split()
                        if parts:
                            service_list.append(parts[0])
                    
                    if service_list:
                        self.add_result(
                            '服务安全', '部分自启动服务', 'INFO',
                            f'自启动服务示例: {", ".join(service_list[:5])}',
                            'info'
                        )
        except Exception as e:
            self.add_result(
                '服务安全', '自启动服务检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    # ================ 防火墙检查模块 ================
    def check_firewall(self):
        """防火墙配置检查"""
        print("[*] 检查防火墙配置...")
        
        firewall_active = False
        firewall_details = []
        
        # 检查iptables
        code, output, _ = self.run_command("iptables -L -n 2>/dev/null")
        if code == 0 and output.strip():
            firewall_active = True
            firewall_details.append('iptables')
            
            lines = output.split('\n')
            input_policy = 'ACCEPT'
            
            for line in lines:
                if 'Chain INPUT (policy' in line:
                    if 'DROP' in line:
                        input_policy = 'DROP'
                    elif 'REJECT' in line:
                        input_policy = 'REJECT'
                    break
            
            if input_policy in ['DROP', 'REJECT']:
                self.add_result(
                    '防火墙', 'iptables默认策略', 'PASS',
                    f'INPUT链默认策略为{input_policy}',
                    'low',
                    {'cis': ['3.5.1'], 'dengbao': ['8.1.5.1']}
                )
            else:
                self.add_result(
                    '防火墙', 'iptables默认策略', 'FAIL',
                    f'INPUT链默认策略不是DROP/REJECT: {input_policy}',
                    'high',
                    {'cis': ['3.5.1'], 'dengbao': ['8.1.5.1']}
                )
        
        # 检查firewalld
        code, output, _ = self.run_command("systemctl is-active firewalld 2>/dev/null")
        if code == 0 and output.strip() == 'active':
            firewall_active = True
            firewall_details.append('firewalld')
            self.add_result(
                '防火墙', 'firewalld状态', 'PASS',
                'firewalld服务运行中',
                'low'
            )
            
            code, zones, _ = self.run_command("firewall-cmd --get-default-zone 2>/dev/null")
            if code == 0:
                self.add_result(
                    '防火墙', 'firewalld默认区域', 'INFO',
                    f'默认区域: {zones.strip()}',
                    'info'
                )
        
        # 检查ufw
        code, output, _ = self.run_command("ufw status 2>/dev/null | grep -i active")
        if code == 0 and 'active' in output.lower():
            firewall_active = True
            firewall_details.append('ufw')
            self.add_result(
                '防火墙', 'UFW状态', 'PASS',
                'UFW防火墙已启用',
                'low'
            )
        
        if firewall_active:
            self.add_result(
                '防火墙', '防火墙状态', 'PASS',
                f'防火墙已启用 ({", ".join(firewall_details)})',
                'low'
            )
        else:
            self.add_result(
                '防火墙', '防火墙状态', 'FAIL',
                '未发现活动的防火墙',
                'critical',
                {'cis': ['3.5.1'], 'stig': ['V-722']}
            )
    
    # ================ 系统更新检查模块 ================
    def check_updates(self):
        """系统更新检查"""
        print("[*] 检查系统更新...")
        
        if os.path.exists('/etc/redhat-release') or os.path.exists('/etc/centos-release'):
            code, output, _ = self.run_command("yum check-update 2>/dev/null")
            if code == 100:
                sec_code, sec_output, _ = self.run_command("yum list-security 2>/dev/null | grep -c 'SecErrata'")
                if sec_code == 0 and sec_output.strip():
                    security_updates = int(sec_output.strip())
                    self.add_result(
                        '系统更新', '可用更新检查', 'WARNING',
                        f'系统有可用更新，其中{security_updates}个为安全更新',
                        'medium',
                        {'cis': ['1.8'], 'iso27001': ['A.12.6.1']}
                    )
                else:
                    self.add_result(
                        '系统更新', '可用更新检查', 'WARNING',
                        '系统有可用更新',
                        'medium'
                    )
            elif code == 0:
                self.add_result(
                    '系统更新', '可用更新检查', 'PASS',
                    '系统已是最新',
                    'low'
                )
        elif os.path.exists('/etc/debian_version'):
            self.run_command("apt-get update 2>/dev/null")
            
            code, output, _ = self.run_command("apt list --upgradable 2>/dev/null")
            if code == 0 and 'upgradable' in output:
                lines = output.split('\n')
                update_count = len([l for l in lines if 'upgradable' in l])
                
                sec_code, sec_output, _ = self.run_command("apt-get -s dist-upgrade 2>/dev/null | grep -c '^Inst.*Security'")
                if sec_code == 0 and sec_output.strip():
                    security_updates = int(sec_output.strip())
                    self.add_result(
                        '系统更新', '可用更新检查', 'WARNING',
                        f'有{update_count}个可用更新，其中{security_updates}个为安全更新',
                        'medium'
                    )
                else:
                    self.add_result(
                        '系统更新', '可用更新检查', 'WARNING',
                        f'有{update_count}个可用更新',
                        'medium'
                    )
            else:
                self.add_result(
                    '系统更新', '可用更新检查', 'PASS',
                    '系统已是最新',
                    'low'
                )
        else:
            self.add_result(
                '系统更新', '可用更新检查', 'INFO',
                '不支持的发行版，跳过更新检查',
                'info'
            )
        
        # 检查系统最后更新时间
        self.check_last_update_time()
    
    def check_last_update_time(self):
        """检查系统最后更新时间"""
        try:
            update_timestamp_file = None
            
            if os.path.exists('/var/cache/apt/pkgcache.bin'):
                update_timestamp_file = '/var/cache/apt/pkgcache.bin'
            elif os.path.exists('/var/cache/yum'):
                code, output, _ = self.run_command("ls -t /var/cache/yum/*/*.sqlite 2>/dev/null | head -1")
                if code == 0 and output.strip():
                    update_timestamp_file = output.strip()
            
            if update_timestamp_file and os.path.exists(update_timestamp_file):
                import time
                mtime = os.path.getmtime(update_timestamp_file)
                update_time = datetime.datetime.fromtimestamp(mtime)
                days_since_update = (datetime.datetime.now() - update_time).days
                
                if days_since_update <= 7:
                    self.add_result(
                        '系统更新', '最后更新时间', 'PASS',
                        f'系统最近 {days_since_update} 天前更新过 ({update_time.strftime("%Y-%m-%d %H:%M:%S")})',
                        'low'
                    )
                elif days_since_update <= 30:
                    self.add_result(
                        '系统更新', '最后更新时间', 'WARNING',
                        f'系统已 {days_since_update} 天未更新 ({update_time.strftime("%Y-%m-%d %H:%M:%S")})',
                        'medium'
                    )
                else:
                    self.add_result(
                        '系统更新', '最后更新时间', 'FAIL',
                        f'系统已 {days_since_update} 天未更新 ({update_time.strftime("%Y-%m-%d %H:%M:%S")})',
                        'high'
                    )
        except Exception as e:
            self.add_result(
                '系统更新', '最后更新时间检查', 'INFO',
                f'无法确定最后更新时间: {str(e)}',
                'info'
            )
    
    # ================ 审计日志检查模块 ================
    def check_audit_logging(self):
        """审计日志检查 - 增强版"""
        print("[*] 检查审计日志配置...")
        
        # 检查auditd服务状态
        code, output, _ = self.run_command("systemctl is-active auditd 2>/dev/null")
        if code == 0 and output.strip() == 'active':
            self.add_result(
                '审计日志', 'auditd服务状态', 'PASS',
                'auditd服务运行中',
                'low',
                {'cis': ['4.1.1'], 'stig': ['V-810']}
            )
            
            # 检查审计规则
            code, rules, _ = self.run_command("auditctl -l 2>/dev/null")
            if code == 0 and rules.strip():
                key_audits = [
                    ('/etc/passwd', 'passwd文件修改'),
                    ('/etc/shadow', 'shadow文件修改'),
                    ('/etc/sudoers', 'sudo配置修改'),
                    ('/var/log/secure', '认证日志'),
                    ('/etc/ssh/sshd_config', 'SSH配置修改')
                ]
                
                for path, desc in key_audits:
                    if path in rules:
                        self.add_result(
                            '审计日志', f'{desc}审计', 'PASS',
                            f'已配置{desc}审计规则',
                            'low'
                        )
                    else:
                        self.add_result(
                            '审计日志', f'{desc}审计', 'WARNING',
                            f'未配置{desc}审计规则',
                            'medium'
                        )
                
                rule_count = len([line for line in rules.split('\n') if line.strip()])
                if rule_count >= 10:
                    self.add_result(
                        '审计日志', '审计规则数量', 'PASS',
                        f'配置了{rule_count}条审计规则',
                        'low'
                    )
                else:
                    self.add_result(
                        '审计日志', '审计规则数量', 'WARNING',
                        f'审计规则数量较少: {rule_count}条',
                        'medium'
                    )
        else:
            self.add_result(
                '审计日志', 'auditd服务状态', 'FAIL',
                'auditd服务未运行',
                'high',
                {'cis': ['4.1.1'], 'stig': ['V-810']}
            )
        
        # 检查系统日志文件权限
        log_files = [
            '/var/log/secure',
            '/var/log/auth.log',
            '/var/log/messages',
            '/var/log/syslog',
            '/var/log/audit/audit.log'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    st = os.stat(log_file)
                    mode = stat.S_IMODE(st.st_mode)
                    if mode & 0o777 != 0o600 and mode & 0o777 != 0o640:
                        self.add_result(
                            '审计日志', f'{log_file}权限',
                            'WARNING', f'日志文件权限过宽: {oct(mode)} (建议600或640)',
                            'medium'
                        )
                except:
                    pass
        
        # 检查日志轮转配置
        self.check_logrotate_config()
    
    def check_logrotate_config(self):
        """检查日志轮转配置"""
        print("[*] 检查日志轮转配置...")
        
        logrotate_conf = '/etc/logrotate.conf'
        if os.path.exists(logrotate_conf):
            try:
                with open(logrotate_conf, 'r') as f:
                    content = f.read()
                    
                    rotate_match = re.search(r'rotate\s+(\d+)', content)
                    if rotate_match:
                        rotate_count = int(rotate_match.group(1))
                        if rotate_count >= 4:
                            self.add_result(
                                '审计日志', '日志轮转周期', 'PASS',
                                f'日志轮转保留 {rotate_count} 个备份',
                                'low'
                            )
                        else:
                            self.add_result(
                                '审计日志', '日志轮转周期', 'WARNING',
                                f'日志轮转保留备份较少: {rotate_count} 个',
                                'medium'
                            )
                    else:
                        self.add_result(
                            '审计日志', '日志轮转周期', 'INFO',
                            '未在logrotate.conf中找到rotate配置',
                            'info'
                        )
                    
                    if 'compress' in content:
                        self.add_result(
                            '审计日志', '日志压缩', 'PASS',
                            '日志轮转时启用压缩',
                            'low'
                        )
                    
                    key_logs = ['secure', 'messages', 'syslog', 'audit/audit.log']
                    for log in key_logs:
                        log_pattern = f'/var/log/{log}'
                        if log_pattern in content:
                            self.add_result(
                                '审计日志', f'{log}轮转配置', 'PASS',
                                f'已配置 {log} 日志轮转',
                                'low'
                            )
                
            except Exception as e:
                self.add_result(
                    '审计日志', '日志轮转配置检查', 'FAIL',
                    f'检查失败: {str(e)}',
                    'medium'
                )
        else:
            self.add_result(
                '审计日志', '日志轮转配置', 'WARNING',
                'logrotate配置文件不存在',
                'medium'
            )
    
    # ================ 内核安全参数检查模块 ================
    def check_kernel_security(self):
        """内核安全参数检查"""
        print("[*] 检查内核安全参数...")
        
        kernel_params = [
            ('net.ipv4.ip_forward', '0', '禁止IP转发', 'medium'),
            ('net.ipv4.conf.all.accept_source_route', '0', '禁止接受源路由', 'medium'),
            ('net.ipv4.conf.default.accept_source_route', '0', '禁止接受源路由(默认)', 'medium'),
            ('net.ipv4.icmp_echo_ignore_broadcasts', '1', '忽略ICMP广播', 'low'),
            ('net.ipv4.tcp_syncookies', '1', '启用SYN Cookies', 'medium'),
            ('kernel.randomize_va_space', '2', '启用ASLR', 'high'),
            ('net.ipv4.conf.all.rp_filter', '1', '启用反向路径过滤', 'medium'),
            ('net.ipv4.conf.default.rp_filter', '1', '启用反向路径过滤(默认)', 'medium'),
        ]
        
        for param, expected, desc, risk in kernel_params:
            param_path = f"/proc/sys/{param.replace('.', '/')}"
            if os.path.exists(param_path):
                with open(param_path, 'r') as f:
                    value = f.read().strip()
                    if value == expected:
                        self.add_result(
                            '内核安全', desc, 'PASS',
                            f'{param} = {value} (正确)',
                            'low',
                            {'cis': ['3.2'], 'stig': ['V-385']}
                        )
                    else:
                        self.add_result(
                            '内核安全', desc, 'FAIL',
                            f'{param} = {value} (期望: {expected})',
                            risk,
                            {'cis': ['3.2'], 'stig': ['V-385']}
                        )
        
        sysctl_files = ['/etc/sysctl.conf', '/etc/sysctl.d/99-sysctl.conf']
        for sysctl_file in sysctl_files:
            if os.path.exists(sysctl_file):
                with open(sysctl_file, 'r') as f:
                    content = f.read()
                    for param, expected, desc, risk in kernel_params:
                        match = re.search(rf'{param}\s*=\s*(\d+)', content)
                        if match:
                            if match.group(1) == expected:
                                self.add_result(
                                    '内核安全', f'{desc} (持久化)',
                                    'PASS', f'{param}在{sysctl_file}中正确配置',
                                    'low'
                                )
                            else:
                                self.add_result(
                                    '内核安全', f'{desc} (持久化)',
                                    'WARNING', f'{param}在{sysctl_file}中配置不正确',
                                    risk
                                )
                break
    
    # ================ 系统加固检查模块 ================
    def check_system_hardening(self):
        """系统加固检查 - 增强版"""
        print("[*] 检查系统加固配置...")
        
        # 1. 检查SELinux状态
        if os.path.exists('/usr/sbin/sestatus'):
            code, output, _ = self.run_command("getenforce 2>/dev/null")
            if code == 0:
                mode = output.strip()
                if mode == 'Enforcing':
                    self.add_result(
                        '系统加固', 'SELinux状态', 'PASS',
                        f'SELinux运行模式: {mode}',
                        'low',
                        {'cis': ['1.6'], 'stig': ['V-386']}
                    )
                else:
                    self.add_result(
                        '系统加固', 'SELinux状态', 'FAIL',
                        f'SELinux未在强制模式: {mode}',
                        'high',
                        {'cis': ['1.6'], 'stig': ['V-386']}
                    )
            
            if os.path.exists('/etc/selinux/config'):
                with open('/etc/selinux/config', 'r') as f:
                    content = f.read()
                    if 'SELINUX=enforcing' in content:
                        self.add_result(
                            '系统加固', 'SELinux配置', 'PASS',
                            'SELinux配置为enforcing模式',
                            'low'
                        )
                    else:
                        self.add_result(
                            '系统加固', 'SELinux配置', 'WARNING',
                            'SELinux未配置为enforcing模式',
                            'medium'
                        )
        
        # 2. 检查时间同步服务
        ntp_services = ['chronyd', 'ntpd', 'systemd-timesyncd']
        time_sync_active = False
        
        for service in ntp_services:
            code, output, _ = self.run_command(f"systemctl is-active {service} 2>/dev/null")
            if code == 0 and output.strip() == 'active':
                time_sync_active = True
                self.add_result(
                    '系统加固', '时间同步服务', 'PASS',
                    f'{service}服务运行中',
                    'low',
                    {'cis': ['2.2.1'], 'iso27001': ['A.12.4.4']}
                )
                
                if service == 'chronyd':
                    code, config, _ = self.run_command("chronyc sources 2>/dev/null")
                    if code == 0 and '^*' in config:
                        self.add_result(
                            '系统加固', 'NTP源配置', 'PASS',
                            '时间同步源配置正确',
                            'low'
                        )
                break
        
        if not time_sync_active:
            self.add_result(
                '系统加固', '时间同步服务', 'FAIL',
                '未发现运行的时间同步服务',
                'high',
                {'cis': ['2.2.1'], 'iso27001': ['A.12.4.4']}
            )
        
        # 3. 检查核心转储限制
        code, output, _ = self.run_command("ulimit -c 2>/dev/null")
        if code == 0:
            if output.strip() == '0':
                self.add_result(
                    '系统加固', '核心转储限制', 'PASS',
                    '核心转储已禁用',
                    'low'
                )
            else:
                self.add_result(
                    '系统加固', '核心转储限制', 'WARNING',
                    f'核心转储限制: {output.strip()}',
                    'low'
                )
        
        # 4. 检查ASLR
        if os.path.exists('/proc/sys/kernel/randomize_va_space'):
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                value = f.read().strip()
                if value == '2':
                    self.add_result(
                        '系统加固', 'ASLR配置', 'PASS',
                        'ASLR已启用完全随机化',
                        'low'
                    )
                elif value == '1':
                    self.add_result(
                        '系统加固', 'ASLR配置', 'WARNING',
                        'ASLR仅启用部分随机化',
                        'medium'
                    )
                else:
                    self.add_result(
                        '系统加固', 'ASLR配置', 'FAIL',
                        'ASLR未启用',
                        'high'
                    )
        
        # 5. 检查隐藏进程
        self.check_hidden_processes()
    
    def check_hidden_processes(self):
        """检查隐藏进程"""
        print("[*] 检查隐藏进程...")
        
        try:
            code, output, _ = self.run_command("ps -ef | awk '{print $2}' | sort -n")
            if code == 0:
                pids = [int(pid) for pid in output.strip().split('\n') if pid.isdigit()]
                
                pid_count = collections.Counter(pids)
                duplicate_pids = [pid for pid, count in pid_count.items() if count > 1]
                
                if duplicate_pids:
                    self.add_result(
                        '系统加固', '隐藏进程检查', 'FAIL',
                        f'发现重复PID: {duplicate_pids[:5]} (可能提示Rootkit)',
                        'critical'
                    )
                else:
                    self.add_result(
                        '系统加固', '隐藏进程检查', 'PASS',
                        '未发现重复PID',
                        'low'
                    )
                
                proc_pids = []
                for pid_dir in os.listdir('/proc'):
                    if pid_dir.isdigit():
                        proc_pids.append(int(pid_dir))
                
                missing_in_ps = set(proc_pids) - set(pids)
                missing_in_proc = set(pids) - set(proc_pids)
                
                if missing_in_ps:
                    self.add_result(
                        '系统加固', '进程一致性检查', 'WARNING',
                        f'发现 {len(missing_in_ps)} 个在/proc中但不在ps输出中的进程',
                        'medium'
                    )
                    
                    for i, pid in enumerate(list(missing_in_ps)[:3]):
                        cmdline_file = f'/proc/{pid}/cmdline'
                        if os.path.exists(cmdline_file):
                            try:
                                with open(cmdline_file, 'r') as f:
                                    cmdline = f.read().replace('\x00', ' ').strip()
                                    self.add_result(
                                        '系统加固', f'异常进程 {pid}', 'INFO',
                                        f'异常进程PID {pid}: {cmdline[:100]}',
                                        'info'
                                    )
                            except:
                                pass
        except Exception as e:
            self.add_result(
                '系统加固', '隐藏进程检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    # ================ 恶意软件防护检查模块 ================
    def check_malware_protection(self):
        """恶意软件防护检查 - 增强版"""
        print("[*] 检查恶意软件防护...")
        
        # 1. 检查防病毒软件
        antivirus_services = ['clamav', 'rkhunter', 'chkrootkit']
        av_installed = False
        
        for service in antivirus_services:
            code, output, _ = self.run_command(f"which {service} 2>/dev/null")
            if code == 0:
                av_installed = True
                self.add_result(
                    '恶意软件防护', f'{service}安装状态', 'PASS',
                    f'{service}已安装',
                    'low',
                    {'iso27001': ['A.12.2.1']}
                )
                
                code2, output2, _ = self.run_command(f"systemctl is-active {service}d 2>/dev/null")
                if code2 == 0 and output2.strip() == 'active':
                    self.add_result(
                        '恶意软件防护', f'{service}服务状态', 'PASS',
                        f'{service}服务运行中',
                        'low'
                    )
                else:
                    if service in ['rkhunter', 'chkrootkit']:
                        self.add_result(
                            '恶意软件防护', f'{service}检查', 'INFO',
                            f'{service}已安装但未作为服务运行',
                            'info'
                        )
        
        if not av_installed:
            self.add_result(
                '恶意软件防护', '防病毒软件', 'WARNING',
                '未发现防病毒软件',
                'medium',
                {'iso27001': ['A.12.2.1']}
            )
        
        # 2. 检查文件完整性工具
        integrity_tools = ['aide', 'tripwire', 'integrity']
        integrity_installed = False
        
        for tool in integrity_tools:
            code, output, _ = self.run_command(f"which {tool} 2>/dev/null")
            if code == 0:
                integrity_installed = True
                self.add_result(
                    '恶意软件防护', f'{tool}安装状态', 'PASS',
                    f'文件完整性工具 {tool} 已安装',
                    'low'
                )
                break
        
        if not integrity_installed:
            self.add_result(
                '恶意软件防护', '文件完整性检查', 'WARNING',
                '未发现文件完整性检查工具',
                'medium'
            )
        
        # 3. 检查可疑进程
        self.check_suspicious_processes()
        
        # 4. 检查计划任务
        self.check_crontab_tasks()
    
    def check_suspicious_processes(self):
        """检查可疑进程"""
        print("[*] 检查可疑进程...")
        
        suspicious_keywords = [
            'cryptominer', 'miner', 'xmrig', 'ccminer', 'minerd',
            'backdoor', 'shell', 'reverse_shell', 'bind_shell',
            'botnet', 'rat', 'rootkit', 'keylogger', 'logger',
            'ransomware', 'encrypt', 'decrypt',
            'tor', 'i2p', 'anonymizer', 'proxy', 'vpn', 'tunnel', 'socks'
        ]
        
        try:
            code, output, _ = self.run_command("ps auxf 2>/dev/null")
            if code == 0:
                suspicious_processes = []
                
                for line in output.strip().split('\n')[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        cmd = parts[10].lower()
                        pid = parts[1]
                        user = parts[0]
                        
                        for keyword in suspicious_keywords:
                            if keyword in cmd:
                                suspicious_processes.append({
                                    'pid': pid,
                                    'user': user,
                                    'cmd': cmd[:100],
                                    'keyword': keyword
                                })
                                break
                
                if suspicious_processes:
                    self.add_result(
                        '恶意软件防护', '可疑进程检查', 'FAIL',
                        f'发现 {len(suspicious_processes)} 个可疑进程',
                        'critical'
                    )
                    
                    for i, proc in enumerate(suspicious_processes[:3]):
                        self.add_result(
                            '恶意软件防护', f'可疑进程 {i+1}', 'INFO',
                            f'PID {proc["pid"]} ({proc["user"]}): {proc["cmd"]} (关键词: {proc["keyword"]})',
                            'info'
                        )
                else:
                    self.add_result(
                        '恶意软件防护', '可疑进程检查', 'PASS',
                        '未发现可疑进程',
                        'low'
                    )
        except Exception as e:
            self.add_result(
                '恶意软件防护', '可疑进程检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    def check_crontab_tasks(self):
        """检查计划任务"""
        print("[*] 检查计划任务...")
        
        suspicious_cron_patterns = [
            r'wget\s+.*\|\s*(sh|bash)',
            r'curl\s+.*\|\s*(sh|bash)',
            r'http://',
            r'https://',
            r'/tmp/',
            r'/dev/shm/',
            r'base64.*decode',
            r'eval\s+.*',
            r'nc\s+.*\s+\d+',
            r'ncat\s+.*\s+\d+',
            r'socat\s+.*'
        ]
        
        try:
            cron_files = [
                '/etc/crontab',
                '/etc/cron.daily/',
                '/etc/cron.hourly/',
                '/etc/cron.weekly/',
                '/etc/cron.monthly/',
                '/etc/cron.d/'
            ]
            
            suspicious_cron_entries = []
            
            if os.path.exists('/etc/crontab'):
                with open('/etc/crontab', 'r') as f:
                    lines = f.readlines()
                    for line_num, line in enumerate(lines, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            for pattern in suspicious_cron_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    suspicious_cron_entries.append({
                                        'file': '/etc/crontab',
                                        'line': line_num,
                                        'content': line[:200],
                                        'pattern': pattern
                                    })
                                    break
            
            code, output, _ = self.run_command("crontab -l 2>/dev/null")
            if code == 0 and output.strip():
                lines = output.strip().split('\n')
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        for pattern in suspicious_cron_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_cron_entries.append({
                                    'file': '用户crontab',
                                    'line': line_num,
                                    'content': line[:200],
                                    'pattern': pattern
                                })
                                break
            
            if suspicious_cron_entries:
                self.add_result(
                    '恶意软件防护', '计划任务检查', 'FAIL',
                    f'发现 {len(suspicious_cron_entries)} 个可疑计划任务',
                    'high'
                )
                
                for i, entry in enumerate(suspicious_cron_entries[:2]):
                    self.add_result(
                        '恶意软件防护', f'可疑计划任务 {i+1}', 'INFO',
                        f'文件: {entry["file"]}, 行: {entry["line"]}: {entry["content"]}',
                        'info'
                    )
            else:
                self.add_result(
                    '恶意软件防护', '计划任务检查', 'PASS',
                    '未发现可疑计划任务',
                    'low'
                )
                
        except Exception as e:
            self.add_result(
                '恶意软件防护', '计划任务检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    # ================ Sudo安全检查模块 ================
    def check_sudo_security(self):
        """Sudo配置安全检查 - 增强版"""
        print("[*] 检查Sudo配置...")
        
        if not os.path.exists('/etc/sudoers'):
            self.add_result('Sudo安全', 'sudoers文件', 'FAIL', 'sudoers文件不存在', 'medium')
            return
        
        # 1. 检查sudoers文件权限
        try:
            st = os.stat('/etc/sudoers')
            if stat.S_IMODE(st.st_mode) != 0o440:
                self.add_result(
                    'Sudo安全', 'sudoers文件权限',
                    'FAIL', f'sudoers文件权限不正确: {oct(stat.S_IMODE(st.st_mode))} (应为440)',
                    'high'
                )
            else:
                self.add_result(
                    'Sudo安全', 'sudoers文件权限',
                    'PASS', f'sudoers文件权限正确: {oct(stat.S_IMODE(st.st_mode))}',
                    'low'
                )
        except Exception as e:
            self.add_result(
                'Sudo安全', 'sudoers文件权限',
                'FAIL', f'检查失败: {str(e)}',
                'medium'
            )
        
        # 2. 检查sudo日志配置
        code, output, _ = self.run_command("grep -i 'Defaults logfile' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true")
        if code == 0 and output.strip():
            self.add_result(
                'Sudo安全', 'Sudo日志配置', 'PASS',
                '已配置sudo操作日志',
                'low'
            )
        else:
            self.add_result(
                'Sudo安全', 'Sudo日志配置', 'WARNING',
                '未配置sudo操作日志',
                'medium'
            )
        
        # 3. 检查sudoers文件语法
        self.check_sudoers_syntax()
        
        # 4. 检查近期sudo使用记录
        self.check_recent_sudo_logs()
    
    def check_sudoers_syntax(self):
        """检查sudoers文件语法"""
        try:
            code, output, _ = self.run_command("visudo -c 2>&1")
            if code == 0:
                self.add_result(
                    'Sudo安全', 'sudoers文件语法', 'PASS',
                    'sudoers文件语法正确',
                    'low'
                )
            else:
                self.add_result(
                    'Sudo安全', 'sudoers文件语法', 'FAIL',
                    f'sudoers文件语法错误: {output.strip()}',
                    'high'
                )
        except Exception as e:
            self.add_result(
                'Sudo安全', 'sudoers文件语法检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    def check_recent_sudo_logs(self):
        """检查近期sudo使用记录"""
        try:
            log_files = [
                '/var/log/secure',
                '/var/log/auth.log',
                '/var/log/sudo.log'
            ]
            
            sudo_log_found = False
            for log_file in log_files:
                if os.path.exists(log_file):
                    code, output, _ = self.run_command(f"tail -100 {log_file} | grep -i sudo | head -5")
                    if code == 0 and output.strip():
                        sudo_log_found = True
                        lines = output.strip().split('\n')
                        self.add_result(
                            'Sudo安全', 'sudo使用记录', 'INFO',
                            f'发现近期sudo使用记录 ({len(lines)}条)',
                            'info'
                        )
                        
                        for i, line in enumerate(lines[:2]):
                            self.add_result(
                                'Sudo安全', f'sudo记录 {i+1}', 'INFO',
                                f'{line[:150]}',
                                'info'
                            )
                        break
            
            if not sudo_log_found:
                self.add_result(
                    'Sudo安全', 'sudo使用记录', 'INFO',
                    '未发现近期sudo使用记录',
                    'info'
                )
                
        except Exception as e:
            self.add_result(
                'Sudo安全', 'sudo使用记录检查', 'FAIL',
                f'检查失败: {str(e)}',
                'medium'
            )
    
    # ================ 网络安全检查模块 ================
    def check_network_security(self):
        """网络安全配置检查 - 增强版"""
        print("[*] 检查网络安全配置...")
        
        # 1. 检查TCP Wrappers
        if os.path.exists('/etc/hosts.allow') and os.path.exists('/etc/hosts.deny'):
            self.add_result(
                '网络安全', 'TCP Wrappers配置', 'PASS',
                'TCP Wrappers配置文件存在',
                'low'
            )
            
            with open('/etc/hosts.deny', 'r') as f:
                content = f.read()
                if 'ALL: ALL' in content:
                    self.add_result(
                        '网络安全', 'hosts.deny默认策略', 'PASS',
                        'hosts.deny配置了默认拒绝策略',
                        'low'
                    )
                else:
                    self.add_result(
                        '网络安全', 'hosts.deny默认策略', 'WARNING',
                        'hosts.deny未配置默认拒绝策略',
                        'medium'
                    )
        else:
            self.add_result(
                '网络安全', 'TCP Wrappers配置', 'INFO',
                'TCP Wrappers未配置',
                'info'
            )
        
        # 2. 检查ICMP配置
        self.check_icmp_config()
        
        # 3. 检查ARP安全参数
        self.check_arp_security()
    
    def check_icmp_config(self):
        """检查ICMP配置"""
        icmp_params = [
            ('net.ipv4.icmp_echo_ignore_all', '1', '忽略所有ICMP请求', 'low'),
            ('net.ipv4.icmp_echo_ignore_broadcasts', '1', '忽略ICMP广播请求', 'low'),
            ('net.ipv4.icmp_ignore_bogus_error_responses', '1', '忽略伪造的ICMP错误响应', 'low'),
            ('net.ipv4.conf.all.accept_redirects', '0', '禁止接受ICMP重定向', 'medium'),
            ('net.ipv4.conf.default.accept_redirects', '0', '禁止接受ICMP重定向(默认)', 'medium'),
            ('net.ipv4.conf.all.secure_redirects', '1', '只接受安全的ICMP重定向', 'low'),
        ]
        
        for param, expected, desc, risk in icmp_params:
            param_path = f"/proc/sys/{param.replace('.', '/')}"
            if os.path.exists(param_path):
                with open(param_path, 'r') as f:
                    value = f.read().strip()
                    if value == expected:
                        self.add_result(
                            '网络安全', desc, 'PASS',
                            f'{param} = {value}',
                            'low'
                        )
                    else:
                        self.add_result(
                            '网络安全', desc, 'WARNING',
                            f'{param} = {value} (期望: {expected})',
                            risk
                        )
    
    def check_arp_security(self):
        """检查ARP安全参数"""
        arp_params = [
            ('net.ipv4.conf.all.arp_ignore', '1', '忽略ARP请求', 'medium'),
            ('net.ipv4.conf.all.arp_announce', '2', 'ARP宣告限制', 'medium'),
            ('net.ipv4.conf.all.rp_filter', '1', '反向路径过滤', 'medium'),
        ]
        
        for param, expected, desc, risk in arp_params:
            param_path = f"/proc/sys/{param.replace('.', '/')}"
            if os.path.exists(param_path):
                with open(param_path, 'r') as f:
                    value = f.read().strip()
                    if value == expected:
                        self.add_result(
                            '网络安全', desc, 'PASS',
                            f'{param} = {value}',
                            'low'
                        )
                    else:
                        self.add_result(
                            '网络安全', desc, 'WARNING',
                            f'{param} = {value} (期望: {expected})',
                            risk
                        )
    
    # ================ 报告生成模块 ================
    def generate_report(self):
        """生成检查报告"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.args.output or "security_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        # 1. 生成JSON报告
        json_report = {
            'metadata': {
                'tool_version': '3.0',
                'generated_at': datetime.datetime.now().isoformat(),
                'command_line': ' '.join(sys.argv)
            },
            'host_info': self.host_info,
            'summary': self.stats,
            'results': self.results
        }
        
        json_file = os.path.join(report_dir, f"security_audit_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)
        
        # 2. 生成文本报告
        text_file = os.path.join(report_dir, f"security_audit_{timestamp}.txt")
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_text_report())
        
        # 3. 生成CSV报告
        csv_file = os.path.join(report_dir, f"security_audit_{timestamp}.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Category', 'Item', 'Status', 'Risk', 'Standards', 'Details', 'Timestamp'])
            for result in self.results:
                standards_str = '; '.join([f'{k}:{",".join(v)}' for k, v in result.get('standards', {}).items()])
                writer.writerow([
                    result['id'],
                    result['category'],
                    result['item'],
                    result['status'],
                    result['risk'],
                    standards_str,
                    result['details'],
                    result['timestamp']
                ])
        
        # 4. 生成HTML报告
        html_file = os.path.join(report_dir, f"security_audit_{timestamp}.html")
        self._generate_html_report(html_file)
        
        return {
            'json': json_file,
            'text': text_file,
            'csv': csv_file,
            'html': html_file
        }
    
    def _generate_text_report(self):
        """生成文本格式报告"""
        lines = []
        lines.append("=" * 80)
        lines.append("             Linux系统安全基线检查报告 v3.0 - 综合增强版")
        lines.append("=" * 80)
        lines.append(f"检查时间: {self.host_info.get('timestamp', 'N/A')}")
        lines.append(f"主机名: {self.host_info.get('hostname', 'N/A')}")
        lines.append(f"IP地址: {self.host_info.get('ip_address', 'N/A')}")
        lines.append(f"操作系统: {self.host_info.get('os_name', 'N/A')}")
        lines.append(f"内核版本: {self.host_info.get('kernel', 'N/A')}")
        lines.append("=" * 80)
        
        # 检查摘要
        lines.append("\n[检查摘要]")
        lines.append("-" * 80)
        total = self.stats['total']
        passed = self.stats['passed']
        failed = self.stats['failed']
        warning = self.stats['warning']
        critical = self.stats['critical']
        
        if total > 0:
            pass_rate = (passed / total) * 100
        else:
            pass_rate = 0
        
        lines.append(f"检查项总数: {total}")
        lines.append(f"通过项: {passed}")
        lines.append(f"失败项: {failed} (其中严重: {critical})")
        lines.append(f"警告项: {warning}")
        lines.append(f"通过率: {pass_rate:.1f}%")
        
        # 风险等级评估
        if critical > 0:
            risk_level = "高危"
            risk_desc = "发现严重安全问题，需要立即修复"
        elif failed > 3:
            risk_level = "中危"
            risk_desc = "存在多个安全问题，需要尽快修复"
        elif failed > 0:
            risk_level = "低危"
            risk_desc = "存在少量安全问题"
        else:
            risk_level = "安全"
            risk_desc = "未发现安全问题"
        
        lines.append(f"风险等级: {risk_level} ({risk_desc})")
        
        # 合规性摘要
        lines.append("\n[合规性摘要]")
        lines.append("-" * 80)
        
        standards_summary = {}
        for result in self.results:
            standards = result.get('standards', {})
            for standard, items in standards.items():
                if standard not in standards_summary:
                    standards_summary[standard] = {'total': 0, 'passed': 0}
                
                standards_summary[standard]['total'] += 1
                if result['status'] == 'PASS':
                    standards_summary[standard]['passed'] += 1
        
        for standard, stats in standards_summary.items():
            if stats['total'] > 0:
                rate = (stats['passed'] / stats['total']) * 100
                lines.append(f"{standard.upper()}: {stats['passed']}/{stats['total']} ({rate:.1f}%)")
        
        # 详细检查结果
        lines.append("\n[详细检查结果]")
        lines.append("-" * 80)
        
        categories = {}
        for result in self.results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        for category, items in categories.items():
            lines.append(f"\n{category}:")
            lines.append("-" * 60)
            
            for item in items:
                status = item['status']
                risk = item['risk']
                details = item['details']
                
                if status == 'PASS':
                    status_str = "[✓]"
                elif status == 'FAIL':
                    status_str = "[✗]"
                else:
                    status_str = "[!]"
                
                standards = item.get('standards', {})
                standards_str = ""
                if standards:
                    std_list = []
                    for std, items in standards.items():
                        std_list.append(f"{std}:{','.join(items)}")
                    standards_str = f" ({', '.join(std_list)})"
                
                lines.append(f"  {status_str} {item['item']} [{risk.upper()}]{standards_str}")
                lines.append(f"      详情: {details}")
        
        lines.append("\n" + "=" * 80)
        lines.append("报告结束")
        lines.append(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"工具版本: v3.0 综合增强版")
        
        return "\n".join(lines)
    
    def _generate_html_report(self, filename):
        """生成HTML格式报告"""
        # 计算通过率
        if self.stats['total'] > 0:
            pass_rate = (self.stats['passed'] / self.stats['total']) * 100
        else:
            pass_rate = 0
        
        # 风险等级评估
        if self.stats['critical'] > 0:
            risk_level = "高危"
            risk_class = "risk-high"
            risk_desc = "发现严重安全问题，需要立即修复"
        elif self.stats['failed'] > 3:
            risk_level = "中危"
            risk_class = "risk-medium"
            risk_desc = "存在多个安全问题，需要尽快修复"
        elif self.stats['failed'] > 0:
            risk_level = "低危"
            risk_class = "risk-low"
            risk_desc = "存在少量安全问题"
        else:
            risk_level = "安全"
            risk_class = "risk-safe"
            risk_desc = "未发现安全问题"
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux系统安全基线检查报告 v3.0</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
        }}
        .container::before {{
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 300px;
            height: 300px;
            background: linear-gradient(135deg, #667eea22 0%, #764ba222 100%);
            border-radius: 50%;
            transform: translate(150px, -150px);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 25px;
            margin-bottom: 40px;
            position: relative;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 32px;
            background: linear-gradient(45deg, #007acc, #00bcd4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 10px;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea11 0%, #764ba211 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-item {{
            text-align: center;
            padding: 25px 15px;
            border-radius: 10px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        .summary-item:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }}
        .summary-item::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
        }}
        .total {{ 
            background: #e3f2fd; 
            border: 2px solid #2196f3;
        }}
        .total::before {{ background: #2196f3; }}
        .passed {{ 
            background: #e8f5e9;
            border: 2px solid #4caf50;
        }}
        .passed::before {{ background: #4caf50; }}
        .failed {{ 
            background: #ffebee;
            border: 2px solid #f44336;
        }}
        .failed::before {{ background: #f44336; }}
        .warning {{ 
            background: #fff3e0;
            border: 2px solid #ff9800;
        }}
        .warning::before {{ background: #ff9800; }}
        .summary-item h3 {{
            margin: 0 0 10px 0;
            color: #37474f;
            font-size: 16px;
        }}
        .summary-item p {{
            margin: 0;
            font-size: 36px;
            font-weight: bold;
            color: #263238;
        }}
        .risk-assessment {{
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
            border-left: 5px solid;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 0 0 rgba(0,0,0,0.1); }}
            70% {{ box-shadow: 0 0 0 10px rgba(0,0,0,0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(0,0,0,0); }}
        }}
        .risk-high {{
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
            color: white;
            border-left-color: #c62828;
        }}
        .risk-medium {{
            background: linear-gradient(135deg, #ffb347 0%, #ffcc33 100%);
            color: #5d4037;
            border-left-color: #ff9800;
        }}
        .risk-low {{
            background: linear-gradient(135deg, #56ab2f 0%, #a8e063 100%);
            color: #1b5e20;
            border-left-color: #4caf50;
        }}
        .risk-safe {{
            background: linear-gradient(135deg, #00b09b 0%, #96c93d 100%);
            color: white;
            border-left-color: #00c853;
        }}
        .results {{
            margin-top: 40px;
        }}
        .category {{
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }}
        .category:hover {{
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }}
        .category-title {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .category-count {{
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 14px;
        }}
        .result-item {{
            padding: 20px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            align-items: flex-start;
            transition: all 0.3s ease;
        }}
        .result-item:hover {{
            background: #f8f9fa;
        }}
        .result-item:last-child {{
            border-bottom: none;
        }}
        .status {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 15px;
            min-width: 70px;
            text-align: center;
            flex-shrink: 0;
        }}
        .status-pass {{ 
            background: linear-gradient(135deg, #56ab2f 0%, #a8e063 100%);
            color: white;
            box-shadow: 0 3px 10px rgba(86, 171, 47, 0.3);
        }}
        .status-fail {{ 
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
            color: white;
            box-shadow: 0 3px 10px rgba(255, 65, 108, 0.3);
        }}
        .status-warning {{ 
            background: linear-gradient(135deg, #ffb347 0%, #ffcc33 100%);
            color: #5d4037;
            box-shadow: 0 3px 10px rgba(255, 179, 71, 0.3);
        }}
        .result-content {{
            flex-grow: 1;
        }}
        .result-title {{
            font-weight: bold;
            color: #37474f;
            margin-bottom: 8px;
            font-size: 16px;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 11px;
            margin-left: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .risk-critical {{ background: #ff1744; color: white; }}
        .risk-high {{ background: #ff5252; color: white; }}
        .risk-medium {{ background: #ffab40; color: white; }}
        .risk-low {{ background: #69f0ae; color: #1b5e20; }}
        .risk-info {{ background: #b3e5fc; color: #01579b; }}
        .details {{
            color: #546e7a;
            font-size: 14px;
            line-height: 1.5;
            margin-top: 5px;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #007acc;
        }}
        .standards {{
            margin-top: 8px;
            font-size: 12px;
            color: #78909c;
        }}
        .standard-tag {{
            display: inline-block;
            background: #e3f2fd;
            color: #1976d2;
            padding: 2px 8px;
            border-radius: 3px;
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        .timestamp {{
            color: #78909c;
            font-size: 13px;
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }}
        .progress-bar {{
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            margin: 20px 0;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(135deg, #56ab2f 0%, #a8e063 100%);
            border-radius: 4px;
            transition: width 1s ease-in-out;
        }}
        .chart-container {{
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            flex-wrap: wrap;
        }}
        .chart {{
            width: 200px;
            height: 200px;
            position: relative;
        }}
        .chart canvas {{
            width: 100% !important;
            height: 100% !important;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 20px;
            }}
            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .category-title {{
                flex-direction: column;
                align-items: flex-start;
            }}
            .category-count {{
                margin-top: 5px;
            }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Linux系统安全基线检查报告 v3.0</h1>
            <div class="subtitle">
                版本: v3.0 综合增强版 | 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="summary">
            <h2>系统信息</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0;">
                <div><strong>主机名:</strong> {self.host_info.get('hostname', 'N/A')}</div>
                <div><strong>IP地址:</strong> {self.host_info.get('ip_address', 'N/A')}</div>
                <div><strong>操作系统:</strong> {self.host_info.get('os_name', 'N/A')}</div>
                <div><strong>内核版本:</strong> {self.host_info.get('kernel', 'N/A')}</div>
            </div>
            
            <h2>检查摘要</h2>
            <div class="summary-grid">
                <div class="summary-item total">
                    <h3>检查项总数</h3>
                    <p>{self.stats['total']}</p>
                </div>
                <div class="summary-item passed">
                    <h3>通过</h3>
                    <p>{self.stats['passed']}</p>
                </div>
                <div class="summary-item failed">
                    <h3>失败</h3>
                    <p>{self.stats['failed']}</p>
                </div>
                <div class="summary-item warning">
                    <h3>警告</h3>
                    <p>{self.stats['warning']}</p>
                </div>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: {pass_rate}%;"></div>
            </div>
            <div style="text-align: center; margin: 10px 0; font-size: 18px; color: #37474f;">
                通过率: <strong>{pass_rate:.1f}%</strong>
            </div>
            
            <div class="risk-assessment {risk_class}">
                <h3 style="margin-top: 0;">风险等级评估</h3>
                <div style="font-size: 24px; font-weight: bold; margin: 10px 0;">{risk_level}</div>
                <p style="margin-bottom: 0;">{risk_desc}</p>
            </div>
        </div>
        
        <div class="results">
            <h2>详细检查结果</h2>"""
        
        # 按类别分组显示结果
        categories = {}
        for result in self.results:
            cat = result['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        for category, items in categories.items():
            # 计算类别通过率
            cat_total = len(items)
            cat_passed = len([i for i in items if i['status'] == 'PASS'])
            cat_rate = (cat_passed / cat_total * 100) if cat_total > 0 else 0
            
            html += f"""
            <div class="category">
                <div class="category-title">
                    <span>{category}</span>
                    <span class="category-count">{cat_passed}/{cat_total} ({cat_rate:.0f}%)</span>
                </div>"""
            
            for item in items:
                status_class = f"status-{item['status'].lower()}"
                risk_class = f"risk-{item['risk']}"
                
                # 生成标准标签
                standards_html = ""
                standards = item.get('standards', {})
                if standards:
                    standards_html = '<div class="standards">'
                    for std, items in standards.items():
                        for it in items:
                            standards_html += f'<span class="standard-tag">{std.upper()}: {it}</span>'
                    standards_html += '</div>'
                
                html += f"""
                <div class="result-item">
                    <span class="status {status_class}">{item['status']}</span>
                    <div class="result-content">
                        <div class="result-title">
                            {item['item']}
                            <span class="risk-badge {risk_class}">{item['risk'].upper()}</span>
                        </div>
                        {standards_html}
                        <div class="details">{item['details']}</div>
                    </div>
                </div>"""
            
            html += "</div>"
        
        # 添加图表
        html += """
            <div class="chart-container">
                <div class="chart">
                    <canvas id="resultsChart"></canvas>
                </div>
            </div>
        """
        
        html += f"""
        </div>
        
        <div class="timestamp">
            报告生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            工具版本: v3.0 综合增强版 | 维护团队: 55K-学安全<br>
            更新说明: 整合v2.1和v1.0所有优点，新增12个增强检查功能
        </div>
    </div>
    
    <script>
        // 创建结果图表
        const ctx = document.getElementById('resultsChart').getContext('2d');
        const resultsChart = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['通过', '失败', '警告'],
                datasets: [{{
                    data: [{self.stats['passed']}, {self.stats['failed']}, {self.stats['warning']}],
                    backgroundColor: [
                        '#4caf50',
                        '#f44336',
                        '#ff9800'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            font: {{
                                size: 14
                            }}
                        }}
                    }},
                    title: {{
                        display: true,
                        text: '检查结果分布',
                        font: {{
                            size: 16
                        }}
                    }}
                }}
            }}
        }});
        
        // 添加点击事件展开/收起详情
        document.querySelectorAll('.result-item').forEach(item => {{
            item.addEventListener('click', function() {{
                const details = this.querySelector('.details');
                if (details.style.display === 'none') {{
                    details.style.display = 'block';
                }} else {{
                    details.style.display = 'none';
                }}
            }});
        }});
    </script>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def generate_fix_commands(self):
        """生成修复命令"""
        fixes = []
        
        for result in self.results:
            if result['status'] == 'FAIL':
                item = result['item']
                details = result['details']
                
                # 1. 空密码账户问题
                if '空密码账户' in item:
                    match = re.search(r'发现真正空密码账户:\s*(\w+)', details)
                    if match:
                        username = match.group(1)
                        fixes.append({
                            'problem': '空密码账户',
                            'command': f'passwd {username}',
                            'description': f'为用户 {username} 设置密码',
                            'impact': '低'
                        })
                
                # 2. SSH允许Root密码登录
                elif 'SSH Root登录' in item and '允许Root密码登录' in details:
                    fixes.append({
                        'problem': 'SSH允许Root密码登录',
                        'command': "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd",
                        'description': '禁用SSH Root密码登录',
                        'impact': '需要重启SSH服务'
                    })
                
                # 3. SSH协议版本不安全
                elif 'SSH协议版本' in item and '不安全' in details:
                    fixes.append({
                        'problem': 'SSH协议版本不安全',
                        'command': "echo 'Protocol 2' >> /etc/ssh/sshd_config && systemctl restart sshd",
                        'description': '设置SSH协议版本为2',
                        'impact': '需要重启SSH服务'
                    })
                
                # 4. 防火墙未启用
                elif '防火墙状态' in item and '未发现活动的防火墙' in details:
                    if 'centos' in self.host_info.get('os_name', '').lower() or 'rhel' in self.host_info.get('os_name', '').lower():
                        fixes.append({
                            'problem': '防火墙未启用',
                            'command': "systemctl start firewalld && systemctl enable firewalld && firewall-cmd --set-default-zone=public",
                            'description': '启用并启动firewalld防火墙',
                            'impact': '会启用防火墙，请确认规则'
                        })
                    elif 'ubuntu' in self.host_info.get('os_name', '').lower() or 'debian' in self.host_info.get('os_name', '').lower():
                        fixes.append({
                            'problem': '防火墙未启用',
                            'command': "apt-get install ufw -y && ufw default deny && ufw enable",
                            'description': '安装并启用UFW防火墙',
                            'impact': '会安装新软件包并启用防火墙'
                        })
                
                # 5. SELinux未启用强制模式
                elif 'SELinux状态' in item and '未在强制模式' in details:
                    fixes.append({
                        'problem': 'SELinux未启用',
                        'command': "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && setenforce 1",
                        'description': '启用SELinux强制模式',
                        'impact': '需要重启系统生效，可能影响服务'
                    })
                
                # 6. 明文传输服务运行中
                elif '明文传输服务' in item and '发现运行的明文传输服务' in details:
                    fixes.append({
                        'problem': '明文传输服务运行中',
                        'command': "systemctl stop telnet && systemctl disable telnet && yum remove telnet-server -y",
                        'description': '停止并移除明文传输服务',
                        'impact': '会停止相关服务并删除软件包'
                    })
                
                # 7. 未配置登录失败锁定
                elif '登录失败锁定策略' in item and '未配置账户登录失败锁定策略' in details:
                    fixes.append({
                        'problem': '未配置登录失败锁定',
                        'command': "echo 'auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' >> /etc/pam.d/system-auth",
                        'description': '配置登录失败5次后锁定15分钟',
                        'impact': '会影响认证策略'
                    })
        
        return fixes
    
    def run_checks(self):
        """执行所有检查"""
        print("\nLinux系统安全基线检查工具 v3.0")
        print("开始安全检查...\n")
        
        start_time = datetime.datetime.now()
        
        # 1. 收集主机信息
        self.collect_host_info()
        print()  # 添加空行
        
        # 2. 定义所有检查项
        checks = [
            ('账户安全', self.check_account_security),
            ('SSH安全', self.check_ssh_security),
            ('文件权限', self.check_file_permissions),
            ('服务安全', self.check_services),
            ('防火墙', self.check_firewall),
            ('系统更新', self.check_updates),
            ('审计日志', self.check_audit_logging),
            ('内核安全', self.check_kernel_security),
            ('系统加固', self.check_system_hardening),
            ('恶意软件防护', self.check_malware_protection),
            ('Sudo安全', self.check_sudo_security),
            ('网络安全', self.check_network_security)
        ]
        
        # 3. 按顺序执行每个检查
        for check_name, check_func in checks:
            if self.args.skip and check_name.lower() in self.args.skip.lower():
                print(f"[!] 跳过 {check_name} 检查")
                continue
            
            print(f"[*] 正在检查: {check_name}")
            try:
                check_func()
            except Exception as e:
                self.add_result(
                    check_name, '检查执行', 'FAIL',
                    f'检查过程出错: {str(e)}',
                    'medium'
                )
                print(f"[!] {check_name} 检查出错: {e}")
        
        # 4. 生成报告
        reports = self.generate_report()
        
        # 5. 显示统计摘要
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n检查完成!")
        print(f"检查用时: {duration:.1f}秒")
        print(f"总计检查项: {self.stats['total']}")
        print(f"通过: {self.stats['passed']}")
        print(f"失败: {self.stats['failed']} (严重: {self.stats['critical']})")
        print(f"警告: {self.stats['warning']}")
        
        # 6. 显示风险等级评估
        if self.stats['critical'] > 0:
            print(f"\n⚠  风险等级: 高危")
            print(f"   发现严重安全问题，需要立即修复！")
        elif self.stats['failed'] > 3:
            print(f"\n⚠  风险等级: 中危")
            print(f"   存在多个安全问题，需要尽快修复")
        elif self.stats['failed'] > 0:
            print(f"\n⚠  风险等级: 低危")
            print(f"   存在少量安全问题")
        else:
            print(f"\n✓  风险等级: 安全")
            print(f"   未发现安全问题")
        
        # 7. 显示报告位置
        print(f"\n[+] 报告已生成:")
        print(f"  JSON报告: {reports['json']}")
        print(f"  文本报告: {reports['text']}")
        print(f"  CSV报告:  {reports['csv']}")
        print(f"  HTML报告: {reports['html']}")
        
        # 8. 根据检查结果返回适当的退出码
        if self.stats['critical'] > 0:
            return 2
        elif self.stats['failed'] > 0:
            return 1
        return 0

def main():
    """主函数 - 命令行入口点"""
    parser = argparse.ArgumentParser(
        description='Linux系统安全基线检查工具 v3.0 - 综合增强版\n'
                   '支持CIS、STIG、等保2.0、ISO27001等多个标准\n'
                   '整合v2.1和v1.0所有优点，新增12个增强检查功能',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
文档版本：v3.0 综合增强版
更新日期：2025年12月05日
适用系统：RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+
维护团队：55K-学安全
联系方式：通过"公众号、博客留言"

新增功能:
  - 账户登录失败锁定策略检查
  - SSH公钥认证和配置验证检查
  - 全局可写文件深度检查
  - Sudo语法验证和近期使用记录
  - 明文高危服务专项检查
  - ICMP重定向和ARP安全参数检查
  - 隐藏进程和可疑进程检查
  - 日志轮转配置检查
  - 可疑计划任务检查
  - 完整SUID/SGID文件分析
  - 网络监听端口进程关联检查
  - 系统最后更新时间检查

示例:
  %(prog)s                         # 执行完整检查
  %(prog)s -o ./reports            # 指定报告输出目录
  %(prog)s --skip "ssh,firewall"   # 跳过指定检查
  %(prog)s --check-suid           # 包含完整SUID/SGID检查
  %(prog)s --check-world-writable # 检查全局可写文件
  %(prog)s --quick                # 快速检查模式

风险等级:
  critical - 必须立即修复
  high     - 需要尽快修复
  medium   - 建议修复
  low      - 可选择性修复
  info     - 仅供参考
        '''
    )
    
    # 定义命令行参数
    parser.add_argument('-o', '--output', help='报告输出目录')
    parser.add_argument('--skip', help='跳过的检查项(逗号分隔)')
    parser.add_argument('--check-suid', action='store_true', help='执行完整SUID/SGID文件检查')
    parser.add_argument('--check-world-writable', action='store_true', help='检查全局可写文件')
    parser.add_argument('--json-only', action='store_true', help='只生成JSON报告')
    parser.add_argument('--quick', action='store_true', help='快速检查模式')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    parser.add_argument('--version', action='store_true', help='显示版本信息')
    
    # 解析命令行参数
    args = parser.parse_args()
    
    # 显示版本信息
    if args.version:
        print("Linux系统安全基线检查工具 v3.0 - 综合增强版")
        print("更新日期：2025年12月05日")
        print("适用系统：RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+")
        print("维护团队：55K-学安全")
        print("联系方式：公众号、博客留言")
        print("\n支持的合规标准:")
        print("  • CIS (Center for Internet Security)")
        print("  • STIG (Security Technical Implementation Guide)")
        print("  • 等保2.0 (网络安全等级保护2.0)")
        print("  • ISO27001 (信息安全管理体系)")
        print("\n新增功能:")
        print("  • 账户登录失败锁定策略检查")
        print("  • SSH公钥认证和配置验证检查")
        print("  • 全局可写文件深度检查")
        print("  • Sudo语法验证和近期使用记录")
        print("  • 明文高危服务专项检查")
        print("  • ICMP重定向和ARP安全参数检查")
        print("  • 隐藏进程和可疑进程检查")
        print("  • 日志轮转配置检查")
        print("  • 可疑计划任务检查")
        sys.exit(0)
    
    # 检查是否为root用户
    if os.geteuid() != 0:
        print("[!] 警告: 部分检查需要root权限")
        print("[!] 建议使用sudo运行此脚本")
        response = input("是否继续? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # 创建安全检查器实例并运行检查
    checker = SecurityBaselineChecker(args)
    return_code = checker.run_checks()
    
    sys.exit(return_code)

# 脚本入口点
if __name__ == '__main__':
    main()