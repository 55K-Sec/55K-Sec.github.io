import os
import stat
import pwd
import grp
import re
from utils.command_runner import run_command

def check_file_permissions(checker):
    critical_files = [
        ('/etc/passwd', 0o644, 'root', 'root'),
        ('/etc/shadow', None, 'root', 'root'),  # 特殊处理
        ('/etc/group', 0o644, 'root', 'root'),
        ('/etc/gshadow', None, 'root', 'root'),
        ('/etc/ssh/sshd_config', 0o600, 'root', 'root'),
        ('/etc/sudoers', 0o440, 'root', 'root'),
        ('/etc/crontab', 0o600, 'root', 'root'),
        ('/etc/hosts.allow', 0o644, 'root', 'root'),
        ('/etc/hosts.deny', 0o644, 'root', 'root')
    ]

    for path, expected_mode, owner, group in critical_files:
        if not os.path.exists(path):
            checker.add_result('文件权限', f'{os.path.basename(path)}', 'WARNING', '文件不存在', 'low')
            continue

        try:
            st = os.stat(path)
            actual_mode = stat.S_IMODE(st.st_mode)
            actual_owner = pwd.getpwuid(st.st_uid).pw_name
            actual_group = grp.getgrgid(st.st_gid).gr_name

            if path in ('/etc/shadow', '/etc/gshadow'):
                # shadow文件：属主root，权限≤640
                if st.st_uid == 0 and (actual_mode & 0o777) <= 0o640:
                    checker.add_result('文件权限', os.path.basename(path), 'PASS', f'权限: {oct(actual_mode)}', 'low')
                else:
                    checker.add_result('文件权限', os.path.basename(path), 'FAIL', f'权限不安全: {oct(actual_mode)}', 'critical')
            else:
                if actual_mode == expected_mode and actual_owner == owner and actual_group == group:
                    checker.add_result('文件权限', os.path.basename(path), 'PASS', f'权限正确: {oct(actual_mode)}', 'low')
                else:
                    checker.add_result('文件权限', os.path.basename(path), 'WARNING',
                        f'期望 {oct(expected_mode)}/{owner}:{group}, 实际 {oct(actual_mode)}/{actual_owner}:{actual_group}',
                        'medium')
        except Exception as e:
            checker.add_result('文件权限', os.path.basename(path), 'FAIL', f'检查异常: {e}', 'medium')

    # 全局可写文件
    if getattr(checker.args, 'check_world_writable', False):
        _check_world_writable_files(checker)

    # SUID/SGID
    if getattr(checker.args, 'check_suid', False):
        _check_suid_sgid_detailed(checker)
    else:
        _check_suid_sgid_basic(checker)

def _check_world_writable_files(checker):
    cmd = "find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | head -50"
    code, output, _ = run_command(cmd)
    if code == 0 and output.strip():
        files = [f for f in output.strip().split('\n') if f]
        suspicious = [f for f in files if not any(tmp in f for tmp in ['/tmp/', '/var/tmp/'])]
        if suspicious:
            checker.add_result('文件权限', '全局可写文件', 'FAIL', f'发现 {len(suspicious)} 个可疑全局可写文件', 'high')
            for i, f in enumerate(suspicious[:5]):
                checker.add_result('文件权限', f'全局可写 #{i+1}', 'INFO', f, 'info')
        else:
            checker.add_result('文件权限', '全局可写文件', 'PASS', '仅临时目录存在', 'low')
    else:
        checker.add_result('文件权限', '全局可写文件', 'PASS', '未发现', 'low')

def _check_suid_sgid_basic(checker):
    suid_count = 0
    suspicious = []
    for fp in checker.common_suid_files:
        if os.path.exists(fp):
            try:
                st = os.stat(fp)
                if st.st_mode & stat.S_ISUID:
                    suid_count += 1
                    if st.st_uid != 0:
                        suspicious.append(fp)
            except:
                pass
    if suspicious:
        for f in suspicious[:5]:
            checker.add_result('文件权限', '非常规SUID文件', 'WARNING', f'SUID且非root属主: {f}', 'medium')
    checker.add_result('文件权限', '常见SUID检查', 'INFO', f'共检查{len(checker.common_suid_files)}个，发现{suid_count}个SUID', 'info')

def _check_suid_sgid_detailed(checker):
    cmd = "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"
    code, output, _ = run_command(cmd)
    if code == 0 and output.strip():
        files = output.strip().split('\n')
        checker.add_result('文件权限', '完整SUID/SGID扫描', 'INFO', f'共发现 {len(files)} 个特权文件', 'info')
        # 可进一步分析...
    else:
        checker.add_result('文件权限', '完整SUID/SGID扫描', 'INFO', '未发现或命令失败', 'info')