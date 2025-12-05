import os
import re
import stat
import pwd
from utils.command_runner import run_command

def check_account_security(checker):
    """检查账户安全配置"""
    
    # 1. 空密码账户检查
    if os.path.exists('/etc/shadow'):
        empty_found = False
        locked_accounts = []
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 2:
                    continue
                user, passwd = parts[0], parts[1]
                if passwd == '':
                    empty_found = True
                    checker.add_result('账户安全', '空密码账户', 'FAIL', f'发现空密码账户: {user}', 'critical')
                elif passwd in ['!!', '*', '!'] or passwd.startswith('!'):
                    locked_accounts.append(user)
        
        if not empty_found:
            checker.add_result('账户安全', '空密码账户', 'PASS', '未发现空密码账户', 'low')

        # 锁定账户分类
        system_users = {'root', 'bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 
                       'mail', 'operator', 'games', 'ftp', 'nobody', 'systemd-network', 
                       'dbus', 'polkitd', 'sshd', 'postfix', 'chrony', 'rpc', 'rpcuser'}
        
        locked_user = [u for u in locked_accounts if u not in system_users]
        if locked_user:
            user_list = ", ".join(locked_user[:10])  # 显示前10个
            checker.add_result('账户安全', '用户账户锁定', 'WARNING', 
                              f'用户账户被锁定: {user_list} (共{len(locked_user)}个)', 'medium')

    # 2. UID=0 非 root 账户检查
    if os.path.exists('/etc/passwd'):
        uid0_nonroot = []
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                    # 获取账户信息
                    shell = parts[-1] if len(parts) > 6 else 'unknown'
                    uid0_nonroot.append(f"{parts[0]} (shell: {shell})")
        
        if uid0_nonroot:
            for u in uid0_nonroot:
                checker.add_result('账户安全', 'UID为0非root账户', 'FAIL', 
                                  f'发现非root的UID=0账户: {u}', 'critical')
        else:
            checker.add_result('账户安全', 'UID为0非root账户', 'PASS', '除root外无UID=0账户', 'low')

    # 3. 密码策略检查
    if os.path.exists('/etc/login.defs'):
        with open('/etc/login.defs', 'r') as f:
            content = f.read()
        
        # 最长有效期
        max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
        if max_days:
            days = int(max_days.group(1))
            if days <= 90:
                checker.add_result('账户安全', '密码最长有效期', 'PASS', f'{days}天 (≤90)', 'low')
            else:
                checker.add_result('账户安全', '密码最长有效期', 'FAIL', f'{days}天 (>90)', 'medium')
        else:
            checker.add_result('账户安全', '密码最长有效期', 'FAIL', '未配置密码最长有效期', 'medium')
        
        # 最短有效期
        min_days = re.search(r'PASS_MIN_DAYS\s+(\d+)', content)
        if min_days:
            days = int(min_days.group(1))
            if days >= 1:
                checker.add_result('账户安全', '密码最短有效期', 'PASS', f'{days}天 (≥1)', 'low')
            else:
                checker.add_result('账户安全', '密码最短有效期', 'FAIL', '应≥1天', 'low')
        else:
            checker.add_result('账户安全', '密码最短有效期', 'FAIL', '未配置密码最短有效期', 'low')
        
        # 密码过期警告
        warn_age = re.search(r'PASS_WARN_AGE\s+(\d+)', content)
        if warn_age:
            days = int(warn_age.group(1))
            if 7 <= days <= 14:
                checker.add_result('账户安全', '密码过期警告', 'PASS', f'提前{days}天警告', 'low')
            else:
                checker.add_result('账户安全', '密码过期警告', 'WARNING', 
                                  f'建议提前7-14天警告（当前{days}天）', 'low')
        else:
            checker.add_result('账户安全', '密码过期警告', 'FAIL', '未配置密码过期警告', 'low')

    # 4. 密码强度检查
    pwquality_conf_files = ['/etc/security/pwquality.conf', '/etc/pam.d/system-auth', 
                           '/etc/pam.d/password-auth', '/etc/pam.d/common-password']
    
    for conf_file in pwquality_conf_files:
        if os.path.exists(conf_file):
            with open(conf_file, 'r') as f:
                content = f.read()
            
            # 最小长度检查
            minlen_match = re.search(r'minlen\s*=\s*(\d+)', content)
            if minlen_match:
                minlen = int(minlen_match.group(1))
                if minlen >= 8:
                    checker.add_result('账户安全', '密码最小长度', 'PASS', f"{minlen}位 (≥8)", 'low')
                else:
                    checker.add_result('账户安全', '密码最小长度', 'FAIL', f'不足8位（当前{minlen}位）', 'medium')
                break
    else:
        checker.add_result('账户安全', '密码最小长度', 'FAIL', '未配置密码最小长度', 'medium')
    
    # 复杂度要求检查
    for conf_file in pwquality_conf_files:
        if os.path.exists(conf_file):
            with open(conf_file, 'r') as f:
                content = f.read()
            
            # 检查是否包含复杂度要求
            has_complexity = False
            complexity_items = []
            
            if 'dcredit' in content:
                complexity_items.append('数字')
                has_complexity = True
            if 'ucredit' in content:
                complexity_items.append('大写字母')
                has_complexity = True
            if 'lcredit' in content:
                complexity_items.append('小写字母')
                has_complexity = True
            if 'ocredit' in content:
                complexity_items.append('特殊字符')
                has_complexity = True
            
            if has_complexity:
                checker.add_result('账户安全', '密码复杂度', 'PASS', 
                                  f'要求包含: {", ".join(complexity_items)}', 'low')
                break
    else:
        checker.add_result('账户安全', '密码复杂度', 'FAIL', '未配置密码复杂度要求', 'medium')

    # 5. 登录失败锁定策略
    pam_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', 
                 '/etc/pam.d/common-auth', '/etc/pam.d/login', '/etc/pam.d/sshd']
    
    lockout_found = False
    for pf in pam_files:
        if os.path.exists(pf):
            with open(pf, 'r') as f:
                content = f.read()
            
            if 'pam_tally2' in content or 'pam_faillock' in content:
                lockout_found = True
                if 'pam_tally2' in content:
                    deny = re.search(r'deny=(\d+)', content)
                    unlock = re.search(r'unlock_time=(\d+)', content)
                    if deny and unlock:
                        checker.add_result('账户安全', '登录失败锁定', 'PASS', 
                                          f"失败{deny.group(1)}次后锁定{unlock.group(1)}秒", 'low')
                    else:
                        checker.add_result('账户安全', '登录失败锁定', 'WARNING', 
                                          'pam_tally2参数不完整', 'medium')
                elif 'pam_faillock' in content:
                    checker.add_result('账户安全', '登录失败锁定', 'PASS', 
                                      '已配置pam_faillock', 'low')
                break
    
    if not lockout_found:
        checker.add_result('账户安全', '登录失败锁定', 'FAIL', '未配置登录失败锁定策略', 'high')

    # 6. 长期未登录账户检查
    try:
        # 使用lastlog命令检查90天内未登录的用户
        code, out, _ = run_command("lastlog -b 90 | tail -n +2 | awk '$1 !~ /^root$/ && $1 !~ /^Username/ {print $1}'")
        if code == 0 and out.strip():
            users = out.strip().split('\n')
            if len(users) > 10:
                checker.add_result('账户安全', '长期未登录账户', 'WARNING', 
                                  f'90天未登录账户: {", ".join(users[:5])}... (共{len(users)}个)', 'medium')
            else:
                checker.add_result('账户安全', '长期未登录账户', 'WARNING', 
                                  f'90天未登录账户: {", ".join(users)}', 'medium')
        else:
            checker.add_result('账户安全', '长期未登录账户', 'PASS', '无90天以上未登录账户', 'low')
    except Exception as e:
        checker.add_result('账户安全', '长期未登录账户', 'INFO', f'检查失败: {str(e)}', 'info')

    # 7. 密码哈希算法检查
    if os.path.exists('/etc/shadow'):
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    if line.startswith('root:'):
                        pass_hash = line.split(':')[1]
                        break
                else:
                    pass_hash = ''
            
            if pass_hash:
                if pass_hash.startswith('$6$'):  # sha512
                    checker.add_result('账户安全', '密码哈希算法', 'PASS', '使用SHA-512算法', 'low')
                elif pass_hash.startswith('$5$'):  # sha256
                    checker.add_result('账户安全', '密码哈希算法', 'WARNING', '使用SHA-256算法(建议使用SHA-512)', 'medium')
                elif pass_hash.startswith('$1$'):  # md5
                    checker.add_result('账户安全', '密码哈希算法', 'FAIL', '使用不安全的MD5算法', 'high')
                elif pass_hash.startswith('$2'):  # bcrypt
                    checker.add_result('账户安全', '密码哈希算法', 'PASS', '使用bcrypt算法', 'low')
                else:
                    checker.add_result('账户安全', '密码哈希算法', 'INFO', f'使用未知算法: {pass_hash[:10]}...', 'info')
        except Exception as e:
            checker.add_result('账户安全', '密码哈希算法', 'INFO', f'检查失败: {str(e)}', 'info')

    # 8. 默认账户检查
    default_users = ['guest', 'test', 'user', 'admin', 'oracle', 'mysql', 'postgres']
    if os.path.exists('/etc/passwd'):
        try:
            with open('/etc/passwd', 'r') as f:
                users = [line.split(':')[0] for line in f]
            
            risky_users = [u for u in default_users if u in users]
            if risky_users:
                checker.add_result('账户安全', '默认账户', 'WARNING', 
                                  f'存在未删除默认账户: {", ".join(risky_users)}', 'medium')
            else:
                checker.add_result('账户安全', '密码哈希算法', 'PASS', '无风险默认账户', 'low')
        except Exception as e:
            checker.add_result('账户安全', '默认账户', 'INFO', f'检查失败: {str(e)}', 'info')

    # 9. 检查root用户的shell配置（新增）
    if os.path.exists('/etc/passwd'):
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.startswith('root:'):
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            shell = parts[-1]
                            if shell not in ['/bin/bash', '/usr/bin/bash', '/sbin/sh']:
                                checker.add_result('账户安全', 'root用户shell', 'WARNING', 
                                                  f'root用户使用非常用shell: {shell}', 'medium')
                            break
        except Exception:
            pass

    # 10. 检查sudo配置（新增）
    sudoers_files = ['/etc/sudoers', '/etc/sudoers.d/']
    try:
        code, out, _ = run_command("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -5")
        if code == 0 and out.strip():
            lines = out.strip().split('\n')
            checker.add_result('账户安全', 'sudo免密配置', 'WARNING', 
                              f'存在sudo免密配置: {lines[0][:50]}...', 'medium')
    except Exception:
        pass