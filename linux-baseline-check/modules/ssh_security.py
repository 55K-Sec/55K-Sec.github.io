import os
import re
from utils.command_runner import run_command

def check_ssh_security(checker):
    """检查SSH服务安全配置"""
    sshd_config = '/etc/ssh/sshd_config'
    
    # 检查配置文件是否存在
    if not os.path.exists(sshd_config):
        checker.add_result('SSH安全', '配置文件', 'FAIL', 'SSH配置文件不存在', 'high')
        return
    
    # 读取配置文件内容
    try:
        with open(sshd_config, 'r') as f:
            content = f.read()
    except Exception as e:
        checker.add_result('SSH安全', '配置文件', 'FAIL', f'无法读取配置文件: {str(e)}', 'high')
        return
    
    # 1. 协议版本检查
    proto = re.search(r'^Protocol\s+(\d+)', content, re.MULTILINE)
    if proto:
        if proto.group(1) == '2':
            checker.add_result('SSH安全', '协议版本', 'PASS', '仅使用SSHv2协议', 'low')
        else:
            checker.add_result('SSH安全', '协议版本', 'FAIL', f'使用了不安全的协议版本: {proto.group(1)}', 'critical')
    else:
        checker.add_result('SSH安全', '协议版本', 'INFO', '未显式配置协议版本(默认SSHv2)', 'low')
    
    # 2. Root登录权限检查
    root_login = re.search(r'^PermitRootLogin\s+(\S+)', content, re.MULTILINE)
    if root_login:
        val = root_login.group(1).lower()
        if val in ('no', 'prohibit-password', 'without-password'):
            checker.add_result('SSH安全', 'Root登录', 'PASS', f'已限制Root登录方式: {root_login.group(1)}', 'low')
        else:
            checker.add_result('SSH安全', 'Root登录', 'FAIL', f'允许Root密码登录: {val}', 'high')
    else:
        checker.add_result('SSH安全', 'Root登录', 'FAIL', '未配置PermitRootLogin(默认允许)', 'high')
    
    # 3. 空密码登录检查
    empty_pw = re.search(r'^PermitEmptyPasswords\s+(yes|no)', content, re.MULTILINE)
    if empty_pw:
        if empty_pw.group(1).lower() == 'no':
            checker.add_result('SSH安全', '空密码登录', 'PASS', '已禁止空密码登录', 'low')
        else:
            checker.add_result('SSH安全', '空密码登录', 'FAIL', '允许使用空密码登录', 'critical')
    else:
        checker.add_result('SSH安全', '空密码登录', 'INFO', '未配置PermitEmptyPasswords(默认禁止)', 'low')
    
    # 4. 密码认证检查
    pw_auth = re.search(r'^PasswordAuthentication\s+(yes|no)', content, re.MULTILINE)
    if pw_auth:
        if pw_auth.group(1).lower() == 'no':
            checker.add_result('SSH安全', '密码认证', 'PASS', '已禁用密码认证(强制使用密钥)', 'low')
        else:
            checker.add_result('SSH安全', '密码认证', 'WARNING', '启用了密码认证，建议禁用并仅使用密钥', 'medium')
    else:
        checker.add_result('SSH安全', '密码认证', 'INFO', '未配置PasswordAuthentication(默认启用)', 'medium')
    
    # 5. 公钥认证检查
    pubkey = re.search(r'^PubkeyAuthentication\s+(yes|no)', content, re.MULTILINE)
    if pubkey:
        if pubkey.group(1).lower() == 'yes':
            checker.add_result('SSH安全', '公钥认证', 'PASS', '已启用公钥认证', 'low')
        else:
            checker.add_result('SSH安全', '公钥认证', 'FAIL', '未启用公钥认证', 'medium')
    else:
        checker.add_result('SSH安全', '公钥认证', 'INFO', '未配置PubkeyAuthentication(默认启用)', 'low')
    
    # 6. 加密算法检查（新增）
    ciphers = re.search(r'^Ciphers\s+(.+)', content, re.MULTILINE)
    insecure_ciphers = ['arcfour', 'blowfish', 'cast128', '3des']
    if ciphers:
        used_insecure = [c for c in insecure_ciphers if c in ciphers.group(1).lower()]
        if used_insecure:
            checker.add_result('SSH安全', '加密算法', 'FAIL', f'使用了不安全的加密算法: {", ".join(used_insecure)}', 'high')
        else:
            checker.add_result('SSH安全', '加密算法', 'PASS', '仅使用安全的加密算法', 'low')
    else:
        checker.add_result('SSH安全', '加密算法', 'INFO', '未明确配置Ciphers(使用系统默认)', 'medium')
    
    # 7. 最大认证尝试次数检查
    max_tries = re.search(r'^MaxAuthTries\s+(\d+)', content, re.MULTILINE)
    if max_tries:
        tries = int(max_tries.group(1))
        if tries <= 3:
            checker.add_result('SSH安全', '最大尝试次数', 'PASS', f'{tries}次 (≤3次，符合安全要求)', 'low')
        else:
            checker.add_result('SSH安全', '最大尝试次数', 'FAIL', f'{tries}次 (>3次，建议减小)', 'medium')
    else:
        checker.add_result('SSH安全', '最大尝试次数', 'WARNING', '未配置MaxAuthTries(默认6次，建议设置为3)', 'medium')
    
    # 8. 连接空闲超时检查
    alive = re.search(r'^ClientAliveInterval\s+(\d+)', content, re.MULTILINE)
    if alive:
        interval = int(alive.group(1))
        if interval <= 300:  # 5分钟
            checker.add_result('SSH安全', '空闲超时', 'PASS', f'{interval}秒 (≤300秒，符合安全要求)', 'low')
        else:
            checker.add_result('SSH安全', '空闲超时', 'WARNING', f'{interval}秒 (>300秒，建议减小)', 'low')
    else:
        checker.add_result('SSH安全', '空闲超时', 'WARNING', '未配置ClientAliveInterval(无空闲超时)', 'medium')
    
    # 9. 访问源限制检查（新增）
    allow_users = re.search(r'^AllowUsers\s+', content, re.MULTILINE)
    allow_groups = re.search(r'^AllowGroups\s+', content, re.MULTILINE)
    deny_users = re.search(r'^DenyUsers\s+', content, re.MULTILINE)
    deny_groups = re.search(r'^DenyGroups\s+', content, re.MULTILINE)
    
    if allow_users or allow_groups or deny_users or deny_groups:
        checker.add_result('SSH安全', '访问控制', 'PASS', '已配置访问控制列表(Allow/Deny Users/Groups)', 'low')
    else:
        checker.add_result('SSH安全', '访问控制', 'WARNING', '未配置访问控制列表(全局开放)', 'medium')
    
    # 10. Banner配置检查（新增）
    banner = re.search(r'^Banner\s+(.+)', content, re.MULTILINE)
    if banner:
        banner_file = banner.group(1).strip()
        if os.path.exists(banner_file):
            checker.add_result('SSH安全', '登录Banner', 'PASS', f'已配置登录Banner: {banner_file}', 'low')
        else:
            checker.add_result('SSH安全', '登录Banner', 'WARNING', f'Banner文件不存在: {banner_file}', 'medium')
    else:
        checker.add_result('SSH安全', '登录Banner', 'INFO', '未配置登录Banner', 'low')
    
    # 11. 检查SSH服务状态
    code, out, _ = run_command("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null")
    if code == 0 and out.strip() == 'active':
        checker.add_result('SSH安全', '服务状态', 'PASS', 'SSH服务运行正常', 'low')
        
        # 12. 检查配置文件语法
        code, out, err = run_command("sshd -t 2>&1")
        if code == 0:
            checker.add_result('SSH安全', '配置语法', 'PASS', '配置文件语法正确', 'low')
        else:
            checker.add_result('SSH安全', '配置语法', 'FAIL', f'配置文件语法错误: {err.strip()}', 'high')
    else:
        checker.add_result('SSH安全', '服务状态', 'WARNING', 'SSH服务未运行或状态异常', 'medium')