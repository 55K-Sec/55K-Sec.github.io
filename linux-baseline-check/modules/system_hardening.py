import os
import re

def check_system_hardening(checker):
    """
    检查系统加固配置，包括核心转储、权限掩码、安全登录等
    """
    results = []
    
    # 1. 检查 Core Dumps
    code, out, _ = checker.run_command("ulimit -c")
    if code == 0 and out.strip() == '0':
        results.append(('Core Dumps', 'PASS', '已禁用', 'low'))
    else:
        results.append(('Core Dumps', 'WARNING', '未禁用，建议设置ulimit -c 0', 'medium'))
    
    # 2. 检查默认umask
    umask_configs = ['/etc/profile', '/etc/bashrc', '/etc/login.defs']
    umask_found = False
    umask_value = None
    
    for config_file in umask_configs:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    # 查找umask设置
                    matches = re.findall(r'umask\s+(\d{3})', content)
                    if matches:
                        umask_value = matches[-1]  # 取最后一个设置
                        umask_found = True
                        break
            except Exception:
                continue
    
    if umask_found and umask_value in ['027', '077']:
        results.append(('默认umask', 'PASS', f'已设置为{umask_value}', 'low'))
    else:
        current_umask = os.umask(0)
        os.umask(current_umask)  # 恢复原始umask
        results.append(('默认umask', 'WARNING', 
                       f'当前会话umask: {oct(current_umask)[-3:]}，建议设置为027或077', 
                       'medium'))
    
    # 3. 检查 Ctrl+Alt+Del 禁用
    ctrl_alt_del_disabled = False
    disabled_msg = ""
    
    # 检查systemd系统
    code, out, _ = checker.run_command("systemctl is-enabled ctrl-alt-del.target 2>/dev/null")
    if code == 0 and "masked" in out:
        ctrl_alt_del_disabled = True
        disabled_msg = "systemd已屏蔽ctrl-alt-del.target"
    elif os.path.exists("/etc/systemd/system/ctrl-alt-del.target"):
        # 检查是否被软链接到/dev/null
        real_path = os.path.realpath("/etc/systemd/system/ctrl-alt-del.target")
        if real_path == "/dev/null":
            ctrl_alt_del_disabled = True
            disabled_msg = "通过软链接到/dev/null禁用"
    
    # 检查inittab（传统init系统）
    if os.path.exists('/etc/inittab'):
        with open('/etc/inittab', 'r') as f:
            content = f.read()
            if 'ca::ctrlaltdel:' in content and 'shutdown' not in content.lower():
                ctrl_alt_del_disabled = True
                disabled_msg = "inittab中已注释或修改Ctrl+Alt+Del设置"
    
    if ctrl_alt_del_disabled:
        results.append(('Ctrl+Alt+Del', 'PASS', disabled_msg, 'low'))
    else:
        results.append(('Ctrl+Alt+Del', 'WARNING', '未禁用Ctrl+Alt+Del重启功能', 'medium'))
    
    # 4. 检查su命令限制
    pam_su_files = ['/etc/pam.d/su', '/etc/pam.d/common-auth']
    wheel_group_restricted = False
    
    for pam_file in pam_su_files:
        if os.path.exists(pam_file):
            try:
                with open(pam_file, 'r') as f:
                    content = f.read()
                    # 检查是否限制为wheel组
                    if 'pam_wheel.so' in content and 'use_uid' in content:
                        wheel_group_restricted = True
                        break
            except Exception:
                continue
    
    if wheel_group_restricted:
        results.append(('su命令限制', 'PASS', '已限制仅wheel组可使用su', 'low'))
    else:
        results.append(('su命令限制', 'FAIL', '未限制wheel组使用su命令', 'high'))
    
    # 5. 检查空密码登录
    no_empty_password = True
    pam_files_to_check = ['/etc/pam.d/login', '/etc/pam.d/sshd', 
                         '/etc/pam.d/system-auth', '/etc/pam.d/common-auth']
    
    for pam_file in pam_files_to_check:
        if os.path.exists(pam_file):
            try:
                with open(pam_file, 'r') as f:
                    content = f.read()
                    # 检查是否包含nullok或nullok_secure
                    if re.search(r'nullok(_secure)?', content):
                        no_empty_password = False
            except Exception:
                continue
    
    if no_empty_password:
        results.append(('空密码登录', 'PASS', '已禁止空密码登录', 'low'))
    else:
        results.append(('空密码登录', 'FAIL', '允许空密码登录，存在安全风险', 'high'))
    
    # 6. 额外检查：SSH空密码登录（补充）
    sshd_config = '/etc/ssh/sshd_config'
    if os.path.exists(sshd_config):
        try:
            with open(sshd_config, 'r') as f:
                content = f.read()
                if 'PermitEmptyPasswords no' in content:
                    results.append(('SSH空密码', 'PASS', 'SSH已禁止空密码登录', 'low'))
                elif 'PermitEmptyPasswords yes' in content:
                    results.append(('SSH空密码', 'FAIL', 'SSH允许空密码登录', 'high'))
        except Exception:
            pass
    
    # 批量添加结果
    for check_name, status, details, risk_level in results:
        checker.add_result('系统加固', check_name, status, details, risk_level)