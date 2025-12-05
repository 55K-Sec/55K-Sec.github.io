import os
import re

def check_kernel_security(checker):
    """检查内核安全配置"""
    
    # 1. ICMP重定向检查（融合两个版本）
    redirect_files = [
        '/proc/sys/net/ipv4/conf/all/accept_redirects',
        '/proc/sys/net/ipv4/conf/default/accept_redirects'
    ]
    redirect_ok = True
    redirect_status = []
    
    for f in redirect_files:
        if os.path.exists(f):
            try:
                with open(f, 'r') as fd:
                    value = fd.read().strip()
                    status = "禁用" if value == '0' else "启用"
                    redirect_status.append(f"{os.path.basename(f)}: {status}({value})")
                    if value != '0':
                        redirect_ok = False
            except Exception:
                redirect_status.append(f"{os.path.basename(f)}: 读取失败")
                redirect_ok = False
    
    if redirect_ok:
        checker.add_result('内核安全', 'ICMP重定向', 'PASS', 
                          f'已禁用ICMP重定向\n{" | ".join(redirect_status)}', 'low')
    else:
        checker.add_result('内核安全', 'ICMP重定向', 'FAIL', 
                          f'未完全禁用ICMP重定向\n{" | ".join(redirect_status)}', 'medium')

    # 2. ARP安全（融合两个检查项）
    # 2.1 ARP反向路径过滤（原第一版本）
    rp_filter_files = [
        '/proc/sys/net/ipv4/conf/all/rp_filter',
        '/proc/sys/net/ipv4/conf/default/rp_filter'
    ]
    rp_filter_ok = True
    rp_status = []
    
    for f in rp_filter_files:
        if os.path.exists(f):
            try:
                with open(f, 'r') as fd:
                    value = fd.read().strip()
                    is_ok = value in ('1', '2')
                    rp_status.append(f"{os.path.basename(f)}: {value}")
                    if not is_ok:
                        rp_filter_ok = False
            except Exception:
                rp_status.append(f"{os.path.basename(f)}: 读取失败")
                rp_filter_ok = False
    
    # 2.2 ARP忽略（原第二版本）
    arp_ignore_files = [
        '/proc/sys/net/ipv4/conf/all/arp_ignore',
        '/proc/sys/net/ipv4/conf/default/arp_ignore'
    ]
    arp_ignore_ok = True
    arp_ignore_status = []
    
    for f in arp_ignore_files:
        if os.path.exists(f):
            try:
                with open(f, 'r') as fd:
                    value = fd.read().strip()
                    is_ok = value == '1'
                    arp_ignore_status.append(f"{os.path.basename(f)}: {value}")
                    if not is_ok:
                        arp_ignore_ok = False
            except Exception:
                arp_ignore_status.append(f"{os.path.basename(f)}: 读取失败")
                arp_ignore_ok = False
    
    # 合并ARP安全结果
    if rp_filter_ok and arp_ignore_ok:
        checker.add_result('内核安全', 'ARP安全', 'PASS', 
                          f'ARP防护配置良好\n反向路径过滤: {" | ".join(rp_status)}\nARP忽略: {" | ".join(arp_ignore_status)}', 'low')
    elif rp_filter_ok:
        checker.add_result('内核安全', 'ARP安全', 'WARNING', 
                          f'ARP反向路径过滤已启用，但ARP忽略未配置\n反向路径过滤: {" | ".join(rp_status)}\nARP忽略: {" | ".join(arp_ignore_status)}', 'medium')
    else:
        checker.add_result('内核安全', 'ARP安全', 'FAIL', 
                          f'ARP防护配置不完整\n反向路径过滤: {" | ".join(rp_status)}\nARP忽略: {" | ".join(arp_ignore_status)}', 'medium')

    # 3. 地址空间随机化（新增）
    aslr_file = '/proc/sys/kernel/randomize_va_space'
    if os.path.exists(aslr_file):
        try:
            with open(aslr_file, 'r') as f:
                aslr = f.read().strip()
            if aslr == '2':
                checker.add_result('内核安全', '地址空间随机化', 'PASS', 
                                  '启用完整ASLR保护 (值: 2)', 'low')
            elif aslr == '1':
                checker.add_result('内核安全', '地址空间随机化', 'WARNING', 
                                  '部分ASLR保护 (值: 1)，建议设为2以获得完整保护', 'medium')
            else:
                checker.add_result('内核安全', '地址空间随机化', 'FAIL', 
                                  f'未启用ASLR保护 (值: {aslr})，建议设为2', 'high')
        except Exception as e:
            checker.add_result('内核安全', '地址空间随机化', 'ERROR', 
                              f'读取ASLR配置失败: {str(e)}', 'high')
    else:
        checker.add_result('内核安全', '地址空间随机化', 'WARNING', 
                          'ASLR配置文件不存在，系统可能不支持', 'medium')

    # 4. SELinux/AppArmor状态（新增）
    # 先检查SELinux
    selinux_file = '/etc/selinux/config'
    selinux_enabled = False
    selinux_mode = 'unknown'
    
    if os.path.exists(selinux_file):
        try:
            with open(selinux_file, 'r') as f:
                content = f.read()
            match = re.search(r'^SELINUX=(\w+)', content, re.MULTILINE)
            if match:
                selinux_mode = match.group(1).lower()
                selinux_enabled = selinux_mode in ['enforcing', 'permissive']
        except Exception as e:
            checker.add_result('内核安全', '强制访问控制', 'ERROR', 
                              f'读取SELinux配置失败: {str(e)}', 'medium')
    
    if selinux_enabled:
        if selinux_mode == 'enforcing':
            checker.add_result('内核安全', 'SELinux', 'PASS', 
                              f'SELinux已启用并处于强制模式 ({selinux_mode})', 'low')
        else:
            checker.add_result('内核安全', 'SELinux', 'WARNING', 
                              f'SELinux处于宽容模式 ({selinux_mode})，建议设为enforcing', 'medium')
    else:
        # 检查AppArmor
        code, out, _ = checker.run_command("aa-status --enabled 2>/dev/null")
        if code == 0:
            checker.add_result('内核安全', 'AppArmor', 'PASS', 
                              'AppArmor已启用', 'low')
        else:
            # 检查是否安装了AppArmor但未启用
            code, out, _ = checker.run_command("dpkg -l | grep apparmor 2>/dev/null | head -1")
            if code == 0 and out.strip():
                checker.add_result('内核安全', '强制访问控制', 'WARNING', 
                                  'AppArmor已安装但未启用', 'high')
            else:
                checker.add_result('内核安全', '强制访问控制', 'FAIL', 
                                  '未启用SELinux或AppArmor，建议至少启用其一', 'high')

    # 5. SYN洪水防护（新增）
    syncookie_files = [
        '/proc/sys/net/ipv4/tcp_syncookies',
        '/proc/sys/net/ipv4/tcp_synack_retries'  # 额外检查项
    ]
    syncookie_ok = True
    syncookie_status = []
    
    for f in syncookie_files:
        if os.path.exists(f):
            try:
                with open(f, 'r') as fd:
                    value = fd.read().strip()
                    filename = os.path.basename(f)
                    if filename == 'tcp_syncookies':
                        is_ok = value == '1'
                        status = "启用" if is_ok else "禁用"
                        syncookie_status.append(f"Syncookies: {status}({value})")
                        if not is_ok:
                            syncookie_ok = False
                    else:  # tcp_synack_retries
                        # 值越小越安全，通常建议<=2
                        try:
                            retries = int(value)
                            if retries <= 2:
                                syncookie_status.append(f"SYNACK重试: 安全({retries})")
                            else:
                                syncookie_status.append(f"SYNACK重试: 偏高({retries})")
                        except ValueError:
                            syncookie_status.append(f"SYNACK重试: 异常值({value})")
            except Exception:
                syncookie_status.append(f"{os.path.basename(f)}: 读取失败")
    
    if syncookie_ok:
        checker.add_result('内核安全', 'SYN洪水防护', 'PASS', 
                          f'SYN洪水防护已启用\n{" | ".join(syncookie_status)}', 'low')
    else:
        checker.add_result('内核安全', 'SYN洪水防护', 'FAIL', 
                          f'未启用SYN洪水防护\n{" | ".join(syncookie_status)}', 'medium')