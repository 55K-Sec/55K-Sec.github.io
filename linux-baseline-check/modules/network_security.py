import os
import re

def check_network_security(checker):
    """
    检查系统网络安全配置，包括：
    1. 监听端口状态
    2. IPv6启用状态
    3. 防火墙状态
    4. IP转发配置
    """
    
    # 1. 监听端口检查
    _check_listening_ports(checker)
    
    # 2. IPv6状态检查
    _check_ipv6_status(checker)
    
    # 3. 防火墙规则检查
    _check_firewall_status(checker)
    
    # 4. IP转发检查
    _check_ip_forwarding(checker)


def _check_listening_ports(checker):
    """检查系统监听端口"""
    code, out, _ = checker.run_command("ss -tuln")
    
    if code == 0:
        lines = out.strip().split('\n')
        if len(lines) > 1:
            # 提取端口号（最多显示前4个）
            ports = []
            for line in lines[1:5]:  # 跳过表头
                parts = line.split()
                if len(parts) >= 5:
                    address = parts[4]
                    port = address.split(":")[-1]
                    ports.append(port)
            
            port_info = f"共 {len(lines)-1} 个监听端口"
            if ports:
                port_info += f"（示例端口：{', '.join(ports)}）"
                
            checker.add_result('网络安全', '监听端口', 'INFO', port_info, 'info')
        else:
            checker.add_result('网络安全', '监听端口', 'INFO', '无监听端口', 'info')
    else:
        checker.add_result('网络安全', '监听端口', 'WARNING', 
                          '无法获取监听端口信息', 'medium')


def _check_ipv6_status(checker):
    """检查IPv6启用状态"""
    ipv6_file = '/proc/sys/net/ipv6/conf/all/disable_ipv6'
    
    if not os.path.exists(ipv6_file):
        checker.add_result('网络安全', 'IPv6状态', 'INFO', 
                          'IPv6配置文件不存在', 'info')
        return
    
    try:
        with open(ipv6_file, 'r') as f:
            ipv6_disabled = f.read().strip() == '1'
        
        if ipv6_disabled:
            checker.add_result('网络安全', 'IPv6状态', 'PASS', 
                              '已禁用IPv6（未使用场景）', 'low')
        else:
            checker.add_result('网络安全', 'IPv6状态', 'INFO', 
                              'IPv6已启用', 'info')
    except (IOError, PermissionError) as e:
        checker.add_result('网络安全', 'IPv6状态', 'WARNING', 
                          f'无法读取IPv6状态: {str(e)}', 'medium')


def _check_firewall_status(checker):
    """检查防火墙状态"""
    firewall_configs = [
        {
            'name': 'ufw',
            'check_cmd': 'ufw status',
            'active_pattern': r'Status:\s*active'
        },
        {
            'name': 'firewalld',
            'check_cmd': 'firewall-cmd --state',
            'active_pattern': r'running'
        },
        {
            'name': 'iptables',
            'check_cmd': 'iptables -L -n',
            'active_pattern': r'^(?!Chain INPUT \(policy ACCEPT\))'  # 非默认ACCEPT策略
        }
    ]
    
    firewall_active = False
    
    for fw in firewall_configs:
        code, out, _ = checker.run_command(fw['check_cmd'])
        
        if code == 0:
            # 使用正则表达式匹配活跃状态
            if re.search(fw['active_pattern'], out, re.MULTILINE | re.IGNORECASE):
                firewall_active = True
                checker.add_result('网络安全', '防火墙状态', 'PASS', 
                                  f'{fw["name"]}已激活并配置规则', 'low')
                return  # 找到活跃防火墙即返回
    
    # 未发现活跃防火墙
    if not firewall_active:
        checker.add_result('网络安全', '防火墙状态', 'FAIL', 
                          '未启用有效的防火墙或未配置规则', 'high')


def _check_ip_forwarding(checker):
    """检查IP转发配置"""
    ip_forward_files = [
        '/proc/sys/net/ipv4/ip_forward',
        '/proc/sys/net/ipv6/conf/all/forwarding'
    ]
    
    for file_path in ip_forward_files:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            is_enabled = content == '1'
            protocol = 'IPv4' if 'ipv4' in file_path else 'IPv6'
            
            if is_enabled:
                checker.add_result('网络安全', f'{protocol}转发', 'INFO', 
                                  f'{protocol}转发已启用（适用于路由/网关场景）', 'info')
            else:
                checker.add_result('网络安全', f'{protocol}转发', 'PASS', 
                                  f'{protocol}转发已禁用（适用于主机场景）', 'low')
                
        except (IOError, PermissionError) as e:
            protocol = 'IPv4' if 'ipv4' in file_path else 'IPv6'
            checker.add_result('网络安全', f'{protocol}转发', 'WARNING', 
                              f'无法读取{protocol}转发配置: {str(e)}', 'medium')