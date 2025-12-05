def check_firewall(checker):
    # 检查 firewalld 或 iptables 是否启用
    for svc in ['firewalld', 'ufw', 'iptables']:
        code, out, _ = checker.run_command(f"systemctl is-active {svc} 2>/dev/null")
        if code == 0 and out.strip() == 'active':
            checker.add_result('防火墙', '防火墙状态', 'PASS', f'{svc} 已启用', 'low')
            return
    checker.add_result('防火墙', '防火墙状态', 'FAIL', '未检测到活动防火墙', 'medium')