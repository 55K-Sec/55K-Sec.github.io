def check_services(checker):
    # 明文高危服务检查（FTP, Telnet, rsh等）
    dangerous_services = ['vsftpd', 'telnet', 'rsh', 'rexec', 'rlogin']
    for svc in dangerous_services:
        code, out, _ = checker.run_command(f"systemctl is-active {svc} 2>/dev/null")
        if code == 0 and out.strip() == 'active':
            checker.add_result('服务安全', '明文高危服务', 'FAIL', f'发现运行中的危险服务: {svc}', 'high')
    checker.add_result('服务安全', '明文高危服务', 'PASS', '未发现明文高危服务运行', 'low')