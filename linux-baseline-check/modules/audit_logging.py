def check_audit_logging(checker):
    # 检查 auditd 是否运行
    code, out, _ = checker.run_command("systemctl is-active auditd 2>/dev/null")
    if code == 0 and out.strip() == 'active':
        checker.add_result('审计日志', 'auditd服务', 'PASS', 'auditd正在运行', 'low')
    else:
        checker.add_result('审计日志', 'auditd服务', 'WARNING', 'auditd未运行', 'medium')

    # 检查日志轮转
    if os.path.exists('/etc/logrotate.d/rsyslog') or os.path.exists('/etc/logrotate.conf'):
        checker.add_result('审计日志', '日志轮转', 'PASS', '发现日志轮转配置', 'low')
    else:
        checker.add_result('审计日志', '日志轮转', 'WARNING', '未发现日志轮转配置', 'medium')