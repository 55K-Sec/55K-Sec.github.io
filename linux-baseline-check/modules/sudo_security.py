def check_sudo_security(checker):
    # Sudo语法检查
    code, out, err = checker.run_command("visudo -c")
    if code == 0:
        checker.add_result('Sudo安全', 'Sudo语法', 'PASS', '语法正确', 'low')
    else:
        checker.add_result('Sudo安全', 'Sudo语法', 'FAIL', f'语法错误: {err}', 'high')

    # 近期Sudo使用
    if os.path.exists('/var/log/auth.log'):
        code, out, _ = checker.run_command("grep 'sudo:' /var/log/auth.log | tail -3")
        if code == 0 and out.strip():
            checker.add_result('Sudo安全', '近期Sudo使用', 'INFO', '最近3条记录:\n' + out, 'info')
        else:
            checker.add_result('Sudo安全', '近期Sudo使用', 'INFO', '无近期Sudo使用记录', 'info')