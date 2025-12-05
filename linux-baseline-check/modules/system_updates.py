def check_system_updates(checker):
    """检查系统最后更新时间"""
    
    # 定义包管理器日志路径和检查方法
    package_managers = [
        {
            'name': 'APT',
            'log_path': '/var/log/apt/history.log',
            'command': "grep 'Start-Date' /var/log/apt/history.log | tail -1",
            'desc': '最后APT更新'
        },
        {
            'name': 'YUM',
            'log_path': '/var/log/yum.log',
            'command': "tail -1 /var/log/yum.log",
            'desc': '最后YUM更新'
        },
        {
            'name': 'DNF',
            'log_path': '/var/log/dnf.log',
            'command': "grep -E 'Start-Date|Transaction started' /var/log/dnf.log | tail -1",
            'desc': '最后DNF更新'
        }
    ]
    
    # 遍历所有包管理器
    found = False
    for pm in package_managers:
        if os.path.exists(pm['log_path']):
            # 执行对应的检查命令
            code, out, _ = checker.run_command(pm['command'])
            
            if code == 0 and out.strip():
                checker.add_result('系统更新', pm['desc'], 'INFO', out.strip(), 'info')
            else:
                checker.add_result('系统更新', pm['desc'], 'WARNING', 
                                 f'无法确定最后更新时间({pm["name"]})', 'low')
            
            found = True
            break
    
    # 如果没有找到任何包管理器日志
    if not found:
        checker.add_result('系统更新', '包管理器日志', 'WARNING', 
                         '未找到APT/YUM/DNF日志文件', 'low')