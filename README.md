# Linux安全基线检查工具 v3.0

## 📌 快速开始
```bash
# 完整检查（需root权限）
sudo python3 security_checker_v3.py

# 快速检查
sudo python3 security_checker_v3.py --quick

# 指定输出目录
sudo python3 security_checker_v3.py -o ./reports
```

## 🎯 核心功能
- **12类安全检查**：账户、SSH、文件权限、服务、防火墙等
- **4种报告格式**：JSON/HTML/CSV/文本
- **自动修复建议**：根据检查结果生成修复命令
- **多标准支持**：CIS、STIG、等保2.0、ISO27001

## 🔍 检查项目
1. **账户安全** - 空密码、UID为0账户、锁定策略
2. **SSH安全** - 协议版本、Root登录、认证方式
3. **文件权限** - 关键文件权限、SUID/SGID、全局可写
4. **服务安全** - 监听端口、明文服务、高危端口
5. **防火墙** - iptables/firewalld/UFW状态
6. **系统更新** - 可用更新、最后更新时间
7. **审计日志** - auditd服务、日志轮转
8. **内核安全** - 内核参数配置
9. **系统加固** - SELinux、时间同步、隐藏进程
10. **恶意软件防护** - 防病毒软件、可疑进程
11. **Sudo安全** - sudoers权限、语法验证
12. **网络安全** - TCP Wrappers、ICMP配置

## 📊 输出示例
```
检查完成!
检查用时: 45.2秒
总计检查项: 215
通过: 180
失败: 15 (严重: 3)
警告: 20
风险等级: 中危
```

## 📁 报告文件
```
reports/
├── security_audit_YYYYMMDD_HHMMSS.json
├── security_audit_YYYYMMDD_HHMMSS.html
├── security_audit_YYYYMMDD_HHMMSS.txt
└── security_audit_YYYYMMDD_HHMMSS.csv
```

## ⚡ 常用命令
```bash
# 跳过特定检查
sudo python3 security_checker_v3.py --skip "ssh,firewall"

# 检查全局可写文件
sudo python3 security_checker_v3.py --check-world-writable

# 检查SUID/SGID文件
sudo python3 security_checker_v3.py --check-suid

# 只生成JSON报告
sudo python3 security_checker_v3.py --json-only

# 显示版本
python3 security_checker_v3.py --version
```

## 🏷️ 版本信息
- **版本**: v3.0 综合增强版
- **更新日期**: 2025年12月05日
- **适用系统**: RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+
- **维护团队**: 55K-学安全

## 📝 注意事项
1. 建议使用root权限运行完整检查
2. 生产环境先测试再修复
3. 完整检查约需5-10分钟
4. 修复前备份重要配置文件
