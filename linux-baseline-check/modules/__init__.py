"""
安全检查模块集合
每个模块实现一类基线安全检查逻辑，可独立测试与复用
"""

# 导入所有检查函数，便于统一管理或动态调用（可选）
from .account_security import check_account_security
from .ssh_security import check_ssh_security
from .file_permissions import check_file_permissions
from .services import check_services
from .firewall import check_firewall
from .system_updates import check_system_updates
from .audit_logging import check_audit_logging
from .kernel_security import check_kernel_security
from .system_hardening import check_system_hardening
from .malware_protection import check_malware_protection
from .sudo_security import check_sudo_security
from .network_security import check_network_security

# 定义公开接口
__all__ = [
    'check_account_security',
    'check_ssh_security',
    'check_file_permissions',
    'check_services',
    'check_firewall',
    'check_system_updates',
    'check_audit_logging',
    'check_kernel_security',
    'check_system_hardening',
    'check_malware_protection',
    'check_sudo_security',
    'check_network_security'
]