COMPLIANCE_MAPPING = {
    'account_policy': {
        'cis': ['5.2.1', '5.3.1', '5.4.1'],
        'stig': ['V-719', 'V-720'],
        'dengbao': ['8.1.4.2'],
        'iso27001': ['A.9.2.1']
    },
    'ssh_security': {
        'cis': ['5.2.8', '5.2.9'],
        'stig': ['V-722'],
        'dengbao': ['8.1.4.5'],
        'iso27001': ['A.13.1.1']
    },
    'file_permissions': {
        'cis': ['6.1.2', '6.1.3'],
        'stig': ['V-779', 'V-780'],
        'dengbao': ['8.1.4.3'],
        'iso27001': ['A.12.1.1']
    },
    'firewall': {
        'cis': ['3.5.1', '3.5.2'],
        'stig': ['V-722', 'V-723'],
        'dengbao': ['8.1.5.1'],
        'iso27001': ['A.13.1.3']
    },
    'audit': {
        'cis': ['4.1.1', '4.1.2'],
        'stig': ['V-810', 'V-811'],
        'dengbao': ['8.1.7.1'],
        'iso27001': ['A.12.4.1']
    }
}

COMMON_SUID_FILES = [
    '/bin/su', '/bin/ping', '/bin/mount', '/bin/umount',
    '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh',
    '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp',
    '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/chage',
    '/usr/bin/at', '/usr/bin/crontab', '/usr/bin/wall'
]

RISK_LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0
}