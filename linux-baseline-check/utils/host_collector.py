import socket
import platform
import os
from .command_runner import run_command

def collect_host_info():
    info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'machine': platform.machine(),
        'python_version': platform.python_version()
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['ip_address'] = s.getsockname()[0]
        s.close()
    except:
        info['ip_address'] = "Unknown"

    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    info['os_name'] = line.split('=', 1)[1].strip().strip('"')
                elif line.startswith('VERSION_ID='):
                    info['os_version'] = line.split('=', 1)[1].strip().strip('"')

    code, out, _ = run_command("uname -r")
    if code == 0:
        info['kernel'] = out.strip()

    code, out, _ = run_command("uptime -p")
    if code == 0:
        info['uptime'] = out.strip()

    return info