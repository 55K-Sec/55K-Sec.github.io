import subprocess

def run_command(cmd: str, capture_output: bool = True):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture_output,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时"
    except Exception as e:
        return -1, "", str(e)