# Linux 系统安全基线检查工具

## 支持环境
- 操作系统：RHEL/CentOS 7+、Ubuntu 16.04+、Debian 9+
- Python 版本：3.6 及以上（推荐 3.8+）

## 安装与使用
```bash
# 克隆仓库
git clone https://github.com/[username]/linux-baseline-check.git
cd linux-baseline-check

# （可选）安装扩展依赖（支持YAML自定义规则、进度条）
pip3 install -r requirements.txt

# 基本使用
sudo python3 main.py -o ./reports

# 高级用法（检查SUID+全局可写文件，跳过SSH检查）
sudo python3 main.py --check-suid --check-world-writable --skip "SSH安全" -o ./reports
