import os

def generate_text_report(report_dir, timestamp, host_info, stats, results):
    filename = os.path.join(report_dir, f"security_audit_{timestamp}.txt")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("Linux系统安全基线检查报告\n")
        f.write("=" * 50 + "\n")
        f.write(f"主机: {host_info.get('hostname', 'N/A')} ({host_info.get('ip_address', 'N/A')})\n")
        f.write(f"时间: {host_info.get('timestamp', 'N/A')}\n\n")
        f.write("检查摘要:\n")
        f.write(f"  总计: {stats['total']}\n")
        f.write(f"  通过: {stats['passed']}\n")
        f.write(f"  警告: {stats['warning']}\n")
        f.write(f"  失败: {stats['failed']} (严重: {stats['critical']})\n\n")
        f.write("详细结果:\n")
        for r in results:
            f.write(f"[{r['status']}] {r['category']} - {r['item']}: {r['details']} (风险: {r['risk']})\n")
    return filename