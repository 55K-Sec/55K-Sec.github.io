import json
import os

def generate_json_report(report_dir, timestamp, metadata, host_info, stats, results):
    data = {
        'metadata': metadata,
        'host_info': host_info,
        'statistics': stats,
        'results': results
    }
    filename = os.path.join(report_dir, f"security_audit_{timestamp}.json")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filename