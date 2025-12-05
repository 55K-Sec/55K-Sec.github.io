import csv
import os

def generate_csv_report(report_dir, timestamp, results):
    filename = os.path.join(report_dir, f"security_audit_{timestamp}.csv")
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'category', 'item', 'status', 'risk', 'details'])
        writer.writeheader()
        for r in results:
            writer.writerow({
                'id': r['id'],
                'category': r['category'],
                'item': r['item'],
                'status': r['status'],
                'risk': r['risk'],
                'details': r['details']
            })
    return filename