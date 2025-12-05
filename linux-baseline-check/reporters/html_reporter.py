import os
import datetime
from collections import defaultdict

def generate_html_report(report_dir, timestamp, host_info, stats, results):
    """
    生成专业的HTML安全审计报告
    """
    # 计算通过率
    pass_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
    fail_rate = (stats['failed'] / stats['total'] * 100) if stats['total'] > 0 else 0
    warning_rate = (stats['warning'] / stats['total'] * 100) if stats['total'] > 0 else 0
    
    # 风险等级评估
    if stats['critical'] > 3:
        risk_level = "危急"
        risk_class = "risk-critical"
        risk_desc = "发现多个严重安全问题，需要立即处理！"
        risk_score = "90-100"
    elif stats['critical'] > 0:
        risk_level = "高危"
        risk_class = "risk-high"
        risk_desc = "发现严重安全问题，需要立即修复"
        risk_score = "70-89"
    elif stats['failed'] > 5:
        risk_level = "中危"
        risk_class = "risk-medium"
        risk_desc = "存在多个安全问题，需要尽快修复"
        risk_score = "40-69"
    elif stats['failed'] > 0:
        risk_level = "低危"
        risk_class = "risk-low"
        risk_desc = "存在少量安全问题，建议修复"
        risk_score = "20-39"
    else:
        risk_level = "安全"
        risk_class = "risk-safe"
        risk_desc = "未发现安全问题，系统状态良好"
        risk_score = "0-19"
    
    # 按类别分组结果并统计
    categories = defaultdict(list)
    category_stats = defaultdict(lambda: {'total': 0, 'passed': 0, 'failed': 0, 'warning': 0})
    
    for r in results:
        cat = r['category']
        categories[cat].append(r)
        category_stats[cat]['total'] += 1
        if r['status'] == 'PASS':
            category_stats[cat]['passed'] += 1
        elif r['status'] == 'FAIL':
            category_stats[cat]['failed'] += 1
        elif r['status'] == 'WARNING':
            category_stats[cat]['warning'] += 1
    
    # 格式化检查时间
    try:
        check_time = datetime.datetime.fromisoformat(host_info.get('timestamp', datetime.datetime.now().isoformat()))
        check_time_str = check_time.strftime('%Y-%m-%d %H:%M:%S')
    except:
        check_time_str = host_info.get('timestamp', 'N/A')
    
    # 生成报告时间
    report_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 生成HTML内容
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux系统安全基线检查报告</title>
    <style>
        /* 基础样式 */
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Microsoft YaHei', 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.15);
            overflow: hidden;
        }}
        
        /* 头部样式 */
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
            font-weight: 600;
            letter-spacing: 1px;
        }}
        
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        
        .header-info {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }}
        
        .info-item {{
            text-align: center;
            flex: 1;
            min-width: 200px;
        }}
        
        .info-label {{
            font-size: 14px;
            opacity: 0.8;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            font-size: 18px;
            font-weight: bold;
        }}
        
        /* 风险指示器 */
        .risk-indicator {{
            background: #fff;
            padding: 25px;
            border-radius: 10px;
            margin: 20px 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .risk-level {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .risk-icon {{
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: bold;
            color: white;
        }}
        
        .risk-critical .risk-icon {{ background: #dc3545; }}
        .risk-high .risk-icon {{ background: #fd7e14; }}
        .risk-medium .risk-icon {{ background: #ffc107; }}
        .risk-low .risk-icon {{ background: #28a745; }}
        .risk-safe .risk-icon {{ background: #20c997; }}
        
        .risk-text h3 {{
            font-size: 24px;
            margin-bottom: 5px;
        }}
        
        .risk-text p {{
            color: #666;
        }}
        
        .risk-score {{
            text-align: center;
        }}
        
        .score-value {{
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .score-label {{
            color: #666;
            font-size: 14px;
        }}
        
        /* 统计卡片 */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 0 40px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }}
        
        .stat-card.total {{
            border-top: 4px solid #007bff;
        }}
        
        .stat-card.passed {{
            border-top: 4px solid #28a745;
        }}
        
        .stat-card.failed {{
            border-top: 4px solid #dc3545;
        }}
        
        .stat-card.warning {{
            border-top: 4px solid #ffc107;
        }}
        
        .stat-card.critical {{
            border-top: 4px solid #6f42c1;
        }}
        
        .stat-value {{
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .stat-label {{
            font-size: 16px;
            color: #666;
        }}
        
        .stat-percent {{
            font-size: 14px;
            color: #999;
            margin-top: 5px;
        }}
        
        /* 进度条 */
        .progress-container {{
            padding: 0 40px;
            margin-bottom: 40px;
        }}
        
        .progress-bar {{
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 20px 0;
            position: relative;
        }}
        
        .progress-fill {{
            height: 100%;
            position: absolute;
            left: 0;
            top: 0;
            transition: width 1s ease-in-out;
        }}
        
        .progress-passed {{
            background: linear-gradient(90deg, #28a745, #20c997);
            width: {pass_rate}%;
        }}
        
        .progress-failed {{
            background: linear-gradient(90deg, #dc3545, #fd7e14);
            width: {fail_rate}%;
            left: {pass_rate}%;
        }}
        
        .progress-warning {{
            background: linear-gradient(90deg, #ffc107, #ffca2c);
            width: {warning_rate}%;
            left: {pass_rate + fail_rate}%;
        }}
        
        .progress-labels {{
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 14px;
            color: #666;
        }}
        
        /* 检查结果 */
        .results-section {{
            padding: 0 40px 40px;
        }}
        
        .category {{
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            border: 1px solid #e0e0e0;
        }}
        
        .category-header {{
            background: linear-gradient(135deg, #4a6fa5 0%, #6a93cb 100%);
            color: white;
            padding: 18px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.3s ease;
        }}
        
        .category-header:hover {{
            background: linear-gradient(135deg, #3a5a85 0%, #5a83bb 100%);
        }}
        
        .category-title {{
            font-size: 18px;
            font-weight: 600;
        }}
        
        .category-stats {{
            display: flex;
            gap: 15px;
            font-size: 14px;
        }}
        
        .category-stat {{
            background: rgba(255, 255, 255, 0.2);
            padding: 5px 12px;
            border-radius: 20px;
        }}
        
        .category-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }}
        
        .category-content.expanded {{
            max-height: 5000px;
        }}
        
        /* 结果项 */
        .result-item {{
            padding: 20px 25px;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            align-items: flex-start;
            transition: background 0.3s ease;
        }}
        
        .result-item:hover {{
            background: #f8f9fa;
        }}
        
        .result-item:last-child {{
            border-bottom: none;
        }}
        
        .status-badge {{
            flex-shrink: 0;
            width: 80px;
            padding: 8px 5px;
            border-radius: 6px;
            text-align: center;
            font-size: 12px;
            font-weight: bold;
            margin-right: 20px;
        }}
        
        .status-PASS {{
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        
        .status-FAIL {{
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        
        .status-WARNING {{
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }}
        
        .status-INFO {{
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }}
        
        .result-content {{
            flex-grow: 1;
        }}
        
        .result-title {{
            font-weight: 600;
            font-size: 16px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .risk-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .risk-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .risk-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .risk-medium {{
            background: #ffc107;
            color: #212529;
        }}
        
        .risk-low {{
            background: #28a745;
            color: white;
        }}
        
        .risk-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .result-details {{
            color: #666;
            font-size: 14px;
            line-height: 1.6;
            margin-top: 8px;
        }}
        
        .result-meta {{
            display: flex;
            gap: 15px;
            margin-top: 10px;
            font-size: 12px;
            color: #888;
        }}
        
        /* 页脚 */
        .footer {{
            background: #f8f9fa;
            padding: 25px 40px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .footer-info {{
            color: #666;
            font-size: 14px;
        }}
        
        .footer-actions {{
            display: flex;
            gap: 10px;
        }}
        
        .btn {{
            padding: 8px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
        }}
        
        .btn-print {{
            background: #6c757d;
            color: white;
        }}
        
        .btn-print:hover {{
            background: #5a6268;
        }}
        
        .btn-export {{
            background: #007bff;
            color: white;
        }}
        
        .btn-export:hover {{
            background: #0056b3;
        }}
        
        /* 响应式设计 */
        @media (max-width: 768px) {{
            .header-info, .risk-indicator, .stats-grid {{
                padding: 20px;
                margin: 20px;
            }}
            
            .results-section {{
                padding: 0 20px 20px;
            }}
            
            .category-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}
            
            .category-stats {{
                align-self: flex-start;
            }}
            
            .result-item {{
                flex-direction: column;
                gap: 15px;
            }}
            
            .status-badge {{
                width: auto;
                align-self: flex-start;
            }}
            
            .footer {{
                flex-direction: column;
                text-align: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>Linux系统安全基线检查报告</h1>
            <div class="subtitle">专业安全审计报告 v3.0</div>
            <div class="header-info">
                <div class="info-item">
                    <div class="info-label">主机名称</div>
                    <div class="info-value">{host_info.get('hostname', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">IP地址</div>
                    <div class="info-value">{host_info.get('ip_address', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">操作系统</div>
                    <div class="info-value">{host_info.get('os_name', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">检查时间</div>
                    <div class="info-value">{check_time_str}</div>
                </div>
            </div>
        </div>
        
        <!-- 风险指示器 -->
        <div class="risk-indicator {risk_class}">
            <div class="risk-level">
                <div class="risk-icon">{risk_level[0]}</div>
                <div class="risk-text">
                    <h3>安全风险等级: {risk_level}</h3>
                    <p>{risk_desc}</p>
                </div>
            </div>
            <div class="risk-score">
                <div class="score-value">{risk_score}</div>
                <div class="score-label">风险分数</div>
            </div>
        </div>
        
        <!-- 统计卡片 -->
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-label">总检查项</div>
                <div class="stat-value">{stats['total']}</div>
                <div class="stat-percent">100%</div>
            </div>
            <div class="stat-card passed">
                <div class="stat-label">通过</div>
                <div class="stat-value">{stats['passed']}</div>
                <div class="stat-percent">{pass_rate:.1f}%</div>
            </div>
            <div class="stat-card failed">
                <div class="stat-label">失败</div>
                <div class="stat-value">{stats['failed']}</div>
                <div class="stat-percent">{fail_rate:.1f}%</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">警告</div>
                <div class="stat-value">{stats['warning']}</div>
                <div class="stat-percent">{warning_rate:.1f}%</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-label">严重问题</div>
                <div class="stat-value">{stats['critical']}</div>
                <div class="stat-percent">{stats['critical']/stats['total']*100:.1f if stats['total'] > 0 else 0}%</div>
            </div>
        </div>
        
        <!-- 进度条 -->
        <div class="progress-container">
            <div class="progress-bar">
                <div class="progress-fill progress-passed"></div>
                <div class="progress-fill progress-failed"></div>
                <div class="progress-fill progress-warning"></div>
            </div>
            <div class="progress-labels">
                <span>通过: {pass_rate:.1f}% ({stats['passed']})</span>
                <span>失败: {fail_rate:.1f}% ({stats['failed']})</span>
                <span>警告: {warning_rate:.1f}% ({stats['warning']})</span>
            </div>
        </div>
        
        <!-- 检查结果 -->
        <div class="results-section">
            <h2 style="margin-bottom: 25px; color: #2c3e50;">详细检查结果</h2>
            {"".join([f'''
            <div class="category">
                <div class="category-header" onclick="toggleCategory('{cat.replace(' ', '_')}')">
                    <div class="category-title">{cat}</div>
                    <div class="category-stats">
                        <div class="category-stat">总: {category_stats[cat]['total']}</div>
                        <div class="category-stat" style="color: #28a745;">✓ {category_stats[cat]['passed']}</div>
                        <div class="category-stat" style="color: #dc3545;">✗ {category_stats[cat]['failed']}</div>
                        <div class="category-stat" style="color: #ffc107;">⚠ {category_stats[cat]['warning']}</div>
                    </div>
                </div>
                <div class="category-content" id="{cat.replace(' ', '_')}">
                    {"".join([f'''
                    <div class="result-item">
                        <div class="status-badge status-{item['status']}">{item['status']}</div>
                        <div class="result-content">
                            <div class="result-title">
                                {item['item']}
                                <span class="risk-badge risk-{item['risk']}">{item['risk'].upper()}</span>
                            </div>
                            <div class="result-details">{item['details']}</div>
                            <div class="result-meta">
                                <span>ID: {item.get('id', 'N/A')}</span>
                                <span>规则: {item.get('rule', 'N/A')}</span>
                                <span>建议: {item.get('recommendation', '请参考安全最佳实践')}</span>
                            </div>
                        </div>
                    </div>
                    ''' for item in items])}
                </div>
            </div>
            ''' for cat, items in categories.items()])}
        </div>
        
        <!-- 页脚 -->
        <div class="footer">
            <div class="footer-info">
                <p>报告生成时间: {report_time} | 工具版本: v3.0 | 安全基线标准: CIS Linux Benchmark</p>
                <p>© 2023 安全运维团队 | 本报告仅用于内部安全审计，请勿外传</p>
            </div>
            <div class="footer-actions">
                <button class="btn btn-print" onclick="window.print()">打印报告</button>
                <button class="btn btn-export" onclick="exportReport()">导出PDF</button>
            </div>
        </div>
    </div>
    
    <script>
        // 切换类别展开/收起
        function toggleCategory(categoryId) {{
            const content = document.getElementById(categoryId);
            content.classList.toggle('expanded');
            
            // 更新所有相同类别的状态
            const headers = document.querySelectorAll('.category-header');
            headers.forEach(header => {{
                if (header.getAttribute('onclick').includes(categoryId)) {{
                    const icon = header.querySelector('.toggle-icon') || (() => {{
                        const icon = document.createElement('span');
                        icon.className = 'toggle-icon';
                        icon.innerHTML = '▼';
                        header.appendChild(icon);
                        return icon;
                    }})();
                    icon.style.transform = content.classList.contains('expanded') 
                        ? 'rotate(180deg)' 
                        : 'rotate(0deg)';
                }}
            }});
        }}
        
        // 默认展开第一个类别
        document.addEventListener('DOMContentLoaded', function() {{
            const firstCategory = document.querySelector('.category-header');
            if (firstCategory) {{
                const categoryId = firstCategory.getAttribute('onclick').match(/'([^']+)'/)[1];
                toggleCategory(categoryId);
            }}
        }});
        
        // 导出PDF（模拟功能）
        function exportReport() {{
            alert('PDF导出功能需要后端支持。请将HTML文件保存后使用浏览器打印功能生成PDF。');
            window.print();
        }}
        
        // 打印样式优化
        window.onbeforeprint = function() {{
            // 展开所有类别以便打印
            document.querySelectorAll('.category-content').forEach(content => {{
                content.classList.add('expanded');
            }});
        }};
        
        // 高亮严重问题
        document.addEventListener('DOMContentLoaded', function() {{
            const criticalItems = document.querySelectorAll('.risk-critical');
            criticalItems.forEach(item => {{
                item.closest('.result-item').style.animation = 'pulse 2s infinite';
            }});
            
            // 添加脉冲动画
            const style = document.createElement('style');
            style.textContent = `
                @keyframes pulse {{
                    0% {{ box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.4); }}
                    70% {{ box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }}
                    100% {{ box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }}
                }}
            `;
            document.head.appendChild(style);
        }});
    </script>
</body>
</html>"""

    # 保存HTML文件
    os.makedirs(report_dir, exist_ok=True)
    filename = os.path.join(report_dir, f"security_audit_{timestamp}.html")
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"报告已生成: {filename}")
    return filename