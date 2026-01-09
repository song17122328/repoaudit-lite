"""
报告生成模块
生成JSON和HTML格式的漏洞报告
"""

import json
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """漏洞报告生成器"""
    
    def generate_json_report(self, bugs, output_path):
        """
        生成JSON格式报告
        
        Args:
            bugs: 漏洞列表
            output_path: 输出文件路径
            
        Returns:
            report: 报告数据
        """
        report = {
            'tool': 'RepoAudit-Lite',
            'description': '基于Qwen API和RepoAudit方法的NPD漏洞检测工具',
            'scan_time': datetime.now().isoformat(),
            'total_bugs': len(bugs),
            'bugs': bugs,
            'summary': self._generate_summary(bugs)
        }
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def generate_html_report(self, bugs, output_path):
        """
        生成HTML格式报告
        
        Args:
            bugs: 漏洞列表
            output_path: 输出文件路径
        """
        html = self._create_html_template(bugs)
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_summary(self, bugs):
        """生成摘要统计"""
        severity_count = {}
        files = set()
        
        for bug in bugs:
            sev = bug.get('severity', 'Unknown')
            severity_count[sev] = severity_count.get(sev, 0) + 1
            files.add(bug.get('file', 'Unknown'))
        
        return {
            'total': len(bugs),
            'files_scanned': len(files),
            'by_severity': severity_count
        }
    
    def _create_html_template(self, bugs):
        """创建HTML模板"""
        summary = self._generate_summary(bugs)
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NPD漏洞检测报告 - RepoAudit-Lite</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .header h1 {{
            color: #2d3748;
            font-size: 36px;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #718096;
            font-size: 16px;
            margin-bottom: 20px;
        }}
        
        .header .meta {{
            color: #a0aec0;
            font-size: 14px;
        }}
        
        .summary {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }}
        
        .summary h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        
        .stat-card .number {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card .label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        
        .bugs-section h2 {{
            color: white;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        
        .bug-card {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 15px;
            border-left: 6px solid #e53e3e;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .bug-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }}
        
        .bug-card.severity-critical {{
            border-left-color: #742a2a;
        }}
        
        .bug-card.severity-high {{
            border-left-color: #e53e3e;
        }}
        
        .bug-card.severity-medium {{
            border-left-color: #ed8936;
        }}
        
        .bug-card.severity-low {{
            border-left-color: #48bb78;
        }}
        
        .bug-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .bug-title {{
            font-size: 20px;
            color: #2d3748;
            font-weight: 600;
        }}
        
        .badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        
        .badge-critical {{
            background: linear-gradient(135deg, #742a2a 0%, #9b2c2c 100%);
        }}
        
        .badge-high {{
            background: linear-gradient(135deg, #c53030 0%, #e53e3e 100%);
        }}
        
        .badge-medium {{
            background: linear-gradient(135deg, #dd6b20 0%, #ed8936 100%);
        }}
        
        .badge-low {{
            background: linear-gradient(135deg, #38a169 0%, #48bb78 100%);
        }}
        
        .bug-info {{
            margin: 15px 0;
        }}
        
        .bug-info-item {{
            margin: 8px 0;
            color: #4a5568;
        }}
        
        .bug-info-label {{
            font-weight: 600;
            color: #2d3748;
            display: inline-block;
            min-width: 100px;
        }}
        
        code {{
            background: #edf2f7;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            color: #d53f8c;
        }}
        
        .code-snippet {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            margin-top: 15px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            line-height: 1.5;
        }}
        
        .code-snippet pre {{
            margin: 0;
        }}
        
        .footer {{
            background: white;
            padding: 20px;
            border-radius: 15px;
            margin-top: 30px;
            text-align: center;
            color: #718096;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NPD漏洞检测报告</h1>
            <div class="subtitle">基于Qwen API和RepoAudit方法的智能代码安全分析</div>
            <div class="meta">
                生成时间：{datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')} | 
                工具版本：RepoAudit-Lite v1.0
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 检测摘要</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="number">{summary['total']}</div>
                    <div class="label">发现漏洞</div>
                </div>
                <div class="stat-card">
                    <div class="number">{summary['files_scanned']}</div>
                    <div class="label">扫描文件</div>
                </div>
"""
        
        # 添加各严重级别统计
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = summary['by_severity'].get(severity, 0)
            if count > 0:
                html += f"""                <div class="stat-card">
                    <div class="number">{count}</div>
                    <div class="label">{severity}</div>
                </div>
"""
        
        html += """            </div>
        </div>
        
        <div class="bugs-section">
            <h2>🐛 漏洞详情</h2>
"""
        
        # 添加每个漏洞
        for i, bug in enumerate(bugs, 1):
            severity = bug.get('severity', 'Medium').lower()
            html += f"""
            <div class="bug-card severity-{severity}">
                <div class="bug-header">
                    <div class="bug-title">漏洞 #{i}: {bug['function']}</div>
                    <span class="badge badge-{severity}">{bug['severity']}</span>
                </div>
                
                <div class="bug-info">
                    <div class="bug-info-item">
                        <span class="bug-info-label">漏洞类型：</span>
                        {bug['type']}
                    </div>
                    <div class="bug-info-item">
                        <span class="bug-info-label">文件路径：</span>
                        <code>{bug['file']}</code>
                    </div>
                    <div class="bug-info-item">
                        <span class="bug-info-label">变量名称：</span>
                        <code>{bug['variable']}</code>
                    </div>
                    <div class="bug-info-item">
                        <span class="bug-info-label">漏洞位置：</span>
                        第 {bug['null_line']} 行（NULL赋值）→ 第 {bug['use_line']} 行（使用）
                    </div>
                    <div class="bug-info-item">
                        <span class="bug-info-label">触发条件：</span>
                        {bug.get('trigger_condition', '无条件触发')}
                    </div>
                    <div class="bug-info-item">
                        <span class="bug-info-label">路径分析：</span>
                        {bug.get('description', '变量在赋值为None后被直接使用')}
                    </div>
                </div>
                
                <div class="code-snippet">
                    <pre>{self._escape_html(bug.get('code_snippet', ''))}</pre>
                </div>
            </div>
"""
        
        html += """        </div>
        
        <div class="footer">
            <p>本报告由 RepoAudit-Lite 自动生成</p>
            <p>基于论文：RepoAudit (ICML 2025) | LLM提供方：阿里云Qwen</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _escape_html(self, text):
        """转义HTML特殊字符"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))


# 测试代码
if __name__ == "__main__":
    # 模拟漏洞数据
    test_bugs = [
        {
            'type': 'Null Pointer Dereference (NPD)',
            'file': 'benchmark/test.py',
            'function': 'bug_example',
            'variable': 'user',
            'null_line': 2,
            'use_line': 5,
            'severity': 'High',
            'description': '当flag为False时，user变量保持为None，在第5行被解引用',
            'trigger_condition': 'flag == False',
            'code_snippet': '''def bug_example(flag):
    user = None
    if flag:
        user = get_user()
    return user.name  # NPD漏洞'''
        },
        {
            'type': 'Null Pointer Dereference (NPD)',
            'file': 'benchmark/test.py',
            'function': 'another_bug',
            'variable': 'data',
            'null_line': 10,
            'use_line': 11,
            'severity': 'Critical',
            'description': 'data变量直接在赋值为None后使用，无任何保护',
            'trigger_condition': '无条件触发',
            'code_snippet': '''def another_bug():
    data = None
    return data.process()  # 直接NPD'''
        }
    ]
    
    import os
    os.makedirs('../output', exist_ok=True)
    
    generator = ReportGenerator()
    
    # 生成报告
    generator.generate_json_report(test_bugs, '../output/test_report.json')
    generator.generate_html_report(test_bugs, '../output/test_report.html')
    
    print("✅ 测试报告生成完成！")
    print("   JSON: ../output/test_report.json")
    print("   HTML: ../output/test_report.html")
    print("\n💡 用浏览器打开HTML文件查看效果")