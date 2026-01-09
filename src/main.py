"""
主程序
整合所有模块，提供命令行接口
"""

import sys
import os
from pathlib import Path
from analyzer import NPDAnalyzer
from report import ReportGenerator

def print_banner():
    """打印程序横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              RepoAudit-Lite - NPD漏洞检测工具                        ║
║                                                                      ║
║  基于论文：RepoAudit (ICML 2025)                                     ║
║  LLM驱动：阿里云Qwen API                                            ║
║  作者：Yuan                                     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_environment():
    """检查运行环境"""
    print("🔧 检查运行环境...")
    
    # 检查API Key
    api_key = os.environ.get('DASHSCOPE_API_KEY')
    if not api_key:
        print("\n❌ 错误：未设置DASHSCOPE_API_KEY环境变量")
        print("\n请按以下步骤设置：")
        print("1. 访问 https://bailian.console.aliyun.com/?tab=model#/api-key")
        print("2. 获取API Key")
        print("3. 设置环境变量：")
        print("   Linux/Mac: export DASHSCOPE_API_KEY='your-key'")
        print("   Windows:   set DASHSCOPE_API_KEY=your-key")
        return False
    
    print(f"   ✅ API Key: {api_key[:10]}...")
    
    # 检查依赖
    try:
        import dashscope
        import tree_sitter
        print("   ✅ 依赖包已安装")
    except ImportError as e:
        print(f"\n❌ 错误：缺少依赖包 {e.name}")
        print("\n请运行: pip install -r requirements.txt")
        return False
    
    return True

def main():
    """主函数"""
    print_banner()
    
    # 1. 检查环境
    if not check_environment():
        sys.exit(1)
    
    # 2. 获取要分析的文件/目录
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # 默认测试文件
        target = '../benchmark/test_npd.py'
        if not os.path.exists(target):
            print(f"\n⚠️  默认测试文件不存在: {target}")
            print("请指定要分析的文件：python main.py <文件路径>")
            sys.exit(1)
        print(f"\n📝 未指定文件，使用默认测试: {target}")
    
    if not os.path.exists(target):
        print(f"\n❌ 错误：文件或目录不存在: {target}")
        sys.exit(1)
    
    # 3. 执行分析
    print(f"\n🚀 开始分析...\n")
    
    analyzer = NPDAnalyzer()
    bugs = []
    
    try:
        if os.path.isfile(target):
            # 分析单个文件
            bugs = analyzer.analyze_file(target)
        else:
            # 分析整个目录
            print(f"📂 扫描目录: {target}\n")
            py_files = list(Path(target).rglob("*.py"))
            print(f"找到 {len(py_files)} 个Python文件\n")
            
            for py_file in py_files:
                bugs.extend(analyzer.analyze_file(str(py_file)))
    
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断分析")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 分析过程出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 4. 生成报告
    print(f"\n{'='*70}")
    if bugs:
        print(f"⚠️  分析完成！共发现 {len(bugs)} 个潜在NPD漏洞")
    else:
        print(f"✅ 分析完成！未发现NPD漏洞")
    print(f"{'='*70}\n")
    
    if bugs:
        # 确保输出目录存在
        output_dir = Path("../output")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成报告
        reporter = ReportGenerator()
        
        json_path = output_dir / "bugs_report.json"
        html_path = output_dir / "vulnerability_report.html"
        
        print("📄 生成报告中...")
        reporter.generate_json_report(bugs, str(json_path))
        reporter.generate_html_report(bugs, str(html_path))
        
        print(f"\n✅ 报告已生成：")
        print(f"   📊 JSON报告: {json_path.absolute()}")
        print(f"   🌐 HTML报告: {html_path.absolute()}")
        
        # 打印漏洞摘要
        print(f"\n📋 漏洞摘要：")
        print(f"{'='*70}")
        
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_bugs = sorted(bugs, key=lambda b: severity_order.get(b['severity'], 4))
        
        for i, bug in enumerate(sorted_bugs, 1):
            severity_icon = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(bug['severity'], '⚪')
            
            print(f"{severity_icon} #{i} [{bug['severity']:8s}] {bug['function']:20s} "
                  f"| {bug['variable']:10s} "
                  f"| 第{bug['null_line']:3d}行→第{bug['use_line']:3d}行")
        
        print(f"{'='*70}")
        print(f"\n💡 提示：用浏览器打开HTML报告查看详细信息")
        print(f"   {html_path.absolute()}")
    else:
        print("✨ 代码质量良好，未发现NPD漏洞！")
    
    print("\n感谢使用 RepoAudit-Lite！\n")


if __name__ == "__main__":
    main()