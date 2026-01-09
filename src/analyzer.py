"""
核心分析模块
整合代码解析和LLM分析，实现NPD漏洞检测
参考RepoAudit的DFBScanAgent设计
"""

from parser import CodeParser
from llm_client import LLMClient

class NPDAnalyzer:
    """
    NPD漏洞分析器
    简化版RepoAudit DFBScanAgent，专注于Python的NPD检测
    """
    
    def __init__(self, api_key=None):
        """
        初始化分析器
        
        Args:
            api_key: Qwen API Key
        """
        self.parser = CodeParser()
        self.llm = LLMClient(api_key)
        self.bugs_found = []
    
    def analyze_file(self, file_path):
        """
        分析单个Python文件
        
        Args:
            file_path: Python文件路径
            
        Returns:
            bugs: 发现的漏洞列表
        """
        print(f"\n{'='*70}")
        print(f"📁 分析文件: {file_path}")
        print(f"{'='*70}")
        
        # 步骤1：解析代码
        try:
            tree, source_code = self.parser.parse_file(file_path)
            functions = self.parser.extract_functions(tree, source_code)
        except Exception as e:
            print(f"❌ 解析失败: {e}")
            return []
        
        print(f"📊 找到 {len(functions)} 个函数\n")
        
        file_bugs = []
        
        # 步骤2：分析每个函数
        for func in functions:
            print(f"🔍 分析函数: {func['name']} (第{func['start_line']}-{func['end_line']}行)")
            
            func_bugs = self._analyze_function(func, file_path)
            file_bugs.extend(func_bugs)
            
            if not func_bugs:
                print(f"   ✅ 未发现漏洞")
        
        return file_bugs
    
    def _analyze_function(self, func, file_path):
        """
        分析单个函数中的NPD漏洞
        
        实现RepoAudit的核心逻辑：
        1. 找到Source（NULL赋值）
        2. 找到Sink（属性访问）
        3. 匹配同一变量的Source-Sink对
        4. 用LLM进行路径敏感分析
        
        Args:
            func: 函数信息字典
            file_path: 文件路径
            
        Returns:
            bugs: 该函数中发现的漏洞列表
        """
        bugs = []
        
        # 步骤1：找NULL赋值（Source）
        null_assigns = self.parser.find_null_assignments(func['node'])
        if not null_assigns:
            return bugs
        
        print(f"   🔹 发现 {len(null_assigns)} 个NULL赋值")
        for na in null_assigns:
            print(f"      - {na['variable']} = None (第{na['line']}行)")
        
        # 步骤2：找属性访问（Sink）
        attr_accesses = self.parser.find_attribute_access(func['node'])
        if not attr_accesses:
            return bugs
        
        print(f"   🔹 发现 {len(attr_accesses)} 个属性访问")
        for aa in attr_accesses:
            print(f"      - {aa['variable']}.xxx (第{aa['line']}行)")
        
        # 步骤3：匹配Source和Sink（同一变量，Source在前）
        matches = []
        for null_assign in null_assigns:
            for attr_access in attr_accesses:
                if (null_assign['variable'] == attr_access['variable'] and
                    null_assign['line'] < attr_access['line']):
                    matches.append((null_assign, attr_access))
        
        if not matches:
            print(f"   ℹ️  未发现匹配的Source-Sink对")
            return bugs
        
        print(f"   🔹 发现 {len(matches)} 个潜在的数据流")
        
        # 步骤4：对每个匹配使用LLM进行路径分析
        for null_assign, attr_access in matches:
            var_name = null_assign['variable']
            print(f"\n   🤖 LLM分析: {var_name} (第{null_assign['line']}行 → 第{attr_access['line']}行)")
            
            # 调用LLM（这是RepoAudit的核心创新）
            llm_result = self.llm.analyze_npd_path(
                func['code'],
                var_name,
                null_assign['line'],
                attr_access['line']
            )
            
            # 步骤5：如果LLM判断为漏洞，记录
            if llm_result.get('is_bug'):
                bug = {
                    'type': 'Null Pointer Dereference (NPD)',
                    'file': file_path,
                    'function': func['name'],
                    'variable': var_name,
                    'null_line': null_assign['line'],
                    'use_line': attr_access['line'],
                    'severity': llm_result.get('severity', 'Medium'),
                    'description': llm_result.get('path_description', ''),
                    'trigger_condition': llm_result.get('trigger_condition', '无'),
                    'reason': llm_result.get('reason', ''),
                    'code_snippet': func['code']
                }
                bugs.append(bug)
                print(f"      ⚠️  发现NPD漏洞！")
                print(f"      严重性: {bug['severity']}")
                print(f"      触发条件: {bug['trigger_condition']}")
            else:
                print(f"      ✅ 路径安全（有保护或不可达）")
        
        return bugs


# 测试代码
if __name__ == "__main__":
    print("="*70)
    print("测试NPD分析器")
    print("="*70)
    
    # 创建测试文件
    test_code = """
def bug1_simple():
    '''最简单的NPD漏洞'''
    user = None
    return user.name


def safe1_with_check():
    '''有检查，不是漏洞'''
    user = None
    if user is not None:
        return user.name
    return "default"


def bug2_conditional(flag):
    '''条件分支导致的NPD'''
    data = None
    if flag:
        data = get_data()
    return data.process()  # 当flag=False时NPD
"""
    
    import os
    test_file = '../benchmark/test_simple.py'
    os.makedirs('../benchmark', exist_ok=True)
    
    with open(test_file, 'w') as f:
        f.write(test_code)
    
    try:
        analyzer = NPDAnalyzer()
        bugs = analyzer.analyze_file(test_file)
        
        print(f"\n{'='*70}")
        print(f"✅ 分析完成！共发现 {len(bugs)} 个漏洞")
        print(f"{'='*70}\n")
        
        for i, bug in enumerate(bugs, 1):
            print(f"漏洞 #{i}:")
            print(f"  函数: {bug['function']}")
            print(f"  变量: {bug['variable']}")
            print(f"  位置: 第{bug['null_line']}行 → 第{bug['use_line']}行")
            print(f"  严重性: {bug['severity']}")
            print(f"  条件: {bug['trigger_condition']}")
            print()
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")