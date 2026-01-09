"""
代码解析模块 - 简化版本
直接遍历AST，不使用Tree-sitter的query功能
"""

from tree_sitter import Language, Parser
import tree_sitter_python as tspython

class CodeParser:
    """Python代码解析器"""
    
    def __init__(self):
        """初始化Tree-sitter解析器"""
        self.PY_LANGUAGE = Language(tspython.language())
        self.parser = Parser(self.PY_LANGUAGE)
    
    def parse_file(self, file_path):
        """解析Python文件"""
        with open(file_path, 'rb') as f:
            source_code = f.read()
        
        tree = self.parser.parse(source_code)
        code_str = source_code.decode('utf-8')
        
        return tree, code_str
    
    def extract_functions(self, tree, source_code):
        """提取所有函数定义"""
        functions = []
        lines = source_code.split('\n')
        
        def visit(node):
            if node.type == "function_definition":
                start = node.start_point[0]
                end = node.end_point[0]
                func_code = '\n'.join(lines[start:end+1])
                
                # 查找函数名
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child.text.decode('utf-8')
                        functions.append({
                            'name': func_name,
                            'start_line': start + 1,
                            'end_line': end + 1,
                            'code': func_code,
                            'node': node
                        })
                        break
            
            for child in node.children:
                visit(child)
        
        visit(tree.root_node)
        return functions
    
    def find_null_assignments(self, func_node):
        """找到 x = None 的赋值"""
        results = []
        
        def visit(node):
            if node.type == "assignment":
                # 检查右边是否是None
                has_none = False
                var_node = None
                
                for child in node.children:
                    if child.type == "none":
                        has_none = True
                    elif child.type == "identifier":
                        var_node = child
                
                if has_none and var_node:
                    results.append({
                        'variable': var_node.text.decode('utf-8'),
                        'line': var_node.start_point[0] + 1
                    })
            
            for child in node.children:
                visit(child)
        
        visit(func_node)
        return results
    
    def find_attribute_access(self, func_node):
        """找到 x.something 的属性访问"""
        results = []
        seen = set()
        
        def visit(node):
            if node.type == "attribute":
                # 找到对象部分
                for child in node.children:
                    if child.type == "identifier":
                        var_name = child.text.decode('utf-8')
                        line = child.start_point[0] + 1
                        key = (var_name, line)
                        
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                'variable': var_name,
                                'line': line
                            })
                        break
            
            for child in node.children:
                visit(child)
        
        visit(func_node)
        return results


# 测试代码
if __name__ == "__main__":
    parser = CodeParser()
    
    test_code = """
def test_bug():
    x = None
    return x.name

def test_safe():
    x = None
    if x is not None:
        return x.name
    return "default"
"""
    
    with open('test_temp.py', 'w') as f:
        f.write(test_code)
    
    try:
        tree, code = parser.parse_file('test_temp.py')
        functions = parser.extract_functions(tree, code)
        
        print(f"✅ 找到 {len(functions)} 个函数:")
        for func in functions:
            print(f"\n函数: {func['name']} (第{func['start_line']}-{func['end_line']}行)")
            nulls = parser.find_null_assignments(func['node'])
            attrs = parser.find_attribute_access(func['node'])
            print(f"  NULL赋值: {len(nulls)} 个")
            print(f"  属性访问: {len(attrs)} 个")
            
            if nulls:
                for n in nulls:
                    print(f"    - {n['variable']} = None (第{n['line']}行)")
            if attrs:
                for a in attrs:
                    print(f"    - {a['variable']}.xxx (第{a['line']}行)")
        
        print("\n✅ 解析器测试通过！")
        
    finally:
        import os
        if os.path.exists('test_temp.py'):
            os.remove('test_temp.py')
            