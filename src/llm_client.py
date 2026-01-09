"""
LLM客户端模块 - Qwen API版本
封装阿里云Qwen API调用，用于代码安全分析
"""

import dashscope
from dashscope import Generation
import json
import os

class LLMClient:
    """Qwen API客户端"""
    
    def __init__(self, api_key=None):
        """
        初始化Qwen客户端
        
        Args:
            api_key: DashScope API Key，如果为None则从环境变量读取
        """
        if api_key is None:
            api_key = os.environ.get('DASHSCOPE_API_KEY')
            if not api_key:
                raise ValueError("请设置DASHSCOPE_API_KEY环境变量")
        
        dashscope.api_key = api_key
        # qwen-max: 最强模型
        # qwen-plus: 性价比高
        # qwen-turbo: 最快最便宜
        self.model = "qwen-max"
    
    def analyze_npd_path(self, func_code, var_name, null_line, use_line):
        """
        使用Qwen分析从NULL赋值到使用之间是否存在危险路径
        
        这是核心功能：让LLM进行路径敏感分析
        
        Args:
            func_code: 函数源代码
            var_name: 变量名
            null_line: NULL赋值所在行
            use_line: 变量使用所在行
            
        Returns:
            dict: 分析结果，包含is_bug, severity等字段
        """
        
        prompt = f"""你是一个专业的代码安全分析专家。请分析以下Python函数中的空指针解引用（NPD）漏洞风险。

函数代码：
```python
{func_code}
```

分析任务：
- 变量 `{var_name}` 在第{null_line}行被赋值为 None
- 变量 `{var_name}` 在第{use_line}行被使用（属性访问）

请仔细分析：
1. 从第{null_line}行到第{use_line}行，是否存在执行路径使得变量仍然是None时被使用？
2. 如果存在危险路径，描述触发条件（例如：某个if条件为False时）
3. 这是否是真实的NPD漏洞？还是被if语句等保护了？
4. 漏洞严重程度如何？

请严格按照以下JSON格式回答（不要添加任何markdown标记如```json，直接输出JSON）：
{{
    "has_dangerous_path": true,
    "path_description": "详细描述执行路径，例如：当flag为False时，user保持为None",
    "trigger_condition": "触发条件，例如：flag=False",
    "is_bug": true,
    "severity": "High",
    "reason": "判断理由"
}}

注意：
- has_dangerous_path: true表示存在危险路径，false表示不存在
- is_bug: true表示这是真实漏洞，false表示被保护了
- severity: 可选值为 Critical, High, Medium, Low
- 如果变量在使用前有if判断保护（如 if x is not None），则is_bug应为false"""

        try:
            response = Generation.call(
                model=self.model,
                messages=[
                    {
                        'role': 'system', 
                        'content': '你是一个专业的代码安全分析专家，擅长发现代码中的安全漏洞。'
                    },
                    {
                        'role': 'user', 
                        'content': prompt
                    }
                ],
                result_format='message',
                temperature=0  # 确定性输出
            )
            
            if response.status_code == 200:
                response_text = response.output.choices[0].message.content.strip()
                
                # 清理可能的markdown标记
                if response_text.startswith("```json"):
                    response_text = response_text[7:]
                if response_text.startswith("```"):
                    response_text = response_text[3:]
                if response_text.endswith("```"):
                    response_text = response_text[:-3]
                
                response_text = response_text.strip()
                
                # 解析JSON
                result = json.loads(response_text)
                
                # 验证必要字段
                required_fields = ['has_dangerous_path', 'is_bug', 'severity']
                for field in required_fields:
                    if field not in result:
                        result[field] = False if field != 'severity' else 'Low'
                
                return result
            else:
                error_msg = f"API返回错误码: {response.status_code}, 消息: {response.message}"
                print(f"⚠️  {error_msg}")
                return {
                    "has_dangerous_path": False,
                    "is_bug": False,
                    "severity": "Low",
                    "error": error_msg
                }
        
        except json.JSONDecodeError as e:
            print(f"⚠️  JSON解析失败: {e}")
            print(f"    响应内容: {response_text[:200]}")
            return {
                "has_dangerous_path": False,
                "is_bug": False,
                "severity": "Low",
                "error": f"JSON解析失败: {str(e)}"
            }
        
        except Exception as e:
            print(f"⚠️  Qwen API调用失败: {e}")
            return {
                "has_dangerous_path": False,
                "is_bug": False,
                "severity": "Low",
                "error": str(e)
            }


# 测试代码
if __name__ == "__main__":
    print("测试Qwen API...")
    print("请确保已设置环境变量: export DASHSCOPE_API_KEY='your-key'\n")
    
    try:
        client = LLMClient()
        
        # 测试用例1：明显的bug
        test_code1 = """
def bug_example(flag):
    user = None
    if flag:
        user = get_user()
    return user.name  # 当flag=False时会NPD
"""
        
        print("="*60)
        print("测试用例1：有bug的代码")
        print("="*60)
        result1 = client.analyze_npd_path(
            func_code=test_code1,
            var_name="user",
            null_line=2,
            use_line=5
        )
        
        print("Qwen分析结果：")
        print(json.dumps(result1, indent=2, ensure_ascii=False))
        
        # 测试用例2：安全的代码
        test_code2 = """
def safe_example():
    user = None
    if user is not None:
        return user.name
    return "default"
"""
        
        print("\n" + "="*60)
        print("测试用例2：安全的代码")
        print("="*60)
        result2 = client.analyze_npd_path(
            func_code=test_code2,
            var_name="user",
            null_line=2,
            use_line=4
        )
        
        print("Qwen分析结果：")
        print(json.dumps(result2, indent=2, ensure_ascii=False))
        
        print("\n✅ 测试完成！")
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        print("\n请检查：")
        print("1. 是否已安装dashscope: pip install dashscope")
        print("2. 是否已设置API Key: export DASHSCOPE_API_KEY='your-key'")