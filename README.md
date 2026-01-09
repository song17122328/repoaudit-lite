# RepoAudit-Lite

基于ICML 2025论文《RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing》的简化实现。
使用阿里云Qwen API进行Python代码中的NPD（空指针解引用）漏洞检测。

## 项目背景

本项目是对RepoAudit论文核心思想的教育实现，主要复现了：
- DFBScanAgent的数据流分析逻辑
- LLM驱动的路径敏感分析
- 自动化漏洞报告生成

使用Qwen API替代原论文的Claude API，降低使用成本。

## 功能特性

- ✅ 基于Tree-sitter的Python代码解析
- ✅ 使用Qwen进行路径敏感的NPD分析
- ✅ 生成JSON和美观的HTML报告
- ✅ 支持单文件和目录扫描
- ✅ 详细的漏洞定位和修复建议

## 安装

### 1. 创建环境
```bash
conda create -n repoaudit python=3.13
conda activate repoaudit
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 获取Qwen API Key

1. 访问 https://dashscope.console.aliyun.com/
2. 登录阿里云账号
3. 开通DashScope服务（有免费额度）
4. 获取API Key

### 4. 设置环境变量
```bash
# Linux/Mac
export DASHSCOPE_API_KEY='your-api-key'

# Windows
set DASHSCOPE_API_KEY=your-api-key
```

## 使用方法

### 基本用法
```bash
cd src
python main.py <文件或目录路径>
```

### 示例
```bash
# 分析单个文件
python main.py ../benchmark/test_npd.py

# 分析整个目录
python main.py ../benchmark/

# 使用默认测试文件
python main.py
```

### 查看报告

程序会在 `output/` 目录生成两种报告：
- `bugs_report.json` - JSON格式，便于程序处理
- `vulnerability_report.html` - HTML格式，用浏览器查看

## 项目结构
```
repoaudit-lite/
├── src/
│   ├── parser.py          # 代码解析（Tree-sitter）
│   ├── llm_client.py      # LLM接口（Qwen API）
│   ├── analyzer.py        # 核心分析逻辑
│   ├── report.py          # 报告生成
│   └── main.py            # 主程序
├── benchmark/
│   └── test_npd.py        # 测试用例（10个函数）
├── output/                # 输出报告目录
├── docs/                  # 文档
├── requirements.txt       # 依赖列表
└── README.md
```

## 与RepoAudit原版对比

| 功能 | RepoAudit原版 | 本项目 | 说明 |
|------|--------------|--------|------|
| 支持语言 | C/C++/Java/Python/Go | Python | 简化实现 |
| 漏洞类型 | NPD/UAF/MLK | NPD | 专注NPD检测 |
| 跨文件分析 | ✓ | ✗ | 单文件内分析 |
| Agent数量 | 2 (MetaScan + DFBScan) | 1 (简化DFBScan) | 简化架构 |
| LLM | Claude 3.5 Sonnet | Qwen-Max | 降低成本 |
| 并行分析 | ✓ (30 workers) | ✗ | 串行分析 |
| 代码量 | ~5000行 | ~1000行 | 教育用途 |

## 技术原理

### 1. 代码解析
使用Tree-sitter解析Python代码为AST（抽象语法树），提取：
- 函数定义
- NULL赋值（x = None）
- 属性访问（x.something）

### 2. 数据流分析
匹配同一变量的NULL赋值（Source）和属性访问（Sink）：
```python
user = None      # Source (第2行)
...
return user.name # Sink (第5行)
```

### 3. LLM路径分析
调用Qwen API判断从Source到Sink是否存在危险路径：
- 是否有if语句保护？
- 触发条件是什么？
- 是否为真实漏洞？

### 4. 报告生成
生成包含详细信息的HTML报告，包括：
- 漏洞位置
- 严重程度
- 触发条件
- 代码片段

## 测试用例说明

`benchmark/test_npd.py` 包含10个测试函数：

**有漏洞的（5个）：**
1. bug1_simple - 最简单的NPD
2. bug2_conditional - 条件分支导致的NPD
3. bug3_parameter - 参数可能为None
4. bug4_complex - 复杂条件NPD
5. bug5_loop - 循环中的NPD

**安全的（5个）：**
1. safe1_with_check - 有NULL检查
2. safe2_early_return - 提前返回
3. safe3_always_assigned - 总是赋值
4. safe4_exception_handling - 异常处理
5. safe5_default_value - 使用默认值

## 成本说明

使用Qwen API的成本：
- qwen-max: 约￥0.12/千tokens
- qwen-plus: 约￥0.04/千tokens
- qwen-turbo: 约￥0.008/千tokens

分析10个函数大约消耗：
- 输入tokens: ~8000
- 输出tokens: ~2000
- 总成本: < ￥0.5

相比Claude API（~￥1.5），成本降低约70%。

## 局限性

1. **仅支持Python**：未实现多语言支持
2. **单文件分析**：不支持跨文件数据流追踪
3. **简化的路径分析**：未实现完整的CFL-reachability算法
4. **LLM依赖**：检测准确性受LLM能力限制

## 未来改进

- [ ] 支持更多漏洞类型（UAF, Memory Leak）
- [ ] 实现跨文件分析
- [ ] 添加Agent Memory机制
- [ ] 支持更多编程语言
- [ ] 优化Prompt以提高准确率

## 参考文献
```bibtex
@inproceedings{repoaudit2025,
  title={RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing},
  author={Guo, Jinyao and Wang, Chengpeng and Xu, Xiangzhe and Su, Zian and Zhang, Xiangyu},
  booktitle={ICML 2025}
}
```

- RepoAudit GitHub: https://github.com/PurCL/RepoAudit
- RepoAudit论文: https://arxiv.org/abs/2501.18160
- Qwen API文档: https://help.aliyun.com/zh/dashscope/

## 作者

[你的名字] - 期末课程项目

## 许可证

MIT License