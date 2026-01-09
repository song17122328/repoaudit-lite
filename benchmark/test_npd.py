"""
NPD漏洞测试用例集
包含5个有漏洞的函数和5个安全的函数，用于验证检测工具的准确性
"""

# ========== 有漏洞的函数 ==========

def bug1_simple():
    """
    漏洞1：最简单的NPD
    严重性：High
    """
    user = None
    return user.name  # 直接NPD


def bug2_conditional(flag):
    """
    漏洞2：条件分支导致的NPD
    严重性：High
    触发条件：flag为False
    """
    data = None
    if flag:
        data = get_data()
    return data.process()  # 当flag=False时NPD


def bug3_parameter(user_input):
    """
    漏洞3：参数可能为None
    严重性：Medium
    """
    user = find_user(user_input)  # 可能返回None
    return user.email  # 未检查就使用


def bug4_complex(x, y):
    """
    漏洞4：复杂条件导致的NPD
    严重性：High
    触发条件：x > 10 且 y >= 5
    """
    ptr = None
    
    if x > 10:
        if y < 5:
            ptr = allocate()
        # 如果y >= 5，ptr仍然是None
    
    return ptr.value  # 部分路径上会NPD


def bug5_loop(items):
    """
    漏洞5：循环中的NPD
    严重性：Medium
    """
    result = None
    for item in items:
        if item.is_valid():
            result = item
            break
    # 如果没有valid item，result仍是None
    return result.get_value()  # 可能NPD


# ========== 安全的函数 ==========

def safe1_with_check():
    """
    安全1：有NULL检查
    """
    user = None
    if user is not None:
        return user.name
    return "default"


def safe2_early_return(flag):
    """
    安全2：提前返回避免NPD
    """
    if not flag:
        return "no data"
    
    data = None
    data = get_data()
    return data.process()


def safe3_always_assigned():
    """
    安全3：变量总是被赋值
    """
    user = None
    user = get_user()  # 总是会赋值
    return user.name


def safe4_exception_handling():
    """
    安全4：异常处理保护
    """
    user = None
    try:
        user = risky_get_user()
    except:
        return "error"
    
    if user:
        return user.name
    return "no user"


def safe5_default_value():
    """
    安全5：使用默认值
    """
    user = None
    user = find_user() or get_default_user()  # 保证不为None
    return user.name


# ========== 辅助函数（模拟） ==========

def get_data():
    """模拟获取数据"""
    pass

def find_user(user_id):
    """模拟查找用户"""
    pass

def get_user():
    """模拟获取用户"""
    pass

def allocate():
    """模拟分配资源"""
    pass

def risky_get_user():
    """模拟可能失败的获取"""
    pass

def get_default_user():
    """模拟获取默认用户"""
    pass