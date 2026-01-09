
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
