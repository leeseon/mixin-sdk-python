import os
import socket
import sys

# 先导入修复代理的模块并禁用macOS代理
print("\n========= 禁用macOS系统代理检测 =========")
import fix_proxy
fix_proxy.disable_macos_proxies()
print("已禁用macOS系统代理检测")

# 打印代理相关环境变量
print("\n========= 代理环境变量检查 =========")
proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'no_proxy', 'NO_PROXY']
found_proxy = False

for var in proxy_vars:
    value = os.environ.get(var, '')
    if value:
        found_proxy = True
        print(f"{var} = {value}")

if not found_proxy:
    print("环境变量中未发现任何代理设置")

# 检查是否可以访问网络
print("\n========= 网络连接检查 =========")
try:
    # 尝试解析域名
    print(f"解析 mixin.one: {socket.gethostbyname('mixin.one')}")
    print(f"解析 blaze.mixin.one: {socket.gethostbyname('blaze.mixin.one')}")
    print(f"解析 mixin-blaze.zeromesh.net: {socket.gethostbyname('mixin-blaze.zeromesh.net')}")
except Exception as e:
    print(f"域名解析失败: {e}")

# 检查Python的请求库是否有代理设置
print("\n========= Python请求库代理设置 =========")
try:
    import requests
    proxies = requests.utils.getproxies()
    if proxies:
        print(f"requests 库检测到代理设置: {proxies}")
        for protocol, proxy in proxies.items():
            print(f"- {protocol}: {proxy}")
    else:
        print("requests 库未检测到代理设置")
except ImportError:
    print("未安装 requests 库")

# 打印系统信息
print("\n========= 系统信息 =========")
import platform
print(f"操作系统: {platform.system()} {platform.release()}")
print(f"Python版本: {platform.python_version()}")
try:
    import websockets
    print(f"Websockets库版本: {websockets.__version__}")
except ImportError:
    print("未安装 websockets 库")

# 检查macOS系统代理设置
print("\n========= macOS系统代理设置 =========")
try:
    # 尝试检查macOS系统代理设置
    import subprocess
    network_services = subprocess.check_output(["networksetup", "-listallnetworkservices"]).decode().split('\n')[1:-1]
    print(f"网络服务列表: {network_services}")
    
    for service in network_services:
        if service.startswith('*'):  # 跳过禁用的服务
            continue
        try:
            proxy_info = subprocess.check_output(["networksetup", "-getwebproxy", service]).decode()
            print(f"\n{service} Web代理设置:")
            print(proxy_info)
        except:
            print(f"无法获取 {service} 的代理设置")
except Exception as e:
    print(f"检查macOS代理设置时出错: {e}")

print("\n========= 开始导入 blaze 模块 =========")
# 在打印环境变量后再导入blaze模块
from examples import blaze
