import asyncio
import os
import sys
import json
import logging
import platform

# 设置日志
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("websocket-test")

# 环境检查
print("\n========= 环境检查 =========")
print(f"操作系统: {platform.system()} {platform.release()}")
print(f"Python版本: {platform.python_version()}")

# 检查代理设置
print("\n========= 代理设置检查 =========")
proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 
              'all_proxy', 'ALL_PROXY', 'no_proxy', 'NO_PROXY']
found_proxy = False
for var in proxy_vars:
    if var in os.environ and os.environ[var]:
        found_proxy = True
        print(f"{var} = {os.environ[var]}")
if not found_proxy:
    print("环境变量中未检测到代理设置")

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

# 修补_scproxy而不是禁用它
print("\n========= 修补macOS代理检测 =========")
try:
    # 导入_scproxy模块
    import _scproxy
    
    # 保存原始函数
    original_get_proxy_settings = _scproxy._get_proxy_settings if hasattr(_scproxy, '_get_proxy_settings') else None
    original_get_proxies = _scproxy._get_proxies if hasattr(_scproxy, '_get_proxies') else None
    
    # 修补函数以返回空代理设置
    if hasattr(_scproxy, '_get_proxy_settings'):
        def no_proxy_settings():
            print("修补的_get_proxy_settings被调用，返回False")
            return False
        _scproxy._get_proxy_settings = no_proxy_settings
    
    if hasattr(_scproxy, '_get_proxies'):
        def no_proxies(*args, **kwargs):
            print("修补的_get_proxies被调用，返回空字典")
            return {}
        _scproxy._get_proxies = no_proxies
    
    print("已修补_scproxy模块函数")
except Exception as e:
    print(f"修补_scproxy模块时出错: {e}")

# 设置NO_PROXY
os.environ['no_proxy'] = '*'
os.environ['NO_PROXY'] = '*'
print(f"已设置no_proxy = {os.environ.get('no_proxy')}")

# 导入websockets库
print("\n========= 导入websockets库 =========")
try:
    import websockets
    print(f"Websockets库版本: {websockets.__version__}")
    
    # 查找与代理相关的模块
    proxy_modules = [m for m in sys.modules.keys() if 'proxy' in m.lower()]
    print(f"已加载的代理相关模块: {proxy_modules}")
    
except ImportError:
    print("未安装websockets库")
    sys.exit(1)

async def test_websocket_connection():
    """测试直接使用websockets库连接到blaze.mixin.one"""
    url = "wss://blaze.mixin.one/"
    backup_url = "wss://mixin-blaze.zeromesh.net/"
    
    logger.info(f"尝试连接到 {url}")
    
    # 明确设置proxy=None (适用于websockets 15+)
    try:
        # 尝试直接修改urllib中的get_proxies函数以返回空代理
        try:
            import urllib.request
            original_getproxies = urllib.request.getproxies
            
            def no_proxies():
                logger.info("修补的getproxies被调用，返回空字典")
                return {}
            
            urllib.request.getproxies = no_proxies
            logger.info("已修补urllib.request.getproxies函数")
        except Exception as e:
            logger.warning(f"修补urllib.request.getproxies时出错: {e}")
        
        connect_kwargs = {
            "max_size": 10 * 1024 * 1024,
            "open_timeout": 30,
            "close_timeout": 10,
            "proxy": None,  # 明确指定不使用代理
            "subprotocols": ["Mixin-Blaze-1"],  # 指定Mixin服务需要的子协议
        }
        
        logger.info(f"连接参数: {connect_kwargs}")
        
        async with websockets.connect(url, **connect_kwargs) as websocket:
            logger.info("连接成功!")
            # 发送一个简单的消息测试连接
            await websocket.send(json.dumps({"msg": "Hello!"}))
            logger.info("消息已发送")
            
            # 等待响应
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                logger.info(f"收到响应: {response}")
            except asyncio.TimeoutError:
                logger.info("等待响应超时，但连接已成功建立")
                
    except Exception as e:
        logger.error(f"连接失败: {e}", exc_info=True)
        
        # 尝试备用服务器
        logger.info(f"尝试连接到备用服务器 {backup_url}")
        try:
            async with websockets.connect(backup_url, **connect_kwargs) as websocket:
                logger.info("备用服务器连接成功!")
        except Exception as e:
            logger.error(f"备用服务器连接也失败: {e}", exc_info=True)

# 运行测试
if __name__ == "__main__":
    print("\n========= 开始测试WebSocket连接 =========")
    
    # 导入pkgutil用于查找子模块
    import pkgutil
    
    asyncio.run(test_websocket_connection())
    print("\n========= WebSocket连接测试完成 =========")
    
    # 恢复原始函数
    import _scproxy
    if hasattr(_scproxy, '_get_proxy_settings') and 'original_get_proxy_settings' in globals() and original_get_proxy_settings:
        _scproxy._get_proxy_settings = original_get_proxy_settings
    
    if hasattr(_scproxy, '_get_proxies') and 'original_get_proxies' in globals() and original_get_proxies:
        _scproxy._get_proxies = original_get_proxies
    
    # 恢复urllib.request.getproxies
    try:
        import urllib.request
        if 'original_getproxies' in locals() or 'original_getproxies' in globals():
            urllib.request.getproxies = original_getproxies
    except Exception:
        pass 