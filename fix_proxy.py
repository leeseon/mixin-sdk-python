"""
修补macOS系统代理检测，以绕过系统配置的代理
在导入任何使用urllib或websockets模块之前先调用这个脚本中的函数
"""
import os
import sys
import logging

logger = logging.getLogger(__name__)

def disable_macos_proxies():
    """
    禁用macOS系统代理检测
    
    在macOS中，即使没有设置代理环境变量，Python仍然会通过_scproxy模块
    自动检测并使用系统配置的代理。这个函数通过修补相关函数来禁用这种行为。
    
    应在导入任何使用网络的模块之前调用此函数。
    """
    # 设置NO_PROXY环境变量
    os.environ['no_proxy'] = '*'
    os.environ['NO_PROXY'] = '*'
    logger.debug("已设置no_proxy='*'")
    
    # 修补_scproxy模块
    try:
        import _scproxy
        
        # 保存原始函数
        original_get_proxy_settings = _scproxy._get_proxy_settings if hasattr(_scproxy, '_get_proxy_settings') else None
        original_get_proxies = _scproxy._get_proxies if hasattr(_scproxy, '_get_proxies') else None
        
        # 修补函数以返回空代理设置
        if hasattr(_scproxy, '_get_proxy_settings'):
            def no_proxy_settings():
                logger.debug("修补的_get_proxy_settings被调用，返回False")
                return False
            _scproxy._get_proxy_settings = no_proxy_settings
        
        if hasattr(_scproxy, '_get_proxies'):
            def no_proxies(*args, **kwargs):
                logger.debug("修补的_get_proxies被调用，返回空字典")
                return {}
            _scproxy._get_proxies = no_proxies
        
        logger.debug("已修补_scproxy模块函数")
    except Exception as e:
        logger.debug(f"修补_scproxy模块时出错: {e}")
    
    # 修补urllib.request.getproxies
    try:
        import urllib.request
        original_getproxies = urllib.request.getproxies
        
        def no_proxies():
            logger.debug("修补的getproxies被调用，返回空字典")
            return {}
        
        urllib.request.getproxies = no_proxies
        logger.debug("已修补urllib.request.getproxies函数")
    except Exception as e:
        logger.debug(f"修补urllib.request.getproxies时出错: {e}")
    
    return True

if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.DEBUG, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # 调用函数禁用代理
    disable_macos_proxies()
    
    print("已禁用macOS系统代理检测")
    print("现在可以导入和使用网络模块，而不会受到系统代理设置的影响") 