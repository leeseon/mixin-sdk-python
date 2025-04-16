
# 先导入修复代理的模块并禁用macOS代理
print("\n========= 禁用macOS系统代理检测 =========")
import fix_proxy
fix_proxy.disable_macos_proxies()
print("已禁用macOS系统代理检测")

# 现在可以安全地导入使用网络的模块
print("\n========= 开始导入 blaze 模块 =========")
from examples import blaze
