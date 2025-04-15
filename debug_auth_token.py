import os
import sys
import json
import base64
import logging
import time
import traceback
import requests
import hashlib
import uuid
from datetime import datetime
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 设置日志格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mixin_auth")

# 禁用代理（如果需要）
print("\n========= 禁用macOS系统代理检测 =========")
try:
    import fix_proxy
    fix_proxy.disable_macos_proxies()
    print("已禁用macOS系统代理检测")
except Exception as e:
    print(f"禁用代理失败: {e}")

# 导入必要的模块
print("\n========= 导入必要模块 =========")
from mixinsdk.clients.config import AppConfig
import jwt
from jose import jwk, jws, jwt as jose_jwt

# API基础URL
API_BASE_URL = "https://api.mixin.one"

# 创建替代的键类，因为原始模块不存在
class Ed25519Key:
    """Ed25519 key implementation"""
    
    def __init__(self, private_key_bytes=None):
        self.private_key_bytes = private_key_bytes
        self.algorithm = "Ed25519"
    
    @classmethod
    def from_base64(cls, base64_data):
        """Create an Ed25519Key from base64 encoded private key"""
        try:
            private_key_bytes = base64.b64decode(base64_data)
            return cls(private_key_bytes)
        except Exception as e:
            raise ValueError(f"Invalid Ed25519 key data: {e}")

# 确保URI正确处理（只获取路径部分）
def ensure_path_only(uri):
    """确保URI只包含路径部分，不包含域名或协议"""
    if uri.startswith('http'):
        parsed = urlparse(uri)
        return parsed.path
    # 确保以/开头
    if not uri.startswith('/'):
        uri = '/' + uri
    return uri

# 计算签名哈希
def calculate_signature_hash(method, uri, bodystring="", debug=False):
    """
    计算签名哈希
    
    Args:
        method: HTTP方法
        uri: 请求路径
        bodystring: 请求体
        debug: 是否输出调试信息
    
    Returns:
        计算的哈希值
    """
    # 准备输入 - 确保方法始终为大写，与Ruby行为一致
    method = method.upper()
    uri = ensure_path_only(uri)
    bodystring = bodystring if bodystring else ""
    
    # 拼接字符串
    input_string = method + uri + bodystring
    
    if debug:
        logger.debug(f"哈希计算: method={method}, uri={uri}, body_len={len(bodystring)}")
    
    # 计算哈希 - Ruby的Digest::SHA256.hexdigest直接处理字符串的UTF-8编码
    input_bytes = input_string.encode('utf-8')
    hashresult = hashlib.sha256(input_bytes).hexdigest()
    
    return hashresult

# 生成认证Token
def sign_authentication_token(
    user_id,
    session_id,
    private_key,
    key_algorithm="Ed25519",
    method="GET",
    uri="/me",
    bodystring="",
):
    """
    生成Mixin API认证Token (JWT)
    
    Args:
        user_id: 用户ID
        session_id: 会话ID
        private_key: 私钥 (base64字符串或字节)
        key_algorithm: 密钥算法，目前只支持Ed25519
        method: HTTP方法
        uri: 请求路径
        bodystring: 请求体
    
    Returns:
        JWT Token字符串
    """
    # 确保URI只包含路径部分
    uri = ensure_path_only(uri)
    
    # 确保bodystring正确处理
    bodystring = bodystring if bodystring else ""
    
    # 计算签名哈希
    hashresult = calculate_signature_hash(method, uri, bodystring)
    
    # 使用标准时间戳格式
    iat = int(time.time())
    exp = iat + 600  # 10分钟过期
    
    # 构建payload
    payload = {
        "exp": exp,
        "iat": iat,
        "jti": str(uuid.uuid4()),
        "scp": "FULL",
        "sid": session_id,
        "sig": hashresult,
        "uid": user_id
    }
    
    # 处理Ed25519密钥
    if key_algorithm.lower() in ["eddsa", "ed25519"]:
        try:
            # 将原始私钥转换为适合直接使用的格式
            if isinstance(private_key, str):
                if len(private_key) == 64:  # 十六进制字符串
                    private_key_bytes = bytes.fromhex(private_key)
                else:
                    # Base64编码
                    private_key_bytes = base64.b64decode(private_key)
            elif isinstance(private_key, bytes):
                private_key_bytes = private_key
            else:
                raise ValueError("不支持的私钥格式")
            
            # 确保私钥长度正确（至少32字节）
            if len(private_key_bytes) >= 32:
                # 使用前32字节作为种子
                seed = private_key_bytes[:32]
                
                # 创建Ed25519私钥
                key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                
                # JWT Headers
                headers = {
                    "alg": "EdDSA",
                    "typ": "JWT",
                }
                
                return jwt.encode(payload, key, algorithm="EdDSA", headers=headers)
            
                # # 手动创建JWT
                # # 1. 创建header部分
                # header_json = json.dumps(headers, separators=(',', ':'))
                # header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
                
                # # 2. 创建payload部分 - 确保按字母顺序排序字段
                # payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
                # payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
                
                # # 3. 创建签名数据
                # signing_input = f"{header_b64}.{payload_b64}"
                
                # # 4. 使用Ed25519密钥进行签名
                # signature = key.sign(signing_input.encode())
                # signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                
                # # 5. 组合JWT
                # token = f"{header_b64}.{payload_b64}.{signature_b64}"
                
                # return token
            else:
                raise ValueError(f"Ed25519 private key must be at least 32 bytes, got {len(private_key_bytes)}")
        except Exception as e:
            logger.error(f"EdDSA签名失败: {e}")
            traceback.print_exc()
            raise
    else:
        raise ValueError(f"仅支持 EdDSA/Ed25519 算法")

# 解码和验证JWT Token
def decode_token(token):
    """
    解码JWT Token (不验证签名)
    
    Args:
        token (str): JWT token字符串
        
    Returns:
        dict: 解码后的header和payload
    """
    try:
        # 解码token头部
        header_encoded = token.split('.')[0]
        header_padded = header_encoded + '=' * (4 - len(header_encoded) % 4)
        header_json = base64.urlsafe_b64decode(header_padded.encode('utf-8')).decode('utf-8')
        header = json.loads(header_json)
        
        # 解码payload
        payload_encoded = token.split('.')[1]
        payload_padded = payload_encoded + '=' * (4 - len(payload_encoded) % 4)
        payload_json = base64.urlsafe_b64decode(payload_padded.encode('utf-8')).decode('utf-8')
        payload = json.loads(payload_json)
        
        return {
            "header": header,
            "payload": payload
        }
    except Exception as e:
        logger.error(f"解码Token失败: {e}")
        traceback.print_exc()
        return None

# 加载应用配置
def load_app_keystore(path):
    """加载应用密钥仓库文件"""
    try:
        with open(path, "r") as f:
            keystore = json.load(f)
            return keystore
    except Exception as e:
        logger.error(f"加载密钥文件失败: {e}")
        return None

# 测试Token生成和API请求
def test_token(keystore_path="mixin-app-keystore.json", method="GET", uri="/me", body=""):
    """测试生成和使用API认证Token"""
    print(f"\n===== 测试Mixin API认证 =====")
    
    # 1. 加载配置
    keystore_data = load_app_keystore(keystore_path)
    if not keystore_data:
        print("错误: 密钥文件加载失败")
        return
    
    # 2. 设置参数
    user_id = keystore_data.get("client_id")
    session_id = keystore_data.get("session_id")
    private_key = keystore_data.get("private_key")
    
    if not all([user_id, session_id, private_key]):
        print("错误: 密钥文件缺少必要字段")
        return
    
    try:
        # 3. 生成Token
        token = sign_authentication_token(
            user_id, 
            session_id, 
            private_key,
            "Ed25519",
            method, 
            uri, 
            body
        )
        
        print(f"生成的Token: {token}")
        
        # 4. 解码Token
        token_data = decode_token(token)
        if token_data:
            print("\nToken解码结果:")
            print(f"头部: {json.dumps(token_data['header'], indent=2)}")
            print(f"载荷: {json.dumps(token_data['payload'], indent=2)}")
        
        # 5. 使用Token进行API请求
        print("\n尝试使用Token进行API请求...")
        api_url = f"{API_BASE_URL}{uri}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        
        response = requests.get(api_url, headers=headers)
        print(f"API响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("API请求成功!")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"API请求失败: {response.text}")
    
    except Exception as e:
        print(f"测试过程中出错: {e}")
        traceback.print_exc()
    
    print("\n===== 测试结束 =====")

# 主程序
if __name__ == "__main__":
    print("\n===== Mixin API认证工具 =====")
    test_token() 