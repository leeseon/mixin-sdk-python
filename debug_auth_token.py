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

# # 创建替代的键类，因为原始模块不存在
# class Ed25519Key:
#     """Ed25519 key implementation"""
    
#     def __init__(self, private_key_bytes=None):
#         self.private_key_bytes = private_key_bytes
#         self.algorithm = "Ed25519"
    
#     @classmethod
#     def from_base64(cls, base64_data):
#         """Create an Ed25519Key from base64 encoded private key"""
#         try:
#             private_key_bytes = base64.b64decode(base64_data)
#             return cls(private_key_bytes)
#         except Exception as e:
#             raise ValueError(f"Invalid Ed25519 key data: {e}")

def ensure_path_only(uri):
    if uri.startswith('http'):
        parsed = urlparse(uri)
        return parsed.path
    if not uri.startswith('/'):
        uri = '/' + uri
    return uri

def calculate_signature_hash(method, uri, bodystring=""):
    method = method.upper()
    uri = ensure_path_only(uri)
    bodystring = bodystring if bodystring else ""
    
    input_string = method + uri + bodystring
    
    input_bytes = input_string.encode('utf-8')
    hashresult = hashlib.sha256(input_bytes).hexdigest()
    
    return hashresult

def sign_authentication_token(
    user_id,
    session_id,
    private_key: bytes,
    key_algorithm,
    method,
    uri,
    bodystring: str = None,
):
    """
    JWT Structure: https://developers.mixin.one/docs/api/guide
    """

    if key_algorithm.lower() in ["rs512", "rsa"]:
        alg = "RS512"
        key = private_key
    elif key_algorithm.lower() in ["eddsa", "ed25519"]:
        alg = "EdDSA"
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key[:32])
    else:
        raise ValueError(f"Unsupported key's algorithm: {key_algorithm}")

    jwt_headers = {
        "alg": alg,
        "typ": "JWT",
    }

    bodystring = bodystring if bodystring else ""
    hashresult = hashlib.sha256((method + uri + bodystring).encode("utf-8")).hexdigest()
    iat = int(time.time())
    exp = iat + 600
    payload = {
        "uid": user_id,
        "sid": session_id,
        "iat": iat,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "sig": hashresult,
        "scp": "FULL",
    }

    return jwt.encode(payload, key, algorithm=alg, headers=jwt_headers)


# # 生成认证Token
# def sign_authentication_token(
#     user_id,
#     session_id,
#     private_key,
#     key_algorithm="Ed25519",
#     method="GET",
#     uri="/me",
#     bodystring="",
# ):
#     uri = ensure_path_only(uri)
    
#     bodystring = bodystring if bodystring else ""
    
#     hashresult = calculate_signature_hash(method, uri, bodystring)
    
#     iat = int(time.time())
#     exp = iat + 600  # 10分钟过期
    
#     payload = {
#         "exp": exp,
#         "iat": iat,
#         "jti": str(uuid.uuid4()),
#         "scp": "FULL",
#         "sid": session_id,
#         "sig": hashresult,
#         "uid": user_id
#     }
    
#     if key_algorithm.lower() in ["eddsa", "ed25519"]:
#         try:
#             if isinstance(private_key, str):
#                 if len(private_key) == 64:
#                     private_key_bytes = bytes.fromhex(private_key)
#                 else:
#                     private_key_bytes = base64.b64decode(private_key)
#             elif isinstance(private_key, bytes):
#                 private_key_bytes = private_key
#             else:
#                 raise ValueError("不支持的私钥格式")
            
#             if len(private_key_bytes) >= 32:
#                 seed = private_key_bytes[:32]
                
#                 key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                
#                 headers = {
#                     "alg": "EdDSA",
#                     "typ": "JWT",
#                 }
                
#                 return jwt.encode(payload, key, algorithm="EdDSA", headers=headers)
            
#             else:
#                 raise ValueError(f"Ed25519 private key must be at least 32 bytes, got {len(private_key_bytes)}")
#         except Exception as e:
#             logger.error(f"EdDSA签名失败: {e}")
#             traceback.print_exc()
#             raise
#     else:
#         raise ValueError(f"仅支持 EdDSA/Ed25519 算法")

# 解码和验证JWT Token
def decode_token(token):
    try:
        header_encoded = token.split('.')[0]
        header_padded = header_encoded + '=' * (4 - len(header_encoded) % 4)
        header_json = base64.urlsafe_b64decode(header_padded.encode('utf-8')).decode('utf-8')
        header = json.loads(header_json)
        
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

def load_app_keystore(path):
    try:
        with open(path, "r") as f:
            keystore = json.load(f)
            return keystore
    except Exception as e:
        logger.error(f"加载密钥文件失败: {e}")
        return None

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

    if isinstance(private_key, str):
        if len(private_key) == 64:
            private_key_bytes = bytes.fromhex(private_key)
    
    if not all([user_id, session_id, private_key]):
        print("错误: 密钥文件缺少必要字段")
        return
    
    try:
        # 3. 生成Token
        token = sign_authentication_token(
            user_id, 
            session_id, 
            private_key_bytes,
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