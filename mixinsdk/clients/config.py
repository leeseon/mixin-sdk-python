import json
from base64 import urlsafe_b64decode

from ..utils import base64_pad_equal_sign


class AppConfig:
    """
    Config object of Mixin applications
    (such as Mixin Messenger bot)
    """

    def __init__(
        self,
        client_id: str,
        session_id: str,
        private_key_str: str = None,
        pin: str = None,
        pin_token: str = None,
        session_private_key: str = None,
    ):
        """You can get bot config values from https://developers.mixin.one/dashboard"""

        if not client_id or not session_id:
            raise ValueError("client_id and session_id are required")

        # Validate authentication method
        has_pin_auth = pin_token is not None
        has_session_auth = session_private_key is not None
        
        if not (has_pin_auth or has_session_auth):
            raise ValueError("Either pin_token or session_private_key must be provided")

        if has_pin_auth and not private_key_str:
            raise ValueError("private_key_str is required when using pin_token")

        self.pin = pin
        self.client_id = client_id
        self.session_id = session_id
        self.pin_token = base64_pad_equal_sign(pin_token) if pin_token else None

        # Set private_key based on authentication method
        if has_pin_auth:
            key_str = private_key_str
        else:
            key_str = session_private_key

        # Determine key algorithm and convert private_key to bytes
        self.key_algorithm = ""  # Ed25519 or RS512 (EdDSA:Ed25519, RSA:RS512)
        if "RSA PRIVATE KEY" in key_str:
            self.key_algorithm = "RS512"
            # Convert RSA private key from PEM format to bytes
            # Remove header, footer and newlines
            pem_lines = key_str.strip().split('\n')
            pem_content = ''.join(pem_lines[1:-1])  # Skip first and last lines
            self.private_key: bytes = urlsafe_b64decode(pem_content.encode())
        else:
            self.key_algorithm = "Ed25519"
            # Try to convert from hex format first
            try:
                self.private_key: bytes = bytes.fromhex(key_str)
            except ValueError:
                # If not hex format, try base64
                key = base64_pad_equal_sign(key_str)
                self.private_key: bytes = urlsafe_b64decode(key.encode())
            

    @classmethod
    def from_payload(cls, payload: dict) -> "AppConfig":
        """
        payload structure:
        {
            "client_id": "required",
            "session_id": "required",
            "private_key_str": "required when using pin_token",
            "pin": "optional",
            "pin_token": "optional",
            "session_private_key": "optional"
        }
        Note: Either pin_token or session_private_key must be provided
        """

        if isinstance(payload, str):
            payload = json.loads(payload)

        # Validate required fields
        required_fields = ["client_id", "session_id"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing required field: {field}")

        # Validate authentication method
        has_pin_auth = "pin_token" in payload
        has_session_auth = "session_private_key" in payload
        
        if not (has_pin_auth or has_session_auth):
            raise ValueError("Either pin_token or session_private_key must be provided")

        if has_pin_auth and "private_key_str" not in payload:
            raise ValueError("private_key_str is required when using pin_token")

        c = cls(
            client_id=payload["client_id"],
            session_id=payload["session_id"],
            private_key_str=payload.get("private_key_str"),
            pin=payload.get("pin"),
            pin_token=payload.get("pin_token"),
            session_private_key=payload.get("session_private_key"),
        )
        return c

    @classmethod
    def from_file(cls, file_path: str) -> "AppConfig":
        with open(file_path, "rt") as f:
            return cls.from_payload(f.read())


class NetworkUserConfig:
    """
    Config object of mixin network user(created by application user)
    """

    def __init__(
        self,
        user_id,
        session_id,
        pin,
        pin_token,
        private_key,
        public_key,
    ):
        """
        - private_key/public_key: must be base64 encoded Ed25519 key
        """
        self.user_id = user_id
        self.session_id = session_id
        self.pin = pin
        self.pin_token = base64_pad_equal_sign(pin_token)
        self.private_key = urlsafe_b64decode(
            base64_pad_equal_sign(private_key).encode()
        )
        if public_key:
            self.public_key = urlsafe_b64decode(
                base64_pad_equal_sign(public_key).encode()
            )
        else:
            self.public_key = None

        self.key_algorithm = "Ed25519"

    @classmethod
    def from_payload(cls, payload: dict) -> "NetworkUserConfig":
        """
        payload structure:
        {
            "user_id": "required",
            "session_id": "required",
            "pin": "",
            "pin_token": "required",
            "private_key": "required",
            "public_key": "",
        }
        """

        if isinstance(payload, str):
            payload = json.loads(payload)

        c = cls(
            payload["user_id"],
            payload["session_id"],
            payload.get("pin"),
            payload["pin_token"],
            payload["private_key"],
            payload.get("public_key"),
        )
        return c

    @classmethod
    def from_file(cls, file_path: str) -> "NetworkUserConfig":
        with open(file_path, "rt") as f:
            return cls.from_payload(f.read())
