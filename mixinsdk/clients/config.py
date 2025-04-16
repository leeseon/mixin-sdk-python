import json
from base64 import urlsafe_b64decode

from ..utils import base64_pad_equal_sign


class AppConfig:
    """
    Config object of Mixin applications
    (such as Mixin Messenger bot)
    """

    def __init__(self, client_id, session_id, pin=None, pin_token=None, session_private_key=None):
        """
        You can get bot config values from https://developers.mixin.one/dashboard
        
        Args:
            client_id: The client ID of your Mixin application
            session_id: The session ID of your Mixin application
            pin: Optional PIN code for operations requiring PIN (can be None)
            pin_token: Optional PIN token for encrypting PIN (can be None if PIN operations are not needed)
            session_private_key: Optional session private key (used when pin_token is not available)
        """

        self.client_id = client_id
        self.session_id = session_id
        self.pin = pin
        self.pin_token = base64_pad_equal_sign(pin_token) if pin_token else None
        self.session_private_key = session_private_key
        self.key_algorithm = "Ed25519"
        self.private_key = bytes.fromhex(self.session_private_key)



    @classmethod
    def from_payload(cls, payload: dict) -> "AppConfig":
        """
        Create AppConfig from a configuration dictionary
        
        payload structure:
        {
            "client_id": "required",
            "session_id": "required",
            "private_key": "required",
            "pin": "optional",
            "pin_token": "optional",
            "session_private_key": "optional - used when pin_token is not available"
        }
        """

        if isinstance(payload, str):
            payload = json.loads(payload)

        return cls(
            client_id=payload["client_id"],
            session_id=payload["session_id"],
            pin=payload.get("pin"),
            pin_token=payload.get("pin_token"),
            session_private_key=payload.get("session_private_key"),
        )

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
        private_key,
        pin=None,
        pin_token=None,
        public_key=None,
        session_private_key=None,
    ):
        """
        Initialize NetworkUserConfig
        
        Args:
            user_id: The user ID
            session_id: The session ID
            private_key: The private key (base64 encoded Ed25519 key)
            pin: Optional PIN code (can be None)
            pin_token: Optional PIN token (can be None if PIN operations are not needed)
            public_key: Optional public key (base64 encoded Ed25519 key)
            session_private_key: Optional session private key (used when pin_token is not available)
        """
        self.user_id = user_id
        self.session_id = session_id
        self.pin = pin
        self.pin_token = base64_pad_equal_sign(pin_token) if pin_token else None
        self.session_private_key = session_private_key
        
        # Process private key
        self.private_key = urlsafe_b64decode(
            base64_pad_equal_sign(private_key).encode()
        )
        
        # Process public key if provided
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
        Create NetworkUserConfig from a configuration dictionary
        
        payload structure:
        {
            "user_id": "required",
            "session_id": "required",
            "private_key": "required",
            "pin": "optional",
            "pin_token": "optional",
            "public_key": "optional",
            "session_private_key": "optional - used when pin_token is not available"
        }
        """

        if isinstance(payload, str):
            payload = json.loads(payload)

        return cls(
            user_id=payload["user_id"],
            session_id=payload["session_id"],
            private_key=payload["private_key"],
            pin=payload.get("pin"),
            pin_token=payload.get("pin_token"),
            public_key=payload.get("public_key"),
            session_private_key=payload.get("session_private_key"),
        )

    @classmethod
    def from_file(cls, file_path: str) -> "NetworkUserConfig":
        with open(file_path, "rt") as f:
            return cls.from_payload(f.read())
