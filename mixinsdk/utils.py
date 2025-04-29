import datetime
import hashlib
import uuid
import logging
import os

logger = logging.getLogger(__name__)


def base64_pad_equal_sign(s: str):
    if not len(s) % 4 == 0:
        s = s + "=" * (4 - len(s) % 4)
    return s


def parse_rfc3339_to_datetime(s: str):
    """
    Params:
    - s: RFC3339Nano format, e.g. `2020-12-12T12:12:12.999999999Z`
    """
    [datestr, timestr] = s.split("T")
    [year, month, day] = datestr.split("-")
    [hour, minute, second] = timestr.split(":")
    [second, nano_sec] = second.split(".")
    microsec = int(nano_sec.rstrip("Z")[:6])

    return datetime.datetime(
        int(year),
        int(month),
        int(day),
        int(hour),
        int(minute),
        int(second),
        int(microsec),
    )


def get_conversation_id_of_two_users(a_user_id, b_user_id):
    """Get conversation id of single chat between two users, such as bot and user."""
    min_id = a_user_id
    max_id = b_user_id
    if min_id > max_id:
        min_id, max_id = max_id, min_id

    md5 = hashlib.md5()
    md5.update(min_id.encode())
    md5.update(max_id.encode())
    sum = list(md5.digest())

    sum[6] = (sum[6] & 0x0F) | 0x30
    sum[8] = (sum[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(sum)))


def is_group_conversation(conversation_id, from_user_id, bot_client_id):
    """
    Check the conversation is a conversation between bot and user,
    or is a group conversation, by compare conversation_id.
    """
    u2u_conv_id = get_conversation_id_of_two_users(from_user_id, bot_client_id)
    if conversation_id == u2u_conv_id:  # single chat
        return False
    return True


def disable_macos_proxies():
    """
    Disable macOS system proxy settings

    This function will:
    1. Disable proxies through environment variables
    2. Override proxy functions in Python's internal _scproxy module
    3. Override proxy functions in urllib.request

    Returns:
        bool: Whether the operation was successful
    """
    logger.info("Disabling macOS system proxy settings...")

    # Set environment variables to disable proxies
    os.environ["no_proxy"] = "*"
    os.environ["NO_PROXY"] = "*"

    try:
        # Try to modify macOS-specific _scproxy module
        import _scproxy

        if hasattr(_scproxy, "_get_proxy_settings"):

            def no_proxy_settings():
                return False

            _scproxy._get_proxy_settings = no_proxy_settings
            logger.debug("Overridden _scproxy._get_proxy_settings")

        if hasattr(_scproxy, "_get_proxies"):

            def no_proxies(*args, **kwargs):
                return {}

            _scproxy._get_proxies = no_proxies
            logger.debug("Overridden _scproxy._get_proxies")

    except ImportError:
        logger.debug("_scproxy module not found, possibly not a macOS system")
    except Exception as e:
        logger.warning(f"Failed to modify _scproxy: {e}")

    try:
        # Modify proxy retrieval functions in urllib
        import urllib.request

        def no_proxies():
            return {}

        urllib.request.getproxies = no_proxies
        logger.debug("Overridden urllib.request.getproxies")
    except Exception as e:
        logger.warning(f"Failed to modify urllib proxy functions: {e}")

    logger.info("Proxy settings have been disabled")
    return True


def check_proxy_status():
    """
    Check the current system's proxy status

    Returns:
        dict: Dictionary containing proxy information
    """
    status = {
        "env_proxy": bool(
            os.environ.get("http_proxy") or os.environ.get("https_proxy")
        ),
        "env_no_proxy": os.environ.get("no_proxy", ""),
    }

    try:
        import urllib.request

        proxies = urllib.request.getproxies()
        status["urllib_proxies"] = proxies
    except Exception:
        status["urllib_proxies"] = "Failed to retrieve"

    return status

    # or by request mixin api
