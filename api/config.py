import os
import ipaddress
from typing import List


DEFAULT_OPTIONS = os.getenv("DEFAULT_OPTIONS", "-sT -sV")

# Comma-separated CIDR list. If empty, no network restriction is applied.
_raw_allowed = os.getenv("ALLOWED_NETWORKS", "")
ALLOWED_NETWORKS: List[ipaddress.IPv4Network] = []
if _raw_allowed.strip():
    for part in _raw_allowed.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            ALLOWED_NETWORKS.append(ipaddress.ip_network(p))
        except Exception:
            # ignore invalid entries
            pass

MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "10"))

# CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")

# Optional API key
API_KEY = os.getenv("API_KEY", "")


def ip_allowed(ip_str: str) -> bool:
    """Return True if ip_str is allowed by ALLOWED_NETWORKS.
    If ALLOWED_NETWORKS is empty, allow all.
    """
    if not ALLOWED_NETWORKS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for net in ALLOWED_NETWORKS:
        if ip in net:
            return True
    return False
