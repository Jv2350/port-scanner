import os
import ipaddress
from typing import List

DEFAULT_OPTIONS = os.getenv("DEFAULT_OPTIONS", "-sT -sV")

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
            pass

MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "10"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")
API_KEY = os.getenv("API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


def ip_allowed(ip_str: str) -> bool:
    if not ALLOWED_NETWORKS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return any(ip in net for net in ALLOWED_NETWORKS)