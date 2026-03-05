import socket
from functools import lru_cache
from typing import Optional

@lru_cache(maxsize=4096)
def reverse_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.rstrip(".")
        return host if host else None
    except Exception:
        return None