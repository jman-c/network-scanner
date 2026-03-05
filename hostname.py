import socket
from functools import lru_cache


@lru_cache(maxsize=4096)
def reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        # strip trailing dot if present
        host = host.rstrip(".")
        return host if host else None
    except Exception:
        return None