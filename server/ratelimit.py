"""Rate limiting module using slowapi.

Initialized here to avoid circular imports between server.main and server.api.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
