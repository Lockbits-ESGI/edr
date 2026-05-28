"""Rate limiting module using slowapi.

Initialized here to avoid circular imports between server.main and server.api.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limiting per-route via @limiter.limit("500/minute").
# /metrics and /health are auto-generated (no decorator) → never rate-limited.
limiter = Limiter(key_func=get_remote_address)
