"""Shared constants for MiniEDR agent/server communication."""

VERSION = "1.0.0"

# Event types that can be sent by agents
EVENT_TYPES = ["heartbeat", "fim", "scan", "system_info"]

# Severity levels for events
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Default timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 10

# Maximum payload size for events (bytes)
MAX_PAYLOAD_SIZE_BYTES = 1_000_000

# VirusTotal rate limit (requests per minute) for free tier
VT_RATE_LIMIT = 4

# Platform names
PLATFORM_LINUX = "Linux"
PLATFORM_WINDOWS = "Windows"
PLATFORM_DARWIN = "Darwin"

# Event source
SOURCE_AGENT = "agent"
SOURCE_SERVER = "server"

# Event status for VT enrichment
VT_STATUS_PENDING = "pending"
VT_STATUS_ENRICHED = "enriched"
VT_STATUS_SKIPPED = "skipped"

# Hash algorithms
HASH_MD5 = "md5"
HASH_SHA256 = "sha256"

# FIM event actions
FIM_CREATED = "created"
FIM_MODIFIED = "modified"
FIM_DELETED = "deleted"
FIM_MOVED = "moved"

# Heartbeat status
HEARTBEAT_ONLINE = "online"
HEARTBEAT_OFFLINE = "offline"
