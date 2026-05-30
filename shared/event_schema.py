"""Shared event schema for agent/server communication using Pydantic v2."""

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class VTResult(BaseModel):
    """VirusTotal analysis result."""

    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    total: int = 0
    status: str = "notfound"  # clean | malicious | suspicious | notfound

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"clean", "malicious", "suspicious", "notfound"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v

    @field_validator("*", mode="before")
    @classmethod
    def ensure_non_negative(cls, v: Any, info) -> int:
        if info.field_name in {
            "malicious",
            "suspicious",
            "undetected",
            "total",
        } and isinstance(v, (int, float)):
            if v < 0:
                raise ValueError(f"{info.field_name} must be non-negative")
            return int(v)
        return v

    @model_validator(mode="after")
    def validate_total(self) -> "VTResult":
        """Ensure total equals sum of malicious + suspicious + undetected."""
        computed = self.malicious + self.suspicious + self.undetected
        if self.total != computed:
            raise ValueError(
                f"total ({self.total}) must equal malicious+suspicious+undetected ({computed})"
            )
        return self


class FIMPayload(BaseModel):
    """File Integrity Monitoring event payload."""

    filepath: str
    event_action: str  # created | modified | deleted
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    vt: Optional[VTResult] = None

    @field_validator("event_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"created", "modified", "deleted", "moved"}
        if v not in allowed:
            raise ValueError(f"event_action must be one of {allowed}, got '{v}'")
        return v

    @field_validator("filepath")
    @classmethod
    def validate_filepath(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("filepath cannot be empty")
        return v


class ProcessSnapshot(BaseModel):
    """Process snapshot data."""

    pid: int
    name: str
    cpu_percent: float = Field(ge=0.0, le=100.0)
    mem_percent: float = Field(ge=0.0, le=100.0)
    exe: str


class NetworkSnapshot(BaseModel):
    """Network connection snapshot data."""

    laddr: str  # local IP:port
    raddr: str  # remote IP:port
    status: str
    pid: int


class SystemInfo(BaseModel):
    """System information payload."""

    os: str
    hostname: str
    kernel: str
    uptime: float = Field(ge=0.0)
    platform: str  # Linux | Windows | Darwin


class HeartbeatPayload(BaseModel):
    """Heartbeat event payload."""

    agent_version: str
    status: str = "online"  # online | offline
    ip: Optional[str] = None
    hostname: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"online", "offline"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v


class MiniEDREvent(BaseModel):
    """Top-level event envelope for agent-server communication."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    hostname: str
    platform: str  # Linux | Windows | Darwin
    event_type: str  # heartbeat | fim | scan | system_info
    severity: str  # low | medium | high | critical
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    source: str = "agent"
    payload: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    glpi_requester_id: int | None = None

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v: str) -> str:
        allowed = {"Linux", "Windows", "Darwin"}
        if v not in allowed:
            raise ValueError(f"platform must be one of {allowed}, got '{v}'")
        return v

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        allowed = {"heartbeat", "fim", "scan", "system_info"}
        if v not in allowed:
            raise ValueError(f"event_type must be one of {allowed}, got '{v}'")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        allowed = {"agent", "server"}
        if v not in allowed:
            raise ValueError(f"source must be one of {allowed}, got '{v}'")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v.endswith("Z"):
            raise ValueError("timestamp must end with 'Z' for UTC timezone")
        try:
            iso_string = v.rstrip("Z")
            datetime.fromisoformat(iso_string)
        except ValueError as e:
            raise ValueError(f"timestamp must be valid ISO8601 format: {e}")
        return v

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        if not v:
            raise ValueError("agent_id cannot be empty")
        try:
            uuid.UUID(v, version=4)
        except ValueError:
            raise ValueError("agent_id must be a valid UUID4 hex string")
        return v

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        if not v:
            raise ValueError("event_id cannot be empty")
        try:
            uuid.UUID(v, version=4)
        except ValueError:
            raise ValueError("event_id must be a valid UUID4 hex string")
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def ensure_list(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return v
        raise ValueError("tags must be a list of strings")

    @model_validator(mode="after")
    def validate_payload_structure(self) -> "MiniEDREvent":
        """Validate payload based on event_type."""
        event_type = self.event_type
        payload = self.payload

        if event_type == "fim":
            # Should match FIMPayload structure
            required = {"filepath", "event_action"}
            if not all(k in payload for k in required):
                raise ValueError(f"FIM payload must contain: {required}")

        elif event_type == "heartbeat":
            # Should match HeartbeatPayload structure
            required = {"agent_version", "status", "hostname"}
            if not all(k in payload for k in required):
                raise ValueError(f"Heartbeat payload must contain: {required}")

        elif event_type == "system_info":
            # Should match SystemInfo structure
            required = {"os", "hostname", "kernel", "uptime", "platform"}
            if not all(k in payload for k in required):
                raise ValueError(f"SystemInfo payload must contain: {required}")

        elif event_type == "scan":
            # Scan payload can be any dict but should not be empty
            if not payload:
                raise ValueError("Scan payload cannot be empty")

        return self
