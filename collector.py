"""System information collection using psutil with cross-platform exception handling."""

import platform
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

import psutil


@dataclass
class ProcessInfo:
    pid: int
    name: str
    status: str
    exe: Optional[str]
    create_time: Optional[float]
    memory_mb: float
    cpu_percent: float


@dataclass
class DiskInfo:
    device: str
    mountpoint: str
    fstype: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


@dataclass
class SystemSnapshot:
    timestamp: str
    platform: str
    hostname: str
    cpu_count: int
    cpu_percent: float
    memory_total_gb: float
    memory_available_gb: float
    memory_percent: float
    disk_info: list[DiskInfo]
    processes: list[ProcessInfo]


def get_system_snapshot() -> SystemSnapshot:
    """Collect system snapshot with graceful error handling."""
    now = datetime.now().isoformat()
    platform_system = platform.system()

    snapshot = SystemSnapshot(
        timestamp=now,
        platform=platform_system,
        hostname=_safe_get_hostname(),
        cpu_count=psutil.cpu_count(logical=False) or 0,
        cpu_percent=_safe_cpu_percent(),
        memory_total_gb=_safe_memory_total(),
        memory_available_gb=_safe_memory_available(),
        memory_percent=_safe_memory_percent(),
        disk_info=_safe_get_disk_info(),
        processes=_safe_get_processes(),
    )
    return snapshot


def _safe_get_hostname() -> str:
    try:
        return platform.node()
    except Exception:
        return "unknown"


def _safe_cpu_percent() -> float:
    try:
        return psutil.cpu_percent(interval=0.1)
    except Exception:
        return 0.0


def _safe_memory_total() -> float:
    try:
        return psutil.virtual_memory().total / (1024**3)
    except Exception:
        return 0.0


def _safe_memory_available() -> float:
    try:
        return psutil.virtual_memory().available / (1024**3)
    except Exception:
        return 0.0


def _safe_memory_percent() -> float:
    try:
        return psutil.virtual_memory().percent
    except Exception:
        return 0.0


def _safe_get_disk_info() -> list[DiskInfo]:
    """Get disk partitions with exception handling for each partition."""
    disks = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return []

    for partition in partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk = DiskInfo(
                device=partition.device,
                mountpoint=partition.mountpoint,
                fstype=partition.fstype,
                total_gb=usage.total / (1024**3),
                used_gb=usage.used / (1024**3),
                free_gb=usage.free / (1024**3),
                percent=usage.percent,
            )
            disks.append(disk)
        except (OSError, PermissionError):
            continue

    return disks


def _safe_get_processes() -> list[ProcessInfo]:
    """Get process list with exception handling for each process."""
    processes = []
    try:
        pids = psutil.pids()
    except Exception:
        return []

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            try:
                name = proc.name()
            except psutil.AccessDenied:
                name = f"<access denied: {pid}>"

            try:
                status = proc.status()
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception:
                status = "unknown"

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, OSError):
                exe = None

            try:
                create_time = proc.create_time()
            except Exception:
                create_time = None

            try:
                memory_info = proc.memory_info()
                memory_mb = memory_info.rss / (1024**2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_mb = 0.0

            try:
                cpu_percent = proc.cpu_percent(interval=0.01)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cpu_percent = 0.0

            process = ProcessInfo(
                pid=pid,
                name=name,
                status=status,
                exe=exe,
                create_time=create_time,
                memory_mb=memory_mb,
                cpu_percent=cpu_percent,
            )
            processes.append(process)

        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.TimeoutExpired):
            continue
        except Exception:
            continue

    return processes


def snapshot_to_dict(snapshot: SystemSnapshot) -> dict[str, object]:
    """Convert SystemSnapshot to JSON-serializable dict."""
    data = asdict(snapshot)
    data["disk_info"] = [asdict(d) for d in snapshot.disk_info]
    data["processes"] = [asdict(p) for p in snapshot.processes]
    return data
