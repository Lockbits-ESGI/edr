# MiniEDR — Architecture & Implementation Patterns Guide

## Executive Summary

MiniEDR is a **cross-platform Python 3.10+ endpoint detection & response tool** with:
- System monitoring (process, network, users) via psutil
- File Integrity Monitoring (FIM) via watchdog
- VirusTotal v3 API integration for file reputation checking
- HTML/JSON report generation via Jinja2

**Codebase Status**: Greenfield (no existing code). All 8 modules must be built from scratch.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         main.py                             │
│              (CLI entry point + orchestration)              │
└────────┬────────────────────────────────────────────┬───────┘
         │                                            │
    ┌────▼─────────┐                        ┌────────▼──────┐
    │ config.py    │                        │  logger.py    │
    │ (YAML + env) │                        │ (RotatingFile)│
    └────────┬─────┘                        └───────────────┘
             │
    ┌────────▼──────────────────────────────────────────────┐
    │               collector.py (Thread: Main)             │
    │         psutil snapshot (processes, net, users)       │
    └────────────┬─────────────────────────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
    ┌────▼────────┐  ┌──▼──────────────┐
    │ hasher.py   │  │ vt_checker.py   │
    │ (SHA256/MD5)│  │ (VirusTotal v3) │
    └──────┬──────┘  │ (4 req/min)     │
           │         └────────┬────────┘
           │                  │
    ┌──────▼──────────────────▼──────────┐
    │      fim.py (Thread: Daemon)       │
    │   watchdog + Thread-safe Alerts    │
    └──────┬───────────────────────────┬─┘
           │                           │
           │                    ┌──────▼─────────┐
           │                    │ reporter.py    │
           │                    │ (JSON + HTML)  │
           │                    │ (Jinja2)       │
           │                    └────────────────┘
           │
    ┌──────▼─────────────────┐
    │  reports/ (output dir) │
    │ - report.json          │
    │ - report.html          │
    └────────────────────────┘
```

---

## Module Breakdown & Implementation Patterns

### 1. config.py — Configuration Management

**Platform-Specific Behavior**:
- **Linux**: Follow XDG Base Directory spec (`$XDG_CONFIG_HOME` → `~/.config`)
- **Windows**: Use `%APPDATA%`
- **macOS**: Use `~/.config` (XDG-like)

**Key Pattern** (from anywhere-agents):
```python
import os
from pathlib import Path
import yaml

def user_config_dir():
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return Path(appdata) / "miniedr" if appdata else None
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return Path(xdg) / "miniedr"
        home = os.environ.get("HOME")
        return Path(home) / ".config" / "miniedr" if home else None

def load_config(config_path):
    if not config_path.exists():
        return {}
    with open(config_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
    return data
```

**Load Order**:
1. Command-line `--config` argument (highest priority)
2. User-level config (XDG/APPDATA)
3. Bundled `config.yaml` (lowest priority)

---

### 2. logger.py — Cross-Platform Logging

**Key Pattern** (from TDengine + Azure CLI):
```python
import logging
from logging.handlers import RotatingFileHandler
import sys

def setup_logging(log_level, log_file):
    logger = logging.getLogger("miniedr")
    logger.setLevel(logging.DEBUG)  # Capture all
    
    # File handler (DEBUG level, rotate at 10MB, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_file,
        mode='a',  # Append mode works on both Windows/Linux
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler (INFO level only)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Format
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
```

**Critical**: Always use `mode='a'` (append) — ensures cross-platform compatibility.

---

### 3. collector.py — System Snapshot

**Key Pattern** (from SaltStack):
```python
import psutil
import platform

def get_system_snapshot():
    snapshot = {
        'system': {
            'platform': platform.system(),  # "Linux", "Windows", "Darwin"
            'hostname': platform.node(),
            'kernel_version': platform.release(),
            'uptime_seconds': int(time.time() - psutil.boot_time()),
        },
        'processes': [],
        'connections': [],
        'users': []
    }
    
    # Processes: handle NoSuchProcess race condition
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            snapshot['processes'].append({
                'pid': p.pid,
                'name': p.name(),
                'exe': p.exe(),
                'cpu_percent': p.cpu_percent(interval=0.1),
                'memory_percent': p.memory_percent(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # Skip dead/privileged processes
    
    # Connections: handle per-process and system-wide
    try:
        for conn in psutil.net_connections(kind='inet'):
            snapshot['connections'].append({
                'pid': conn.pid,
                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status,
            })
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass  # Graceful degradation
    
    # Users: active sessions
    try:
        snapshot['users'] = [
            {'user': u.name, 'terminal': u.terminal, 'host': u.host, 'started': u.tstamp}
            for u in psutil.users()
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    
    return snapshot
```

**Exception Handling**:
- `psutil.NoSuchProcess` — process died between pids() and Process()
- `psutil.AccessDenied` — no permissions (normal on Linux for root processes)
- `psutil.ZombieProcess` — process is zombie (handle gracefully)

---

### 4. hasher.py — File Hashing

**Key Pattern** (standard library):
```python
import hashlib
from typing import Optional

def compute_md5(filepath: str) -> Optional[str]:
    try:
        md5 = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):  # 8KB chunks
                md5.update(chunk)
        return md5.hexdigest()
    except (IOError, PermissionError):
        return None

def compute_sha256(filepath: str) -> Optional[str]:
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, PermissionError):
        return None
```

**Note**: Chunked reads handle large files without loading into memory.

---

### 5. vt_checker.py — VirusTotal API v3

**Key Pattern** (from CAPEv2 + production examples):

**Rate Limiting** (4 requests/minute = 15 seconds between requests):
```python
import requests
import time
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
VT_API_URL = "https://www.virustotal.com/api/v3/files"
VT_API_KEY = os.environ.get("VT_API_KEY")  # Load from .env

class RateLimiter:
    def __init__(self, requests_per_minute=4):
        self.min_interval = 60.0 / requests_per_minute  # 15 seconds
        self.last_request_time = 0.0
    
    def wait(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()

rate_limiter = RateLimiter(requests_per_minute=4)

def check_file(filepath: str) -> dict:
    """Check file with VirusTotal API v3."""
    # Compute SHA256
    sha256 = compute_sha256(filepath)
    if not sha256:
        return {'hash': None, 'status': 'unhashable'}
    
    rate_limiter.wait()  # Enforce rate limit before request
    
    headers = {'x-apikey': VT_API_KEY}
    url = f"{VT_API_URL}/{sha256}"
    
    try:
        logger.info(f"Querying VirusTotal for {sha256}")
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 404:
            logger.info(f"File not found in VirusTotal: {sha256}")
            return {'hash': sha256, 'status': 'unknown'}
        
        if response.status_code == 429:
            logger.warning("Rate limit exceeded")
            return {'hash': sha256, 'error': 'rate_limited'}
        
        if response.status_code != 200:
            logger.error(f"VT API error: {response.status_code}")
            return {'hash': sha256, 'error': response.status_code}
        
        data = response.json()
        analysis = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        
        return {
            'hash': sha256,
            'status': 'known',
            'malicious': analysis.get('malicious', 0),
            'suspicious': analysis.get('suspicious', 0),
            'undetected': analysis.get('undetected', 0),
            'total': sum(analysis.values()),
        }
    
    except requests.exceptions.Timeout:
        logger.error(f"VT request timeout for {sha256}")
        return {'hash': sha256, 'error': 'timeout'}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"VT connection error: {e}")
        return {'hash': sha256, 'error': 'connection_error'}
    except requests.exceptions.RequestException as e:
        logger.error(f"VT request failed: {e}")
        return {'hash': sha256, 'error': 'request_error'}
    except Exception as e:
        logger.error(f"Unexpected error checking VirusTotal: {e}")
        return {'hash': sha256, 'error': 'unexpected_error'}
```

**Critical**: Never hardcode API key in code. Load from `.env` via `python-dotenv`.

---

### 6. fim.py — File Integrity Monitoring

**Key Pattern** (from repowise + SaltStack + Google ADK):

```python
import threading
import time
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, PatternMatchingEventHandler
import logging

logger = logging.getLogger(__name__)

class FIMAlert:
    def __init__(self, timestamp, event_type, filepath, file_hash=None, vt_result=None):
        self.timestamp = timestamp
        self.event_type = event_type  # created, modified, deleted, moved
        self.filepath = filepath
        self.file_hash = file_hash
        self.vt_result = vt_result

class SecurityFileHandler(PatternMatchingEventHandler):
    def __init__(self, alerts, lock, vt_checker=None):
        # Monitor config files, binaries; ignore temp files
        super().__init__(
            patterns=['*.conf', '*.cfg', '*.ini', '*.yml', '*.yaml', '*.bin', '*.exe', '*.sh'],
            ignore_patterns=['*.tmp', '*.swp', '~*', '#*#', '.git/*', '.svn/*'],
            ignore_directories=True,
            case_sensitive=False
        )
        self.alerts = alerts  # shared deque
        self.lock = lock      # threading.Lock
        self.vt_checker = vt_checker
    
    def on_created(self, event):
        self._process(event, 'created')
    
    def on_modified(self, event):
        self._process(event, 'modified')
    
    def on_deleted(self, event):
        self._process(event, 'deleted')
    
    def on_moved(self, event):
        self._process(event, 'moved')
    
    def _process(self, event, event_type):
        filepath = event.src_path
        logger.debug(f"FIM event: {event_type} {filepath}")
        
        # Optional: check with VirusTotal
        vt_result = None
        file_hash = None
        if self.vt_checker and event_type in ['created', 'modified']:
            file_hash = compute_sha256(filepath)
            if file_hash:
                vt_result = self.vt_checker.check_file(filepath)
        
        # Create alert (thread-safe)
        alert = FIMAlert(
            timestamp=time.time(),
            event_type=event_type,
            filepath=filepath,
            file_hash=file_hash,
            vt_result=vt_result
        )
        
        with self.lock:
            self.alerts.append(alert)
        
        logger.info(f"FIM Alert: {event_type} {filepath}")

def start_fim_monitor(watch_dirs, vt_checker=None):
    """Start FIM monitoring in daemon thread."""
    alerts = deque()
    lock = threading.Lock()
    
    observer = Observer()
    event_handler = SecurityFileHandler(alerts, lock, vt_checker)
    
    for watch_dir in watch_dirs:
        try:
            observer.schedule(event_handler, watch_dir, recursive=True)
            logger.info(f"Monitoring {watch_dir}")
        except Exception as e:
            logger.error(f"Failed to schedule {watch_dir}: {e}")
    
    observer.start()
    
    return observer, alerts, lock

def get_alerts(alerts, lock):
    """Return and clear accumulated alerts (thread-safe)."""
    with lock:
        batch = list(alerts)
        alerts.clear()
    return batch

# In main.py:
try:
    observer, alerts, lock = start_fim_monitor(watch_dirs, vt_checker)
    
    # Main loop
    while True:
        time.sleep(5)
        current_alerts = get_alerts(alerts, lock)
        if current_alerts:
            logger.info(f"Got {len(current_alerts)} FIM alerts")

except KeyboardInterrupt:
    logger.info("Stopping FIM monitor...")
    observer.stop()
    observer.join()
```

**Thread Safety**:
- `threading.Lock()` protects `deque` append/pop
- Always copy under lock, then process outside lock
- `daemon=True` on observer thread ensures clean exit

---

### 7. reporter.py + templates/report.html.j2 — Report Generation

**Key Pattern** (from Django REST Framework + ansible-job-report):

**Python Generator**:
```python
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode()
        return super().default(obj)

def generate_json_report(snapshot, alerts, output_path):
    report_data = {
        'generated_at': datetime.now(),
        'snapshot': snapshot,
        'alerts': [
            {
                'timestamp': a.timestamp,
                'event_type': a.event_type,
                'filepath': a.filepath,
                'file_hash': a.file_hash,
                'vt_result': a.vt_result,
            }
            for a in alerts
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(report_data, f, cls=JSONEncoder, indent=2)

def generate_html_report(snapshot, alerts, output_path):
    env = Environment(
        loader=FileSystemLoader('templates'),
        autoescape=True
    )
    template = env.get_template('report.html.j2')
    
    # Filter alerts by severity
    malicious_alerts = [a for a in alerts if a.vt_result and a.vt_result.get('malicious', 0) > 0]
    suspicious_alerts = [a for a in alerts if a.vt_result and a.vt_result.get('suspicious', 0) > 0]
    clean_alerts = [a for a in alerts if a.vt_result and a.vt_result.get('malicious', 0) == 0]
    
    html = template.render(
        generated_at=datetime.now(),
        hostname=snapshot['system']['hostname'],
        platform=snapshot['system']['platform'],
        processes=snapshot['processes'],
        connections=snapshot['connections'],
        users=snapshot['users'],
        all_alerts=alerts,
        malicious_alerts=malicious_alerts,
        suspicious_alerts=suspicious_alerts,
        clean_alerts=clean_alerts,
        alert_count=len(alerts),
        malicious_count=len(malicious_alerts),
        suspicious_count=len(suspicious_alerts),
        clean_count=len(clean_alerts),
    )
    
    with open(output_path, 'w') as f:
        f.write(html)
```

**HTML Template** (`templates/report.html.j2`):
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MiniEDR Report</title>
    <style>
    {% include 'styles.css' %}
    </style>
</head>
<body>
    <div class="header">
        <h1>MiniEDR Report</h1>
        <p>Generated: {{ generated_at.isoformat() }}</p>
        <p>Host: {{ hostname }} ({{ platform }})</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Alerts: {{ alert_count }}</p>
        <p><span class="badge malicious">🔴 Malicious: {{ malicious_count }}</span></p>
        <p><span class="badge suspicious">🟡 Suspicious: {{ suspicious_count }}</span></p>
        <p><span class="badge clean">🟢 Clean: {{ clean_count }}</span></p>
    </div>
    
    <div class="alerts-section">
        <h2>File Integrity Alerts</h2>
        {% if all_alerts %}
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>File Path</th>
                    <th>Status</th>
                    <th>Hash</th>
                </tr>
            </thead>
            <tbody>
                {% for alert in all_alerts %}
                <tr class="{% if alert.vt_result.malicious > 0 %}malicious{% elif alert.vt_result.suspicious > 0 %}suspicious{% else %}clean{% endif %}">
                    <td>{{ alert.timestamp }}</td>
                    <td>{{ alert.event_type }}</td>
                    <td>{{ alert.filepath }}</td>
                    <td>
                        {% if alert.vt_result.malicious > 0 %}
                            <span class="badge malicious">🔴 MALICIOUS</span>
                        {% elif alert.vt_result.suspicious > 0 %}
                            <span class="badge suspicious">🟡 SUSPICIOUS</span>
                        {% else %}
                            <span class="badge clean">🟢 CLEAN</span>
                        {% endif %}
                    </td>
                    <td>{{ alert.file_hash[:16] }}...</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No alerts.</p>
        {% endif %}
    </div>
    
    <div class="processes-section">
        <h2>Process List (Top 20 by CPU)</h2>
        <table>
            <thead>
                <tr><th>PID</th><th>Name</th><th>CPU %</th><th>Memory %</th></tr>
            </thead>
            <tbody>
                {% for proc in processes[:20]|sort(attribute='cpu_percent', reverse=True) %}
                <tr>
                    <td>{{ proc.pid }}</td>
                    <td>{{ proc.name }}</td>
                    <td>{{ proc.cpu_percent|round(2) }}</td>
                    <td>{{ proc.memory_percent|round(2) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
```

**CSS** (`templates/styles.css`):
```css
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
    margin: 0;
    padding: 20px;
    background: #f5f5f5;
}

.header {
    background: #333;
    color: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
}

.summary {
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin-bottom: 20px;
}

th, td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

th {
    background: #f9f9f9;
    font-weight: 600;
}

tbody tr:hover {
    background: #f5f5f5;
}

tbody tr.malicious {
    background: #ffe6e6;
}

tbody tr.suspicious {
    background: #fff9e6;
}

tbody tr.clean {
    background: #e6f7e6;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: 600;
}

.badge.malicious {
    background: #dc3545;
    color: white;
}

.badge.suspicious {
    background: #ffc107;
    color: black;
}

.badge.clean {
    background: #28a745;
    color: white;
}
```

---

## Cross-Platform Compatibility Checklist

- [ ] **Platform Detection**: Use `platform.system()` with explicit "Linux", "Windows", "Darwin" comparisons
- [ ] **Path Handling**: Use `pathlib.Path` for all file operations (works cross-platform)
- [ ] **Config Paths**: XDG spec on POSIX, `%APPDATA%` on Windows
- [ ] **File I/O**: Always use `mode='a'` for append, explicit UTF-8 encoding
- [ ] **Process Monitoring**: Handle `psutil.NoSuchProcess`, `psutil.AccessDenied` gracefully
- [ ] **File Monitoring**: Use watchdog (cross-platform abstraction over inotify/FSEvents/ETW)
- [ ] **Logging**: RotatingFileHandler with `mode='a'` (cross-platform)
- [ ] **HTTP Requests**: Use `requests` with `timeout` parameter (prevents hangs)

---

## Error Handling Strategy

| Module | Exception | Strategy |
|--------|-----------|----------|
| collector.py | `psutil.NoSuchProcess` | `continue` to next process |
| collector.py | `psutil.AccessDenied` | Log and skip (expect on privileged processes) |
| hasher.py | `IOError`, `PermissionError` | Return `None` (caller decides action) |
| vt_checker.py | `requests.Timeout` | Log error, return `{'error': 'timeout'}` |
| vt_checker.py | `requests.ConnectionError` | Log error, return `{'error': 'connection_error'}` |
| fim.py | `watchdog` events | Log and continue (never crash observer) |
| reporter.py | Template rendering | Log error, write fallback report |

**Rule**: Never crash the application. Always gracefully degrade and log.

---

## Performance & Scale Targets

- **Process Monitoring**: <100ms for snapshot (typical system: 500-2000 processes)
- **File Hashing**: SHA256 at ~100 MB/sec (chunked I/O)
- **VirusTotal Rate**: 4 requests/minute (enforced via sleep, no queue backlog)
- **FIM**: Sub-second response to file events (watchdog observer)
- **Report Generation**: <5 seconds for typical system state

---

## Testing Strategy

**Unit Tests** (`tests/`):
- `test_hasher.py` — Compute hashes, verify correctness, handle missing files
- `test_vt_checker.py` — Mock API responses, test rate limiting, error cases

**Integration Tests** (manual):
- Verify FIM alerts on file creation/modification
- Verify HTML/JSON reports generate without errors
- Verify cross-platform compatibility (run on Linux + Windows + macOS)

**No External Dependencies**:
- Mock `requests` library for VT API tests
- Mock file system for hasher tests
- Don't require actual VirusTotal API key for tests

---

## Deployment Notes

**Requirements Installation**:
```bash
pip install -r requirements.txt
```

**First Run Setup**:
```bash
# Copy .env.example to .env and add your VT API key
cp .env.example .env
# Add your API key to .env
```

**Running**:
```bash
# Monitor mode (default, runs until Ctrl+C)
python main.py --mode monitor

# Scan mode (single snapshot, no FIM)
python main.py --mode scan --output-dir ./reports

# Custom config
python main.py --config /custom/config.yaml
```

---

## Known Limitations & Future Work

**Current Scope**:
- Read-only system monitoring (no remediation actions)
- VirusTotal v3 free tier (4 req/min, file lookup only)
- Local file systems only (no network shares)
- No agent/server architecture (standalone tool)

**Future Enhancements**:
- Database persistence (SQLite for alert history)
- Real-time alerting (Slack, syslog, SIEM integration)
- Privilege escalation detection
- Memory analysis (yara signatures)
- Server/agent architecture for fleet monitoring
- VirusTotal paid tier support (higher rate limit)
