# MiniEDR — Research & Patterns Reference (Generated from GitHub Analysis)

This document consolidates real-world patterns extracted from production codebases for use during MiniEDR implementation.

---

## 1. Cross-Platform Python Patterns

### Platform Detection

**Source**: LLVM Project, Dangerzone, Hermes Agent

```python
import platform
import sys

# Platform detection
def get_platform():
    system = platform.system()
    if system == "Darwin":
        return "macos"
    elif system == "Windows":
        return "windows"
    elif system == "Linux":
        return "linux"
    else:
        return "unknown"

# WSL detection (Linux that's actually Windows)
def is_wsl():
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower() or "wsl" in platform.release().lower()
    except FileNotFoundError:
        return False
```

### Logging Setup

**Source**: TDengine, Azure CLI (production-proven)

```python
import logging
from logging.handlers import RotatingFileHandler
import sys

def setup_logging(log_level="INFO", log_file="app.log"):
    logger = logging.getLogger("miniedr")
    logger.setLevel(logging.DEBUG)  # Capture all internally
    
    # File handler: DEBUG level with rotation
    file_handler = RotatingFileHandler(
        log_file,
        mode='a',  # Critical: 'a' = append, works on Windows + Linux
        maxBytes=10 * 1024 * 1024,  # 10MB per file
        backupCount=5  # Keep 5 old files
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler: INFO level (user-facing)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level))
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
```

### YAML Config Loading (XDG + APPDATA)

**Source**: anywhere-agents (XDG-compliant)

```python
import os
import sys
from pathlib import Path
import yaml

def get_config_dir():
    """Get platform-specific config directory."""
    if sys.platform == "win32":
        # Windows: %APPDATA%
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "miniedr"
        return None
    else:
        # POSIX (Linux/macOS): XDG Base Directory
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return Path(xdg) / "miniedr"
        home = os.environ.get("HOME")
        if home:
            return Path(home) / ".config" / "miniedr"
        return None

def load_config(config_path):
    """Load YAML config with error handling."""
    if not config_path.exists():
        return {}
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError as e:
        logger.error(f"Config YAML error: {e}")
        return {}
    except OSError as e:
        logger.error(f"Config read error: {e}")
        return {}
```

---

## 2. psutil Exception Handling

**Source**: SaltStack, mlflow, TDengine (battle-tested)

### Pattern: Graceful Process Iteration

```python
import psutil

# Process iteration with full exception handling
def get_processes_safe():
    processes = []
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            processes.append({
                'pid': p.pid,
                'name': p.name(),
                'exe': p.exe(),
                'cmdline': ' '.join(p.cmdline()) if p.cmdline() else None,
                'cpu_percent': p.cpu_percent(interval=0.1),
                'memory_percent': p.memory_percent(),
            })
        except psutil.NoSuchProcess:
            # Process terminated between pids() call and Process() instantiation
            continue
        except psutil.AccessDenied:
            # No permissions to access process (normal on Linux for root processes)
            logger.debug(f"Access denied for PID {pid}")
            continue
        except psutil.ZombieProcess:
            # Process is zombie (can't read attributes)
            continue
    return processes
```

### Pattern: Safe CPU Times with ZombieProcess

```python
def get_cpu_times_safe(process):
    """Get CPU times, handling zombie processes."""
    try:
        return process.cpu_times()
    except psutil.ZombieProcess:
        # Can't read zombie process CPU times
        return None
    except psutil.NoSuchProcess:
        # Process died
        return None
    except psutil.AccessDenied:
        # Permission denied
        return None
```

### Pattern: Process Termination with Escalation

```python
def terminate_process_tree(pid):
    """Kill a process and all children with progressive escalation."""
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return  # Already dead
    
    # Kill children first
    children = parent.children(recursive=True)
    for child in children:
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    
    # Wait for children to terminate
    _, still_alive = psutil.wait_procs(children, timeout=3)
    
    # Force kill survivors
    for p in still_alive:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass
    
    # Terminate parent
    try:
        parent.terminate()
        parent.wait(timeout=3)
    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
        try:
            parent.kill()
        except psutil.NoSuchProcess:
            pass
```

---

## 3. VirusTotal API v3 Integration

**Source**: CAPEv2, IBM mcp-context-forge

### Pattern: File Hash Lookup

```python
import requests
from http import HTTPStatus

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.environ.get("VT_API_KEY")  # Never hardcode!

def vt_file_lookup(sha256_hash: str, timeout: int = 15) -> dict:
    """Lookup file in VirusTotal by SHA256."""
    if not VT_API_KEY:
        return {'error': 'VT_API_KEY not set'}
    
    url = f"{VT_API_BASE}/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == HTTPStatus.NOT_FOUND:
            logger.info(f"File not in VirusTotal: {sha256_hash}")
            return {'hash': sha256_hash, 'status': 'unknown'}
        
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            logger.warning("VT rate limit hit")
            return {'hash': sha256_hash, 'error': 'rate_limited'}
        
        if response.status_code != HTTPStatus.OK:
            logger.error(f"VT error {response.status_code}")
            return {'hash': sha256_hash, 'error': response.status_code}
        
        data = response.json()
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        
        return {
            'hash': sha256_hash,
            'status': 'known',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'total_vendors': sum(stats.values()),
        }
    
    except requests.exceptions.Timeout:
        logger.error(f"VT timeout for {sha256_hash}")
        return {'hash': sha256_hash, 'error': 'timeout'}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"VT connection error: {e}")
        return {'hash': sha256_hash, 'error': 'connection_error'}
    except requests.exceptions.RequestException as e:
        logger.error(f"VT request error: {e}")
        return {'hash': sha256_hash, 'error': 'request_error'}
```

### Pattern: Rate Limiting (4 req/min = 15s intervals)

```python
import time

class VTRateLimiter:
    """Enforce VirusTotal free tier rate limit (4 req/min)."""
    
    def __init__(self, requests_per_minute: int = 4):
        self.min_interval = 60.0 / requests_per_minute  # 15 seconds
        self.last_request_time = 0.0
        self.logger = logging.getLogger(__name__)
    
    def wait(self):
        """Block until enough time has passed since last request."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            self.logger.debug(f"Rate limit: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

# Usage
rate_limiter = VTRateLimiter(requests_per_minute=4)

for sha256 in file_hashes:
    rate_limiter.wait()  # Enforce rate limit BEFORE request
    result = vt_file_lookup(sha256)
```

---

## 4. Watchdog + File Monitoring Patterns

**Source**: repowise, SaltStack, Google ADK

### Pattern: Observer Lifecycle & Graceful Shutdown

```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import time
import signal

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"File created: {event.src_path}")
    
    def on_modified(self, event):
        if not event.is_directory:
            logger.info(f"File modified: {event.src_path}")

def start_observer(watch_paths):
    """Start file monitoring in main thread."""
    observer = Observer()
    handler = MyHandler()
    
    for path in watch_paths:
        observer.schedule(handler, path, recursive=True)
    
    observer.start()
    logger.info("Observer started")
    
    try:
        # Block until KeyboardInterrupt
        while observer.is_alive():
            observer.join(timeout=1)
    except KeyboardInterrupt:
        logger.info("Stopping observer...")
    finally:
        observer.stop()
        observer.join()
        logger.info("Observer stopped")
```

### Pattern: Thread-Safe Alert Accumulation (with Locking)

```python
import threading
from collections import deque
from dataclasses import dataclass
from typing import List

@dataclass
class Alert:
    timestamp: float
    event_type: str  # created, modified, deleted, moved
    filepath: str
    hash: str = None

class SecurityHandler(FileSystemEventHandler):
    def __init__(self, alerts: deque, lock: threading.Lock):
        self.alerts = alerts
        self.lock = lock
    
    def on_any_event(self, event):
        if event.is_directory:
            return
        
        alert = Alert(
            timestamp=time.time(),
            event_type=event.event_name,
            filepath=event.src_path
        )
        
        # Add to shared queue (thread-safe with lock)
        with self.lock:
            self.alerts.append(alert)

# Main thread
alerts = deque()
lock = threading.Lock()
handler = SecurityHandler(alerts, lock)

observer = Observer()
observer.schedule(handler, "/path/to/monitor", recursive=True)
observer.start()

# Retrieve alerts safely
while True:
    time.sleep(5)
    with lock:
        batch = list(alerts)
        alerts.clear()
    
    if batch:
        logger.info(f"Got {len(batch)} alerts")
        for alert in batch:
            logger.info(f"  {alert.event_type}: {alert.filepath}")
```

### Pattern: PatternMatchingEventHandler for Filtering

```python
from watchdog.events import PatternMatchingEventHandler

class SecurityFileHandler(PatternMatchingEventHandler):
    """Monitor only security-relevant files, ignore noise."""
    
    def __init__(self):
        super().__init__(
            # Include patterns: config files, binaries, scripts
            patterns=['*.conf', '*.cfg', '*.ini', '*.yml', '*.yaml', 
                     '*.bin', '*.exe', '*.sh', '*.bat', '*.ps1'],
            # Exclude patterns: temporary files, editor backups, VCS
            ignore_patterns=['*.tmp', '*.swp', '~*', '#*#', 
                            '.git/*', '.svn/*', '__pycache__/*',
                            'node_modules/*'],
            ignore_directories=True,
            case_sensitive=False
        )
    
    def on_created(self, event):
        logger.info(f"Created: {event.src_path}")
    
    def on_modified(self, event):
        logger.info(f"Modified: {event.src_path}")
```

### Pattern: Debouncing (for editor atomic saves)

```python
import threading

class DebouncedHandler(FileSystemEventHandler):
    """Debounce rapid file events (editor atomic saves)."""
    
    def __init__(self, debounce_ms=1000):
        self.debounce_ms = debounce_ms
        self.timer = None
        self.pending_files = set()
        self.lock = threading.Lock()
    
    def on_any_event(self, event):
        if event.is_directory:
            return
        
        with self.lock:
            self.pending_files.add(event.src_path)
            
            # Cancel old timer and create new one
            if self.timer:
                self.timer.cancel()
            
            self.timer = threading.Timer(
                self.debounce_ms / 1000.0,
                self._process_batch
            )
            self.timer.daemon = True
            self.timer.start()
    
    def _process_batch(self):
        with self.lock:
            batch = list(self.pending_files)
            self.pending_files.clear()
            self.timer = None
        
        # Process entire batch after debounce period
        for filepath in batch:
            logger.info(f"Processing: {filepath}")
```

---

## 5. Jinja2 HTML Reporting Patterns

**Source**: Django REST Framework, ansible-job-report, cve-bin-tool

### Pattern: Custom JSON Encoder (datetime handling)

```python
import json
import datetime
import uuid
from typing import Any

class JSONEncoder(json.JSONEncoder):
    """Encode datetime, date, time, UUID, bytes."""
    
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime.datetime):
            # ISO 8601 format: "2026-05-07T10:30:45.123456"
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            # "2026-05-07"
            return obj.isoformat()
        elif isinstance(obj, datetime.time):
            # "10:30:45.123456"
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            # Total seconds as float
            return obj.total_seconds()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, bytes):
            # Decode bytes to string
            return obj.decode('utf-8', errors='replace')
        
        return super().default(obj)

# Usage
report_data = {
    'generated_at': datetime.datetime.now(),
    'timestamp': datetime.datetime.now(),
    'items': [...]
}
json_string = json.dumps(report_data, cls=JSONEncoder, indent=2)
```

### Pattern: Jinja2 Template with Inline CSS (No External Dependencies)

```python
from jinja2 import Environment, FileSystemLoader

# Setup
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=True  # Auto-escape for security
)

# Render
template = env.get_template('report.html.j2')
html = template.render(
    title="MiniEDR Report",
    generated_at=datetime.datetime.now(),
    hostname=socket.gethostname(),
    data=report_data
)

# Write
with open('report.html', 'w') as f:
    f.write(html)
```

### HTML Template Pattern (Inline CSS)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        /* Inline CSS - no external dependencies */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container { max-width: 1200px; margin: 0 auto; }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        
        .section {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #f9f9f9;
            font-weight: 600;
            color: #555;
        }
        
        tbody tr:hover { background: #fafafa; }
        
        /* Severity badges */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.malicious { background: #ff4757; color: white; }
        .badge.suspicious { background: #ffa502; color: white; }
        .badge.clean { background: #2ed573; color: white; }
        
        /* Row highlighting */
        tr.malicious { background: #ffe6e6; }
        tr.suspicious { background: #fff5e6; }
        tr.clean { background: #e6f9e6; }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-number { font-size: 2em; font-weight: 700; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p>Generated: {{ generated_at.isoformat() }}</p>
            <p>Host: {{ hostname }}</p>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{{ malicious_count }}</div>
                    <div class="stat-label">Malicious</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ suspicious_count }}</div>
                    <div class="stat-label">Suspicious</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ clean_count }}</div>
                    <div class="stat-label">Clean</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Alerts</h2>
            {% if alerts %}
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event</th>
                        <th>File</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in alerts %}
                    <tr class="{% if alert.malicious %}malicious{% elif alert.suspicious %}suspicious{% else %}clean{% endif %}">
                        <td>{{ alert.timestamp }}</td>
                        <td>{{ alert.event_type }}</td>
                        <td>{{ alert.filepath }}</td>
                        <td>
                            {% if alert.malicious %}
                            <span class="badge malicious">🔴 Malicious</span>
                            {% elif alert.suspicious %}
                            <span class="badge suspicious">🟡 Suspicious</span>
                            {% else %}
                            <span class="badge clean">🟢 Clean</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No alerts.</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
```

---

## References & Production Sources

| Pattern | Source | Repo | Language |
|---------|--------|------|----------|
| Platform detection | LLVM Project | llvm/llvm-project | C++ |
| Logging setup | TDengine | taosdata/TDengine | Python |
| Config loading | anywhere-agents | yzhao062/anywhere-agents | Python |
| psutil handling | SaltStack | saltstack/salt | Python |
| VirusTotal API | CAPEv2 | kevoreilly/CAPEv2 | Python |
| Watchdog patterns | repowise | repowise-dev/repowise | Python |
| HTML reporting | cve-bin-tool | intel/cve-bin-tool | Python |
| JSON encoding | Django REST | encode/django-rest-framework | Python |

All examples are from **actively maintained**, **production-grade** open-source projects (updated 2026).

