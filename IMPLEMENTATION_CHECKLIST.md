# MiniEDR — Quick Reference Checklist

Use this checklist during implementation to verify patterns are followed correctly.

---

## ✅ Pre-Implementation Checklist

- [ ] Read RESEARCH_SUMMARY.md (5 min) — understand research scope
- [ ] Read IMPLEMENTATION_GUIDE.md (15 min) — study architecture
- [ ] Reference PATTERNS_REFERENCE.md as needed — copy patterns
- [ ] Review todo list — understand sequence
- [ ] Verify Python 3.10+ available (`python3 --version`)

---

## ✅ Module Implementation Checklist

### 1. config.py — YAML Config Loading

**Imports**:
```python
import os, sys, yaml
from pathlib import Path
```

**Key Functions**:
- [ ] `get_config_dir()` — Returns platform-specific config directory (XDG/APPDATA)
- [ ] `load_config(path)` — Loads YAML safely, returns dict
- [ ] `get_config(key, default)` — Retrieves config value with fallback

**Platform-Specific Behavior**:
- [ ] Windows: Use `os.environ['APPDATA']` → `Path(...) / "miniedr"`
- [ ] Linux/macOS: Check `$XDG_CONFIG_HOME` first, then `~/.config`
- [ ] Use `pathlib.Path` (works on all platforms)
- [ ] Use `encoding='utf-8'` explicitly

**Error Handling**:
- [ ] yaml.YAMLError caught, logged, returns empty dict
- [ ] OSError caught, logged, returns empty dict
- [ ] Top-level must be dict, return {} if not

**✅ When complete**: You can import `config.load_config()` and get platform-aware YAML

---

### 2. logger.py — Cross-Platform Logging

**Imports**:
```python
import logging
from logging.handlers import RotatingFileHandler
import sys
```

**Key Function**:
- [ ] `setup_logging(level, log_file)` — Returns configured logger

**Implementation Details**:
- [ ] Logger named "miniedr" with DEBUG level (internal)
- [ ] File handler: RotatingFileHandler with `mode='a'`, 10MB max, 5 backups
- [ ] Console handler: StreamHandler to sys.stdout with INFO level (user-facing)
- [ ] Format: `%(asctime)s [%(levelname)-8s] %(name)s: %(message)s`
- [ ] Dateformat: `%Y-%m-%d %H:%M:%S`

**Critical Details**:
- [ ] ALWAYS use `mode='a'` (append) — this is cross-platform
- [ ] File handler writes DEBUG (detailed), console writes INFO+ (user-friendly)
- [ ] RotatingFileHandler prevents infinite log growth
- [ ] Both handlers use SAME formatter

**✅ When complete**: Logger can be used: `logger = setup_logging()` and logs work on both Windows/Linux

---

### 3. collector.py — System Snapshot via psutil

**Imports**:
```python
import psutil, platform, time, logging
```

**Key Function**:
- [ ] `get_system_snapshot()` — Returns dict with system info

**Structure**:
```python
snapshot = {
    'system': {...},      # platform, hostname, kernel, uptime
    'processes': [...],   # List of process dicts
    'connections': [...], # List of network connection dicts
    'users': [...]        # List of active user dicts
}
```

**Process Fields**:
- [ ] pid, name, exe, cpu_percent, memory_percent

**Connection Fields**:
- [ ] pid, laddr (ip:port), raddr (ip:port), status

**Exception Handling**:
- [ ] `psutil.NoSuchProcess` — `continue` (process died)
- [ ] `psutil.AccessDenied` — `continue` (no permissions, normal for root)
- [ ] `psutil.ZombieProcess` — Handle gracefully (skip that attribute)

**Critical**:
- [ ] Never crash on permission denied
- [ ] Silently skip processes we can't read
- [ ] Log warnings only

**✅ When complete**: `snapshot = get_system_snapshot()` returns dict with all system state

---

### 4. hasher.py — File Hashing (MD5 & SHA256)

**Imports**:
```python
import hashlib
from typing import Optional
```

**Key Functions**:
- [ ] `compute_md5(filepath: str) -> Optional[str]`
- [ ] `compute_sha256(filepath: str) -> Optional[str]`

**Implementation**:
- [ ] Use `hashlib.md5()` or `hashlib.sha256()`
- [ ] Read file in **8KB chunks** (handle large files without memory bloat)
- [ ] Use `hexdigest()` to get hex string
- [ ] Return `None` on IOError or PermissionError
- [ ] Never crash

**Loop Pattern**:
```python
hash_obj = hashlib.sha256()
with open(filepath, 'rb') as f:
    for chunk in iter(lambda: f.read(8192), b''):
        hash_obj.update(chunk)
return hash_obj.hexdigest()
```

**✅ When complete**: Both functions work, return hex strings or None

---

### 5. vt_checker.py — VirusTotal API v3

**Imports**:
```python
import requests, time, logging, os
from http import HTTPStatus
```

**Key Functions**:
- [ ] `RateLimiter` class — Enforce 4 req/min (15 second intervals)
- [ ] `check_file(filepath: str) -> dict` — Check file with VT API

**RateLimiter**:
- [ ] `__init__(requests_per_minute=4)` — Calculate min_interval = 60/4 = 15 seconds
- [ ] `wait()` — Sleep if needed to enforce interval

**check_file() Returns**:
- [ ] Success (200): `{'hash': sha256, 'status': 'known', 'malicious': X, 'suspicious': Y, ...}`
- [ ] Not found (404): `{'hash': sha256, 'status': 'unknown'}`
- [ ] Error: `{'hash': sha256, 'error': 'reason'}`

**API Details**:
- [ ] URL: `https://www.virustotal.com/api/v3/files/{sha256}`
- [ ] Header: `x-apikey: {VT_API_KEY}`
- [ ] Load key from `os.environ['VT_API_KEY']` (NEVER hardcode)
- [ ] Timeout: 15 seconds per request

**Exception Handling**:
- [ ] `requests.exceptions.Timeout` — Log, return `{'error': 'timeout'}`
- [ ] `requests.exceptions.ConnectionError` — Log, return `{'error': 'connection_error'}`
- [ ] Any other RequestException — Log, return `{'error': 'request_error'}`

**Logging**:
- [ ] Log INFO: File lookup
- [ ] Log WARNING: Rate limit hit
- [ ] Log ERROR: API errors
- [ ] Log all requests so we can audit rate limiting

**Critical**:
- [ ] CALL `rate_limiter.wait()` BEFORE each request
- [ ] Never hardcode VT API key
- [ ] Use `timeout=15` on requests

**✅ When complete**: `result = check_file('path/to/file')` returns VT analysis dict

---

### 6. fim.py — File Integrity Monitoring (watchdog)

**Imports**:
```python
import threading, time, logging
from collections import deque
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
```

**Data Classes**:
- [ ] `FIMAlert` — timestamp, event_type, filepath, file_hash, vt_result

**Handler**:
- [ ] Extend `PatternMatchingEventHandler`
- [ ] Patterns include: config files, binaries, scripts
- [ ] Ignore patterns: `*.tmp`, `*.swp`, `~*`, `.git/*`, etc.
- [ ] Implement: `on_created`, `on_modified`, `on_deleted`, `on_moved`
- [ ] Use `threading.Lock` to protect shared alerts deque

**Observer Lifecycle**:
- [ ] `observer = Observer()`
- [ ] `observer.schedule(handler, path, recursive=True)` for each watch dir
- [ ] `observer.start()` — Start observer thread
- [ ] Main loop with `while observer.is_alive(): observer.join(timeout=1)`
- [ ] On KeyboardInterrupt: `observer.stop()`, then `observer.join()`

**Thread Safety**:
- [ ] Use `threading.Lock()` to protect deque
- [ ] Append under lock: `with lock: alerts.append(...)`
- [ ] Copy under lock, process outside lock

**Logging**:
- [ ] Log DEBUG for each FIM event
- [ ] Log INFO for alerts
- [ ] Log ERROR for exceptions

**✅ When complete**: Observer runs, detects file changes, accumulates alerts safely

---

### 7. reporter.py — JSON & HTML Report Generation

**Imports**:
```python
import json, logging, datetime
from jinja2 import Environment, FileSystemLoader
```

**JSON Encoder**:
- [ ] Extend `json.JSONEncoder`
- [ ] Override `default()` method
- [ ] Handle: datetime (→ isoformat()), date, time, UUID, bytes
- [ ] Return `obj.isoformat()` for datetime objects

**JSON Report**:
- [ ] Function: `generate_json_report(snapshot, alerts, output_path)`
- [ ] Use custom JSONEncoder
- [ ] Write with `indent=2` for readability

**HTML Report**:
- [ ] Function: `generate_html_report(snapshot, alerts, output_path)`
- [ ] Load template from `templates/report.html.j2`
- [ ] Pass context: hostname, platform, processes, connections, alerts, counts
- [ ] Write HTML to file

**Template**:
- [ ] File: `templates/report.html.j2`
- [ ] Include inline CSS (no external dependencies)
- [ ] Responsive design (CSS Grid/Flexbox)
- [ ] Color-coded badges: 🔴 malicious, 🟡 suspicious, 🟢 clean
- [ ] Tables for processes, alerts, connections
- [ ] Summary section with counts

**✅ When complete**: `generate_json_report()` and `generate_html_report()` produce valid outputs

---

### 8. main.py — Entry Point & Orchestration

**Imports**:
```python
import argparse, logging, time, sys
from config import load_config
from logger import setup_logging
from collector import get_system_snapshot
from fim import start_fim_monitor, get_alerts
from reporter import generate_json_report, generate_html_report
```

**CLI Arguments**:
- [ ] `--mode` — "monitor" (default) or "scan"
- [ ] `--config` — Path to config file
- [ ] `--output-dir` — Report output directory

**Behavior**:
- [ ] **scan mode**: Single snapshot, no FIM, generate reports, exit
- [ ] **monitor mode**: Start FIM, periodic snapshots, generate reports on Ctrl+C

**Execution**:
1. [ ] Parse arguments
2. [ ] Load config
3. [ ] Setup logging
4. [ ] Get initial snapshot
5. [ ] Start FIM observer (daemon thread)
6. [ ] Main loop (check alerts, periodic snapshots)
7. [ ] On KeyboardInterrupt: Stop observer, generate final reports
8. [ ] Exit gracefully

**✅ When complete**: `python main.py --mode monitor` runs, detects files, generates reports on Ctrl+C

---

## ✅ Cross-Platform Verification Checklist

**Before final submission**:
- [ ] Platform detection: `platform.system()` returns expected values
- [ ] Logging: File handler uses `mode='a'` (checked in code)
- [ ] Config: XDG path logic correct for Linux, APPDATA for Windows
- [ ] Paths: All use `pathlib.Path` (not string concatenation)
- [ ] Encoding: UTF-8 explicit in all file operations
- [ ] Exceptions: No bare `except:`, all exceptions named
- [ ] Type hints: All functions have type hints
- [ ] Docstrings: All public functions have docstrings

---

## ✅ Error Handling Verification

**Per-module exception checklist**:

**config.py**:
- [ ] yaml.YAMLError caught
- [ ] OSError caught
- [ ] Returns sensible defaults (empty dict)

**logger.py**:
- [ ] No exceptions expected (stdlib library)

**collector.py**:
- [ ] `psutil.NoSuchProcess` handled
- [ ] `psutil.AccessDenied` handled
- [ ] `psutil.ZombieProcess` handled

**hasher.py**:
- [ ] IOError caught
- [ ] PermissionError caught
- [ ] Returns None on errors

**vt_checker.py**:
- [ ] `requests.exceptions.Timeout` caught
- [ ] `requests.exceptions.ConnectionError` caught
- [ ] `requests.exceptions.RequestException` caught (general fallback)

**fim.py**:
- [ ] Observer doesn't crash on file system errors
- [ ] Errors logged, processing continues

**reporter.py**:
- [ ] Template rendering errors caught
- [ ] JSON serialization errors caught
- [ ] File write errors caught

**main.py**:
- [ ] KeyboardInterrupt handled (graceful shutdown)
- [ ] All module exceptions caught, logged

---

## ✅ Testing Checklist

**Unit Tests** (`tests/`):

**test_hasher.py**:
- [ ] Test MD5 computation (known file)
- [ ] Test SHA256 computation (known file)
- [ ] Test with nonexistent file (returns None)
- [ ] Test with permission-denied file (returns None, no exception)

**test_vt_checker.py**:
- [ ] Mock requests library
- [ ] Test successful response (200)
- [ ] Test not found (404)
- [ ] Test rate limit (429)
- [ ] Test timeout exception
- [ ] Test connection error exception

**Integration Tests** (manual):
- [ ] Run on Linux (if available)
- [ ] Run on Windows (or simulate)
- [ ] Test FIM detects file creation
- [ ] Test FIM detects file modification
- [ ] Test reports generate without errors
- [ ] Test HTML report is valid (can open in browser)
- [ ] Test JSON report is valid (can parse)

---

## ✅ Documentation Verification

- [ ] IMPLEMENTATION_GUIDE.md exists (architecture + patterns)
- [ ] PATTERNS_REFERENCE.md exists (code examples)
- [ ] RESEARCH_SUMMARY.md exists (research overview)
- [ ] All modules have docstrings
- [ ] README.md created (how to run)
- [ ] config.yaml documented (all sections explained)

---

## Final Verification Checklist

Before marking COMPLETE:

**Code Quality**:
- [ ] No `as any` type suppressions
- [ ] No `@ts-ignore` or `@ts-expect-error`
- [ ] No bare `except:` blocks
- [ ] No empty `catch(e) {}` blocks
- [ ] All type hints present
- [ ] All public functions documented

**Functionality**:
- [ ] All imports work (no ModuleNotFoundError)
- [ ] All functions execute without errors
- [ ] Platform detection works
- [ ] Config loading works
- [ ] Logger writes to file
- [ ] Processes can be listed
- [ ] Files can be hashed
- [ ] VT API can be queried (if key provided)
- [ ] FIM detects changes
- [ ] Reports generate

**Cross-Platform**:
- [ ] Windows path handling works
- [ ] Linux path handling works
- [ ] macOS path handling works
- [ ] File I/O uses UTF-8
- [ ] Logging uses append mode

**Security**:
- [ ] VT API key never hardcoded
- [ ] VT API key loaded from .env
- [ ] Jinja2 autoescape=True (prevent XSS in HTML)
- [ ] YAML uses safe_load (prevent arbitrary code execution)

---

## Success Criteria (✅ = Ready to Ship)

- ✅ All 8 modules implemented
- ✅ All exceptions handled gracefully
- ✅ Cross-platform compatibility verified
- ✅ All tests pass
- ✅ HTML/JSON reports generate correctly
- ✅ Documentation complete
- ✅ No type errors
- ✅ No linter warnings (if using pylint/flake8)

---

**Use this checklist as you implement each module. Check off items as completed.**

**If all items checked = Implementation complete and ready for review.**

