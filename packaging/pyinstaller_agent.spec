# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for MiniEDR Agent onefile binary."""

from pathlib import Path

project_root = Path(SPECPATH).parent

a = Analysis(
    [str(project_root / 'agent' / 'main.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / 'agent' / 'config.yaml'), 'agent'),
        (str(project_root / 'templates' / 'report.html.j2'), 'templates'),
    ],
    hiddenimports=[
        'psutil',
        'watchdog',
        'watchdog.observers',
        'watchdog.events',
        'jinja2',
        'yaml',
        'pydantic',
        'dotenv',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='miniedr-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
