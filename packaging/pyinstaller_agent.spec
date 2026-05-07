# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for MiniEDR Agent onefile binary."""

a = Analysis(
    ['agent/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('agent/config.yaml', 'agent'),
        ('templates/report.html.j2', 'templates'),
        ('shared', 'shared'),
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
