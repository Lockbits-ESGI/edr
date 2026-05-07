# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for MiniEDR Server onefile binary."""

a = Analysis(
    ['server/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('server/.env.example', 'server'),
        ('shared', 'shared'),
    ],
    hiddenimports=[
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'sqlalchemy.pool',
        'pydantic',
        'pydantic_settings',
        'httpx',
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
    name='miniedr-server',
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
