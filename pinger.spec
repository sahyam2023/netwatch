# -*- mode: python ; coding: utf-8 -*-

# Define icon filename here as well for consistency
ICON_FILENAME = "app_icon.ico"
# Define the sound file name
SOUND_FILENAME = "alert.wav"

a = Analysis(
    ['pinger.py'],
    pathex=[],
    binaries=[],
    # --- FIX: Add alert.wav to datas ---
    datas=[(ICON_FILENAME, '.'), (SOUND_FILENAME, '.')], # Bundle both files
    # --- END FIX ---
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetWatch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app_icon.ico',
    uac_admin=True,
)