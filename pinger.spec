# -*- mode: python ; coding: utf-8 -*-

# Define icon filename here as well for consistency
ICON_FILENAME = "app_icon.ico"

a = Analysis(
    ['pinger.py'],
    pathex=[],
    binaries=[],
    # --- ADD ICON TO DATAS ---
    datas=[(ICON_FILENAME, '.')], # Bundle ICON_FILENAME into the root (.)
    # --- END ---
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
    # --- NO NEED TO ADD TO a.binaries or a.datas here again ---
    a.binaries,
    a.datas,
    # --- END ---
    [],
    name='PingWatch', # Use the name from your command
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # --- Use console=False and disable_windowed_traceback ---
    console=False,                # Matches --noconsole
    disable_windowed_traceback=False,
    # --- END ---
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app_icon.ico', # Set the EXE icon here
    uac_admin=True,       # Request admin privileges
)