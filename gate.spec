# -*- mode: python -*-

a = Analysis(['submodule_public.py'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='submodule_public',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    version='..\\ms_version_1.txt', # Specify version info file for metadata
)
