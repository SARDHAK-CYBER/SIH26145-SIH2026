# PyInstaller spec -- single-file StealthTap desktop app.
#   Windows:  pyinstaller packaging/stealthtap.spec --noconfirm     ->  dist/stealthtap.exe
#   Linux  :  same command on a Linux host                          ->  dist/stealthtap
# Prerequisite: the dashboard built with a same-origin API base into build/ui:
#   (cd dashboard-app && VITE_API_BASE= VITE_LIVE_API_BASE= npx vite build --outDir ../build/ui --emptyOutDir)
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
IS_WIN = sys.platform.startswith("win")

datas = [
    (str(ROOT / "build" / "ui"), "ui"),
    (str(ROOT / "intel" / "ja4_threat_intel.json"), "intel"),
    (str(ROOT / "samples" / "simulated_attack_traffic.pcap"), "samples"),
]
for f in (ROOT / "models").iterdir():          # inference artefacts only -- no training CSVs
    if f.suffix in (".onnx", ".json"):
        datas.append((str(f), "models"))

hidden = (
    collect_submodules("scapy.layers")
    + ["scapy.arch.libpcap", "scapy.arch.linux", "scapy.arch.windows", "scapy.arch.common",
       "uvicorn.logging", "uvicorn.loops.auto", "uvicorn.protocols.http.auto",
       "uvicorn.protocols.websockets.auto", "uvicorn.lifespan.on", "multipart", "python_multipart",
       "onnxruntime", "redis"]
    + collect_submodules("src")
)
if IS_WIN:
    hidden += ["scapy.arch.windows.native"]

excludes = ["xgboost", "sklearn", "scipy", "pandas", "matplotlib", "tkinter", "torch",
            "IPython", "notebook", "pytest", "onnxmltools", "skl2onnx", "asyncpg"]

a = Analysis([str(ROOT / "stealthtap_app.py")], pathex=[str(ROOT)], datas=datas,
             hiddenimports=hidden, excludes=excludes, noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [],
          name="stealthtap", console=True, upx=False, runtime_tmpdir=None,
          uac_admin=IS_WIN)   # Windows: prompt for elevation -- live capture needs it
