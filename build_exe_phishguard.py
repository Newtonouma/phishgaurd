"""
build_exe.py  —  PhishGuard Phishing Awareness Chatbot
=======================================================
SETUP:
  python -m venv phish_env
  phish_env\\Scripts\\activate
  pip install scikit-learn==1.4.2 pandas==2.1.4 numpy==1.26.4
  pip install matplotlib==3.8.4 shap lime flask flask-cors
  pip install openpyxl pyinstaller==6.6.0

BUILD:
  python build_exe.py

OUTPUT:
  dist\\PhishGuard_UWS.exe

UWS MSc IT with Data Analytics | B01821745
"""
import subprocess, sys, os, glob

HERE = os.path.dirname(os.path.abspath(__file__))
sep  = os.pathsep

print("="*60)
print("  PhishGuard — Windows Build")
print("  B01821745 | UWS MSc IT with Data Analytics")
print("="*60)

is_64 = sys.maxsize > 2**32
print(f"\nPython: {sys.version.split()[0]}  ({'64-bit ✅' if is_64 else '32-bit ❌'})")
if not is_64:
    print("ERROR: Need 64-bit Python"); sys.exit(1)

for f in ["app.py","phishing_pipeline.py"]:
    if not os.path.exists(os.path.join(HERE,f)):
        print(f"MISSING: {f}"); sys.exit(1)

data_files = glob.glob(os.path.join(HERE,"*.csv"))
data_args  = [f"--add-data={fp}{sep}." for fp in data_files]
print(f"Bundling {len(data_files)} data file(s)")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile", "--windowed",
    "--name", "PhishGuard_UWS", "--clean",
    f"--add-data=phishing_pipeline.py{sep}.",
] + data_args + [
    "--hidden-import=phishing_pipeline",
    "--hidden-import=sklearn.feature_extraction.text",
    "--hidden-import=sklearn.linear_model._logistic",
    "--hidden-import=sklearn.tree._classes",
    "--hidden-import=sklearn.svm._classes",
    "--hidden-import=sklearn.naive_bayes",
    "--hidden-import=sklearn.ensemble._forest",
    "--hidden-import=sklearn.calibration",
    "--hidden-import=sklearn.model_selection._split",
    "--hidden-import=sklearn.metrics._classification",
    "--hidden-import=sklearn.metrics._ranking",
    "--hidden-import=sklearn.utils._cython_blas",
    "--hidden-import=sklearn.neighbors._partition_nodes",
    "--hidden-import=sklearn.tree._utils",
    "--hidden-import=matplotlib.backends.backend_tkagg",
    "--hidden-import=matplotlib.backends._backend_tk",
    "--hidden-import=matplotlib.backends.backend_agg",
    "--collect-all=matplotlib",
    "--collect-all=sklearn",
    "app.py",
]

print("\nBuilding…\n")
result = subprocess.run(cmd, cwd=HERE)

if result.returncode == 0:
    exe = os.path.join(HERE,"dist","PhishGuard_UWS.exe")
    sz  = os.path.getsize(exe)/1e6 if os.path.exists(exe) else 0
    print(f"\n{'='*60}")
    print(f"  ✅ BUILD SUCCESSFUL")
    print(f"  dist\\PhishGuard_UWS.exe  ({sz:.0f} MB)")
    print(f"{'='*60}")
    print("\nNote: For Gmail extension, see the extension/ folder.")
    print("  1. Open Chrome → chrome://extensions")
    print("  2. Enable Developer Mode")
    print("  3. Load Unpacked → select extension/ folder")
    print("  4. Run: python api_server.py  (for extension to call)")
else:
    print(f"\n{'='*60}\n  ❌ BUILD FAILED\n{'='*60}")
    sys.exit(1)
