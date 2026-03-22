"""
CELL 19 — Full Export for PhishGuard API
=========================================
Add this cell to your Colab notebook AFTER Cell 18.
It saves ALL 5 models (not just the best) using joblib
so the local API server can load every classifier and
run the Decision Tree decision-path explainer.

UWS MSc IT with Data Analytics | B01821745
"""

# ─────────────────────────────────────────────────────────
#  CELL 19 — Full Export (all 5 models via joblib)
# ─────────────────────────────────────────────────────────
import joblib, json, os
import numpy as np

OUT_DIR = "/content"   # change to your Drive path if preferred, e.g. "/content/drive/MyDrive/PhishGuard"

# ── 1. Build safe results dict (no numpy arrays) ─────────
safe_results = {}
for name, res in results.items():
    safe_results[name] = {
        k: float(v) for k, v in res.items()
        if k in ("accuracy", "precision", "recall", "f1", "auc")
    }

# ── 2. Save ALL models + vectorizer via joblib ───────────
full_export = {
    "vectorizer":        vectorizer,
    "trained":           trained,            # dict of {name: fitted_model}
    "results":           safe_results,
    "cv_scores":         {k: v.tolist() for k, v in cv_scores.items()},
    "feature_names":     list(vectorizer.get_feature_names_out()),
    # Keep train/test arrays for SHAP LinearExplainer background
    "_fitted_X_train":   X_train,
    "_y_train":          y_train,
    "_X_test":           X_test,
    "_y_test":           y_test,
    "banner_id":         "B01821745",
}

joblib_path = os.path.join(OUT_DIR, "phishguard_model.joblib")
joblib.dump(full_export, joblib_path, compress=3)
print(f"✅ Saved: {joblib_path}")
print(f"   Models: {list(trained.keys())}")
print(f"   Features: {len(full_export['feature_names']):,}")

# ── 3. Save metrics JSON (used by /metrics endpoint) ─────
results_path = os.path.join(OUT_DIR, "model_results.json")
with open(results_path, "w") as f:
    json.dump(safe_results, f, indent=2)
print(f"✅ Saved: {results_path}")

# ── 4. Save merged dataset CSV (for re-training in API) ──
csv_path = os.path.join(OUT_DIR, "phishguard_dataset.csv")
df[["text", "label", "source"]].to_csv(csv_path, index=False)
print(f"✅ Saved: {csv_path}  ({len(df):,} rows)")

# ── 5. Decision Tree: print top-level rules ──────────────
from sklearn.tree import export_text
dt_model = trained["Decision Tree"]
feat_names = list(vectorizer.get_feature_names_out())
dt_text = export_text(dt_model, feature_names=feat_names, max_depth=4,
                      spacing=3, decimals=4, show_weights=True)
print("\n── Decision Tree Top-4 Levels ──")
print(dt_text[:3000])   # truncated for readability
print(f"\nTree depth: {dt_model.get_depth()}  |  Leaves: {dt_model.get_n_leaves()}")

# ── 6. Download files ─────────────────────────────────────
try:
    from google.colab import files
    files.download(joblib_path)
    files.download(results_path)
    files.download(csv_path)
    print("\n📥 Downloads started — place all 3 files next to api_server.py")
except ImportError:
    print(f"\n📁 Files saved in {OUT_DIR} — download manually")

print("\n" + "="*55)
print("  Place these files next to api_server.py:")
print("  • phishguard_model.joblib  ← main model file")
print("  • model_results.json       ← metrics")
print("  • phishguard_dataset.csv   ← optional re-train")
print("  Then run:  python api_server.py")
print("  API auto-loads joblib on startup — no demo training needed.")
print("="*55)
