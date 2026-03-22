"""
api_server.py  —  PhishGuard Flask API
========================================
Bridges the Gmail browser extension and the ML pipeline.
Serves predictions and explanations as JSON.

Startup priority:
  1. Load  phishguard_model.joblib  (saved by api /model/save or notebook full export)
  2. Load  phishguard_model.pkl     (exported from Colab Cell-18 / Cell-19)
  3. Fall back to demo auto-training (no real datasets required)

Run:
    pip install flask flask-cors joblib
    python api_server.py

Endpoints:
    GET  /health              — status + trained flag + loaded models
    POST /predict             — classify email (includes Decision Tree path)
    POST /explain/shap        — SHAP explanation
    POST /explain/lime        — LIME explanation
    POST /explain/tree        — Decision Tree exact path (NEW)
    GET  /explain/tree/global — Top-level Decision Tree rules (NEW)
    GET  /metrics             — model performance metrics
    GET  /feature_importance  — top features from best model
    POST /train               — re-train with supplied data
    POST /model/save          — persist current model to disk
    GET  /dashboard           — HTML stub (full app = python app.py)

UWS MSc IT with Data Analytics | B01821745
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os, sys, threading, logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishing_pipeline import (PhishingDetector, PhishingDataLoader,
                                MODEL_PATH_JOBLIB, MODEL_PATH_PKL)

app = Flask(__name__)
CORS(app)   # Allow extension to call from mail.google.com

# ── Global state ──────────────────────────────────────────
detector = PhishingDetector(max_features=10000)
_trained      = False
_model_source = "none"       # "joblib" | "colab_pkl" | "demo"


# ── Startup: load or train ────────────────────────────────

def _startup():
    """
    Called once in a background thread.
    Priority: joblib save → Colab pkl export → demo training.
    """
    global _trained, _model_source, detector

    # 1 ── Try full joblib save (all 5 models) ───────────────
    if os.path.exists(MODEL_PATH_JOBLIB):
        try:
            logging.info(f"Loading pre-trained model: {MODEL_PATH_JOBLIB}")
            detector = PhishingDetector.load(MODEL_PATH_JOBLIB)
            _trained      = True
            _model_source = "joblib"
            logging.info(f"Loaded  |  best={detector.best_model()}")
            return
        except Exception as e:
            logging.warning(f"joblib load failed: {e}")

    # 2 ── Try Colab pickle export (best model only) ─────────
    if os.path.exists(MODEL_PATH_PKL):
        results_json = MODEL_PATH_PKL.replace(".pkl", "_results.json")
        try:
            logging.info(f"Loading Colab export: {MODEL_PATH_PKL}")
            detector = PhishingDetector.load_colab_export(
                MODEL_PATH_PKL,
                results_json if os.path.exists(results_json) else None)
            _trained      = True
            _model_source = "colab_pkl"
            logging.info(f"Loaded Colab export  |  models={list(detector.trained.keys())}")
            return
        except Exception as e:
            logging.warning(f"Colab pkl load failed: {e}")

    # 3 ── Fall back: demo training ───────────────────────────
    _demo_train()


def _demo_train():
    """Train on built-in demo data (no external datasets needed)."""
    global _trained, _model_source
    import pandas as pd, random
    logging.info("Auto-training on demo data…")

    legit = [
        "Dear team, please find attached the Q3 financial report for review.",
        "Hi Sarah, can we reschedule our call to Friday afternoon?",
        "Your order has been confirmed and will ship within 2 business days.",
        "Please submit your expense reports by end of day Friday.",
        "The system maintenance window is Sunday 2am-4am. Plan accordingly.",
        "Welcome to the team! Your onboarding documents are attached.",
        "Budget approval for Q4 has been granted. Please proceed.",
        "Meeting notes from yesterday are attached. Action items highlighted.",
        "Your leave request for December has been approved by HR.",
        "The project deadline has been extended to January 15th.",
        "Please review the attached proposal before Thursday's meeting.",
        "The client has approved the revised budget. We can proceed.",
    ] * 20
    phish = [
        "URGENT: Your account has been SUSPENDED! Click here IMMEDIATELY to verify.",
        "Congratulations! You WON £5000! Claim NOW before expiry.",
        "Your password EXPIRES TODAY. Reset immediately or lose access.",
        "SECURITY ALERT: Unusual login on your account! Verify NOW.",
        "Your PayPal account is LIMITED. Click here to restore access.",
        "HMRC NOTICE: You are owed a tax refund. Claim here immediately.",
        "Your Netflix subscription has EXPIRED. Update payment NOW.",
        "FINAL NOTICE: Your Amazon account will close in 24 hours!",
        "Your DHL parcel cannot be delivered. Pay customs fee NOW.",
        "Bank security alert: Your card has been compromised. Verify NOW.",
        "Your Microsoft account is at risk. Update your credentials immediately.",
        "Apple ID suspended due to suspicious activity. Verify now.",
    ] * 20

    texts  = legit + phish
    labels = [0] * len(legit) + [1] * len(phish)
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)

    df = pd.DataFrame({"text": list(texts), "label": list(labels), "source": "demo"})
    detector.fit(df, test_size=0.2, cv_folds=3)
    _trained      = True
    _model_source = "demo"
    logging.info(f"Demo training complete  |  best={detector.best_model()}")


threading.Thread(target=_startup, daemon=True).start()


# ── Helper ────────────────────────────────────────────────

def _require_trained():
    if not _trained:
        return jsonify({"error": "Models not yet trained. Retry in a few seconds."}), 503
    return None


# ── Routes ────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status":       "ok",
        "trained":      _trained,
        "model_source": _model_source,
        "best_model":   detector.best_model() if _trained else None,
        "models":       list(detector.trained.keys()) if _trained else [],
        "banner_id":    "B01821745",
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Classify an email.
    Response includes Decision Tree path when DT is trained,
    in addition to the standard SHAP-based explanation.
    """
    err = _require_trained()
    if err: return err

    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = str(data["text"])
    try:
        pred     = detector.predict(text, model_name=data.get("model"))
        shap_r   = detector.explain_shap(text)
        dt_r     = (detector.explain_decision_tree(text)
                    if "Decision Tree" in detector.trained else {})
        exp_text = detector.generate_explanation(text, pred, shap_r, dt_r)

        return jsonify({
            "label":            pred["label"],
            "prediction":       pred["prediction"],
            "confidence":       pred["confidence"],
            "model":            pred["model"],
            "all_models":       pred["all_models"],
            "explanation":      exp_text,
            "shap_features":    shap_r.get("features", {}),
            "decision_tree": {
                "available":    bool(dt_r and "path" in dt_r),
                "prediction":   dt_r.get("prediction"),
                "confidence":   dt_r.get("confidence"),
                "path_depth":   dt_r.get("path_depth"),
                "key_triggers": dt_r.get("key_triggers", []),
                "phish_steps":  dt_r.get("phish_steps"),
                "legit_steps":  dt_r.get("legit_steps"),
                "tree_text":    dt_r.get("tree_text", ""),
                "interpretation": dt_r.get("interpretation", ""),
            },
        })
    except Exception as e:
        logging.exception("predict error")
        return jsonify({"error": str(e)}), 500


@app.route("/explain/shap", methods=["POST"])
def explain_shap():
    err = _require_trained()
    if err: return err
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text"}), 400
    return jsonify(detector.explain_shap(data["text"],
                                         model_name=data.get("model")))


@app.route("/explain/lime", methods=["POST"])
def explain_lime():
    err = _require_trained()
    if err: return err
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text"}), 400
    return jsonify(detector.explain_lime(data["text"],
                                          model_name=data.get("model")))


@app.route("/explain/tree", methods=["POST"])
def explain_tree():
    """
    Decision Tree exact path explanation.
    Returns every rule checked on the path from root to leaf.
    This is the most transparent XAI method — no approximation.

    Body: { "text": "...", "top_n": 20 }
    """
    err = _require_trained()
    if err: return err

    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    if "Decision Tree" not in detector.trained:
        return jsonify({
            "error": "Decision Tree model not loaded. "
                     "Use the full joblib export (all 5 models) from the notebook."
        }), 422

    top_n  = int(data.get("top_n", 20))
    result = detector.explain_decision_tree(data["text"], top_n_path=top_n)
    return jsonify(result)


@app.route("/explain/tree/global")
def explain_tree_global():
    """
    Return a text rendering of the top levels of the fitted Decision Tree.
    Useful for reports: shows the globally most important split rules.
    """
    err = _require_trained()
    if err: return err

    if "Decision Tree" not in detector.trained:
        return jsonify({"error": "Decision Tree not loaded"}), 422

    max_depth = int(request.args.get("depth", 4))
    text      = detector.explain_decision_tree_text(max_depth=max_depth)
    fi        = detector.get_feature_importance()
    return jsonify({
        "tree_text":        text,
        "feature_importance": fi,
        "model_depth": detector.trained["Decision Tree"].get_depth(),
        "n_leaves":    detector.trained["Decision Tree"].get_n_leaves(),
    })


@app.route("/metrics")
def metrics():
    err = _require_trained()
    if err: return err
    out = {}
    for name, res in detector.results.items():
        if "f1" in res:
            out[name] = {k: res[k] for k in
                         ("accuracy", "precision", "recall", "f1", "auc")
                         if k in res}
    return jsonify({
        "models":       out,
        "best":         detector.best_model(),
        "model_source": _model_source,
    })


@app.route("/feature_importance")
def feature_importance():
    err = _require_trained()
    if err: return err
    return jsonify(detector.get_feature_importance(
        top_n=int(request.args.get("top_n", 20))))


@app.route("/train", methods=["POST"])
def train():
    """Re-train with data from the request body."""
    global _trained, _model_source
    data = request.get_json()
    if not data or "emails" not in data:
        return jsonify({"error": "Provide emails array: [{text, label}, ...]"}), 400
    import pandas as pd
    df = pd.DataFrame(data["emails"])
    detector.fit(df, test_size=0.2)
    _trained      = True
    _model_source = "api_upload"
    return jsonify({"status": "trained", "best": detector.best_model()})


@app.route("/model/save", methods=["POST"])
def model_save():
    """Persist the current detector to phishguard_model.joblib."""
    err = _require_trained()
    if err: return err
    data = request.get_json() or {}
    path = data.get("path", MODEL_PATH_JOBLIB)
    try:
        saved = detector.save(path)
        return jsonify({"status": "saved", "path": saved})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard")
def dashboard():
    dt_available = "Decision Tree" in detector.trained if _trained else False
    dt_depth     = (detector.trained["Decision Tree"].get_depth()
                    if dt_available else "—")
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>PhishGuard Dashboard</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background:#1A2332; color:white;
            text-align:center; padding:60px; }}
    h1   {{ color:#FF6B2B; }}
    .badge {{ background:#FF6B2B; padding:4px 12px; border-radius:20px;
              font-size:13px; margin:4px; display:inline-block; }}
    .info  {{ background:#243044; border-radius:10px; padding:20px;
              max-width:480px; margin:20px auto; text-align:left;
              font-size:13px; line-height:1.7; }}
    code   {{ color:#FF6B2B; }}
  </style>
</head>
<body>
  <h1>🛡 PhishGuard API</h1>
  <div>
    <span class="badge">{'✅ Trained' if _trained else '⏳ Training…'}</span>
    <span class="badge">Source: {_model_source}</span>
    <span class="badge">Best: {detector.best_model() if _trained else '—'}</span>
    {'<span class="badge">🌳 Decision Tree ✓</span>' if dt_available else ''}
  </div>
  <div class="info">
    <b>Available models:</b><br>
    {'<br>'.join(f'• {k}' for k in detector.trained) if _trained else '—'}
    <br><br>
    <b>Decision Tree depth:</b> {dt_depth} levels<br>
    <b>XAI endpoints:</b><br>
    • <code>POST /explain/tree</code> — exact decision path<br>
    • <code>POST /explain/shap</code> — SHAP attributions<br>
    • <code>POST /explain/lime</code> — LIME explanation<br>
    • <code>GET  /explain/tree/global</code> — top-level rules<br>
    <br>
    Launch <code>python app.py</code> for the full desktop dashboard.
  </div>
</body>
</html>"""


if __name__ == "__main__":
    print("=" * 55)
    print("  PhishGuard API Server — B01821745 | UWS MSc IT")
    print("  http://localhost:5000")
    print("  Decision Tree XAI: /explain/tree")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False)
