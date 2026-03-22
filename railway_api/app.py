"""
api_server.py  â€”  PhishGuard Flask API
========================================
Bridges the Gmail browser extension and the ML pipeline.
Serves predictions and explanations as JSON.

Startup priority:
  1. Load  phishguard_model.joblib  (saved by api /model/save or notebook full export)
  2. Load  phishguard_model.pkl     (exported from Colab Cell-18 / Cell-19)
  3. Wait for uploaded training data via /train
     (demo fallback remains available via /train/fallback)

Run:
    pip install flask flask-cors joblib
    python api_server.py

Endpoints:
    GET  /health              â€” status + trained flag + loaded models
    GET  /data/status         â€” uploaded dataset status
    POST /data/upload         â€” upload CSV/XLSX/JSON/TXT/EML dataset files
    POST /data/clear          â€” clear uploaded dataset from memory
    POST /predict             â€” classify email (includes Decision Tree path)
    POST /explain/shap        â€” SHAP explanation
    POST /explain/lime        â€” LIME explanation
    POST /explain/tree        â€” Decision Tree exact path (NEW)
    GET  /explain/tree/global â€” Top-level Decision Tree rules (NEW)
    GET  /metrics             â€” model performance metrics
    GET  /feature_importance  â€” top features from best model
    POST /train               â€” re-train with supplied data
    POST /train/fallback      â€” explicit demo fallback training
    POST /model/save          â€” persist current model to disk
    GET  /dashboard           â€” HTML stub (full app = python app.py)

UWS MSc IT with Data Analytics | B01821745
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
import os, sys, threading, logging, tempfile
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishing_pipeline import (PhishingDetector, PhishingDataLoader,
                                MODEL_PATH_JOBLIB, MODEL_PATH_PKL)

app = Flask(__name__)
CORS(app)   # Allow extension to call from mail.google.com
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "350"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# â”€â”€ Global state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
detector = PhishingDetector(max_features=10000)
_trained      = False
_model_source = "awaiting_upload"  # "joblib" | "colab_pkl" | "dataset_upload" | "api_upload" | "demo_fallback" | "awaiting_upload"
_uploaded_df  = None
_upload_info  = {
    "loaded": False,
    "rows": 0,
    "phishing": 0,
    "legitimate": 0,
    "files": [],
}


# â”€â”€ Startup: load or train â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _startup():
    """
    Called once in a background thread.
    Priority: joblib save â†’ Colab pkl export â†’ wait for uploaded training data.
    """
    global _trained, _model_source, detector

    # 1 â”€â”€ Try full joblib save (all 5 models) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # 2 â”€â”€ Try Colab pickle export (best model only) â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # 3 â”€â”€ No model files: require uploaded training data â”€â”€â”€â”€â”€
    _trained = False
    _model_source = "awaiting_upload"
    logging.warning(
        "No model file found. Upload labelled emails to /train before predictions. "
        "Use /train/fallback only as a temporary demo fallback."
    )


def _demo_train():
    """Train on built-in demo data as an explicit fallback."""
    global _trained, _model_source
    import pandas as pd, random
    logging.info("Training on demo fallback dataâ€¦")

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
        "Congratulations! You WON Â£5000! Claim NOW before expiry.",
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
    _model_source = "demo_fallback"
    logging.info(f"Demo fallback training complete  |  best={detector.best_model()}")


threading.Thread(target=_startup, daemon=True).start()


# â”€â”€ Helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _require_trained():
    if not _trained:
        return jsonify({
            "error": (
                "Models are not trained yet. Upload labelled emails to POST /train. "
                "Preferred flow: POST /data/upload then POST /train. "
                "Optional fallback: POST /train/fallback."
            )
        }), 503
    return None


ALLOWED_UPLOAD_EXTS = {".csv", ".xlsx", ".xls", ".json", ".txt", ".eml"}


def _set_uploaded_dataset(df, file_names):
    global _uploaded_df, _upload_info
    _uploaded_df = df.copy()
    n = len(df)
    phish = int((df["label"] == 1).sum()) if "label" in df.columns else 0
    _upload_info = {
        "loaded": True,
        "rows": n,
        "phishing": phish,
        "legitimate": max(0, n - phish),
        "files": list(file_names),
    }


def _clear_uploaded_dataset():
    global _uploaded_df, _upload_info
    _uploaded_df = None
    _upload_info = {
        "loaded": False,
        "rows": 0,
        "phishing": 0,
        "legitimate": 0,
        "files": [],
    }


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(_err):
    return jsonify({
        "error": f"Upload too large. Max allowed size is {MAX_UPLOAD_MB} MB."
    }), 413


# â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/health")
def health():
    return jsonify({
        "status":       "ok",
        "trained":      _trained,
        "model_source": _model_source,
        "best_model":   detector.best_model() if _trained else None,
        "models":       list(detector.trained.keys()) if _trained else [],
        "dataset_loaded": _upload_info["loaded"],
        "dataset_rows": _upload_info["rows"],
        "banner_id":    "B01821745",
    })


@app.route("/data/status")
def data_status():
    return jsonify(_upload_info)


@app.route("/data/upload", methods=["POST"])
def data_upload():
    """
    Upload one or more dataset files and keep merged data in memory.
    Accepted extensions: CSV, XLSX, XLS, JSON, TXT, EML.
    """
    content_len = request.content_length or 0
    if content_len:
        logging.info(f"/data/upload request size: {content_len / (1024 * 1024):.2f} MB")
    if content_len and content_len > app.config["MAX_CONTENT_LENGTH"]:
        raise RequestEntityTooLarge()

    files = request.files.getlist("files")
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"error": "No files uploaded. Use multipart/form-data with 'files'."}), 400

    loader = PhishingDataLoader()
    tmp_paths = []
    kept_names = []
    try:
        for f in files:
            if not f or not f.filename:
                continue
            name = secure_filename(f.filename)
            ext = os.path.splitext(name)[1].lower()
            if ext not in ALLOWED_UPLOAD_EXTS:
                return jsonify({
                    "error": f"Unsupported file type for {name}. "
                             f"Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTS))}"
                }), 400

            t = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
            f.save(t.name)
            t.close()
            tmp_paths.append(t.name)
            kept_names.append(name)

        if not tmp_paths:
            return jsonify({"error": "No valid files uploaded."}), 400

        df = loader.load_files(tmp_paths)
        _set_uploaded_dataset(df, kept_names)
        return jsonify({
            "status": "uploaded",
            "dataset": _upload_info,
            "load_report": loader.load_report,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        for p in tmp_paths:
            try:
                os.unlink(p)
            except Exception:
                pass


@app.route("/data/clear", methods=["POST"])
def data_clear():
    _clear_uploaded_dataset()
    return jsonify({"status": "cleared", "dataset": _upload_info})


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
    This is the most transparent XAI method â€” no approximation.

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
    """Train with uploaded dataset (preferred) or JSON emails from request body."""
    global _trained, _model_source
    data = request.get_json(silent=True) or {}
    test_size = float(data.get("test_size", 0.2))
    cv_folds = int(data.get("cv_folds", 5))

    import pandas as pd
    train_source = None
    if "emails" in data:
        df = pd.DataFrame(data["emails"])
        train_source = "api_upload"
    elif _uploaded_df is not None and len(_uploaded_df) > 0:
        df = _uploaded_df.copy()
        train_source = "dataset_upload"
    else:
        return jsonify({
            "error": (
                "No training data available. Upload dataset files to POST /data/upload "
                "or send JSON body with emails: [{text, label}, ...]."
            )
        }), 400

    detector.fit(df, test_size=test_size, cv_folds=cv_folds)
    _trained      = True
    _model_source = train_source
    n = len(df)
    ph = int((df["label"] == 1).sum()) if "label" in df.columns else None
    return jsonify({
        "status": "trained",
        "best": detector.best_model(),
        "model_source": _model_source,
        "rows": n,
        "phishing": ph,
    })


@app.route("/train/fallback", methods=["POST"])
def train_fallback():
    """Explicitly train using built-in demo fallback emails."""
    _demo_train()
    return jsonify({
        "status": "trained",
        "best": detector.best_model(),
        "model_source": _model_source,
        "warning": "Demo fallback is active. Upload datasets to /train for production training.",
    })


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
    dt_depth = (detector.trained["Decision Tree"].get_depth()
                if dt_available else "-")
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PhishGuard Railway Dashboard</title>
  <style>
    :root {{
      --bg:#0f1b2d;
      --card:#1c2b42;
      --card2:#243653;
      --text:#e8eefc;
      --muted:#9fb1ce;
      --accent:#ff6b2b;
      --line:#344a6a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(1200px 500px at 10% -10%, #253a58 0%, var(--bg) 60%);
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 28px 18px 40px; }}
    h1 {{ margin: 0 0 10px; color: var(--accent); }}
    .sub {{ color: var(--muted); margin-bottom: 16px; }}
    .chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 18px; }}
    .chip {{
      background: var(--card2);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 12px;
    }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    .card {{
      background: linear-gradient(180deg, #20314c 0%, #1a2a41 100%);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
    }}
    .card h2 {{ margin: 0 0 10px; font-size: 16px; }}
    .hint {{ color: var(--muted); font-size: 12px; margin: 0 0 10px; }}
    input, textarea, button {{
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--line);
      font: inherit;
    }}
    input, textarea {{ background: #112036; color: var(--text); padding: 10px; }}
    textarea {{ min-height: 110px; resize: vertical; }}
    .row {{ display: flex; gap: 8px; margin-top: 8px; }}
    .row > * {{ flex: 1; }}
    button {{
      background: var(--accent);
      color: white;
      padding: 10px 12px;
      cursor: pointer;
      font-weight: 600;
    }}
    button.alt {{ background: #2d4261; }}
    button.warn {{ background: #7a4d1d; }}
    pre {{
      background: #101c2f;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
      color: #c7d7ef;
      overflow: auto;
      max-height: 220px;
      font-size: 12px;
      font-family: Consolas, Menlo, monospace;
    }}
    @media (max-width: 920px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>PhishGuard Railway Control Panel</h1>
    <div class="sub">Upload dataset files, train models, and run predictions directly from Railway.</div>

    <div class="chips">
      <div class="chip" id="chip-trained">{'Trained' if _trained else 'Awaiting Upload'}</div>
      <div class="chip">Source: <span id="chip-source">{_model_source}</span></div>
      <div class="chip">Best: <span id="chip-best">{detector.best_model() if _trained else '-'}</span></div>
      <div class="chip">DT Depth: <span id="chip-depth">{dt_depth}</span></div>
      <div class="chip">Dataset Rows: <span id="chip-rows">{_upload_info['rows']}</span></div>
    </div>

    <div class="grid">
      <section class="card">
        <h2>1) Load Dataset Files</h2>
        <p class="hint">Accepted: CSV, XLSX, XLS, JSON, TXT, EML. Upload first, then train.</p>
        <input id="files" type="file" multiple accept=".csv,.xlsx,.xls,.json,.txt,.eml" />
        <div class="row">
          <button onclick="uploadFiles()">Upload Datasets</button>
          <button class="alt" onclick="clearData()">Clear Uploaded Data</button>
        </div>
        <pre id="upload-log">Ready.</pre>
      </section>

      <section class="card">
        <h2>2) Train Models</h2>
        <p class="hint">Preferred: train from uploaded dataset. Fallback: train demo data explicitly.</p>
        <div class="row">
          <input id="test-size" type="number" step="0.01" min="0.05" max="0.5" value="0.2" />
          <input id="cv-folds" type="number" step="1" min="2" max="10" value="5" />
        </div>
        <div class="row">
          <button onclick="trainUploaded()">Train Uploaded Data</button>
          <button class="warn" onclick="trainFallback()">Train Demo Fallback</button>
        </div>
        <pre id="train-log">Waiting for dataset upload.</pre>
      </section>

      <section class="card">
        <h2>3) Quick Prediction</h2>
        <p class="hint">Use after training to verify end-to-end behavior.</p>
        <textarea id="predict-text" placeholder="Paste an email here..."></textarea>
        <div class="row">
          <button onclick="predictOne()">Run Prediction</button>
          <button class="alt" onclick="refreshStatus()">Refresh Status</button>
        </div>
        <pre id="predict-log">No prediction yet.</pre>
      </section>

      <section class="card">
        <h2>System Status</h2>
        <p class="hint">Live health and dataset status from API endpoints.</p>
        <pre id="status-log">Loading...</pre>
      </section>
    </div>
  </div>

  <script>
    async function apiGet(url) {{
      const r = await fetch(url);
      const t = await r.text();
      let j = {{}};
      try {{ j = JSON.parse(t); }} catch (e) {{ j = {{ raw: t }}; }}
      if (!r.ok) throw new Error(JSON.stringify(j));
      return j;
    }}

    async function apiPost(url, body, isForm) {{
      const init = {{ method: "POST" }};
      if (isForm) {{
        init.body = body;
      }} else {{
        init.headers = {{ "Content-Type": "application/json" }};
        init.body = JSON.stringify(body || {{}});
      }}
      const r = await fetch(url, init);
      const t = await r.text();
      let j = {{}};
      try {{ j = JSON.parse(t); }} catch (e) {{ j = {{ raw: t }}; }}
      if (!r.ok) throw new Error(JSON.stringify(j));
      return j;
    }}

    function put(id, data) {{
      const el = document.getElementById(id);
      el.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    }}

    async function refreshStatus() {{
      try {{
        const [health, data] = await Promise.all([apiGet('/health'), apiGet('/data/status')]);
        put('status-log', {{ health, data }});
        document.getElementById('chip-trained').textContent = health.trained ? 'Trained' : 'Awaiting Upload';
        document.getElementById('chip-source').textContent = health.model_source;
        document.getElementById('chip-best').textContent = health.best_model || '-';
        document.getElementById('chip-rows').textContent = data.rows || 0;
      }} catch (e) {{
        put('status-log', 'Status error: ' + e.message);
      }}
    }}

    async function uploadFiles() {{
      const input = document.getElementById('files');
      if (!input.files || input.files.length === 0) {{
        put('upload-log', 'Select one or more files first.');
        return;
      }}
      const fd = new FormData();
      for (const f of input.files) fd.append('files', f);
      put('upload-log', 'Uploading...');
      try {{
        const out = await apiPost('/data/upload', fd, true);
        put('upload-log', out);
        await refreshStatus();
      }} catch (e) {{
        put('upload-log', 'Upload failed: ' + e.message);
      }}
    }}

    async function clearData() {{
      put('upload-log', 'Clearing...');
      try {{
        const out = await apiPost('/data/clear', {{}}, false);
        put('upload-log', out);
        await refreshStatus();
      }} catch (e) {{
        put('upload-log', 'Clear failed: ' + e.message);
      }}
    }}

    async function trainUploaded() {{
      const testSize = parseFloat(document.getElementById('test-size').value || '0.2');
      const cvFolds = parseInt(document.getElementById('cv-folds').value || '5', 10);
      put('train-log', 'Training from uploaded dataset...');
      try {{
        const out = await apiPost('/train', {{ test_size: testSize, cv_folds: cvFolds }}, false);
        put('train-log', out);
        await refreshStatus();
      }} catch (e) {{
        put('train-log', 'Train failed: ' + e.message);
      }}
    }}

    async function trainFallback() {{
      put('train-log', 'Training demo fallback...');
      try {{
        const out = await apiPost('/train/fallback', {{}}, false);
        put('train-log', out);
        await refreshStatus();
      }} catch (e) {{
        put('train-log', 'Fallback failed: ' + e.message);
      }}
    }}

    async function predictOne() {{
      const text = document.getElementById('predict-text').value.trim();
      if (!text) {{
        put('predict-log', 'Paste email text first.');
        return;
      }}
      put('predict-log', 'Predicting...');
      try {{
        const out = await apiPost('/predict', {{ text }}, false);
        put('predict-log', out);
      }} catch (e) {{
        put('predict-log', 'Predict failed: ' + e.message);
      }}
    }}

    refreshStatus();
    setInterval(refreshStatus, 15000);
  </script>
</body>
</html>"""

if __name__ == "__main__":
    print("=" * 55)
    print("  PhishGuard API Server â€” B01821745 | UWS MSc IT")
    print("  http://localhost:5000")
    print("  Decision Tree XAI: /explain/tree")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False)

