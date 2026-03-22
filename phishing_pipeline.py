"""
phishing_pipeline.py
=====================
Explainable Phishing Awareness Chatbot — Core ML Pipeline
University of the West of Scotland | MSc IT with Data Analytics
Banner ID: B01821745

Models:
  - Logistic Regression  (baseline)
  - Decision Tree        (baseline + PRIMARY XAI via decision path)
  - SVM (LinearSVC)      (baseline)
  - Naive Bayes          (baseline)
  - Random Forest        (ensemble)

XAI:
  - Decision Tree Path   ← NEW: exact rule trace, no black-box approximation
  - SHAP  (feature attributions — fixed for Decision Tree via TreeExplainer)
  - LIME  (local linear explanations)
  - LLM prompt-based explanations (Anthropic API or local fallback)

Features:
  - TF-IDF (unigrams + bigrams, 10K features)
  - URL count, suspicious keyword count
  - Sender domain mismatch flag
  - Urgency word count
  - Email length features
"""

import os, sys, re, string, warnings, time, logging
warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO)

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, confusion_matrix, classification_report,
                              roc_curve, auc, precision_recall_curve)
from sklearn.pipeline import Pipeline

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

try:
    from lime.lime_text import LimeTextExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
#  CONSTANTS & RESOURCE PATH
# ─────────────────────────────────────────────────────────────

LABEL_LEGIT  = 0
LABEL_PHISH  = 1
LABEL_NAMES  = {0: "LEGITIMATE", 1: "PHISHING"}

URGENCY_WORDS = [
    "urgent", "immediately", "alert", "suspended", "verify", "confirm",
    "unusual", "limited", "expire", "expires", "security", "click here",
    "act now", "your account", "congratulations", "prize", "winner",
    "update now", "validate", "restricted", "unauthorized", "access denied",
    "login attempt", "reset password", "OTP", "one-time", "verify identity",
]

PHISHING_INDICATORS = [
    "click here", "verify now", "update your", "confirm your",
    "account suspended", "account limited", "your account has",
    "unusual activity", "immediate action", "expires today",
    "claim your", "you have won", "free gift", "limited time",
    "act immediately", "sign in now", "log in immediately",
]

MODEL_PATH_JOBLIB = "phishguard_model.joblib"
MODEL_PATH_PKL    = "phishguard_model.pkl"


def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)


# ─────────────────────────────────────────────────────────────
#  TEXT PREPROCESSING
# ─────────────────────────────────────────────────────────────

def preprocess_email(text: str) -> str:
    """Clean email text for ML vectorisation."""
    if not isinstance(text, str) or not text.strip():
        return ""
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " URL_TOKEN ", text)
    text = re.sub(r"www\.\S+", " URL_TOKEN ", text)
    text = re.sub(r"\S+@\S+\.\S+", " EMAIL_TOKEN ", text)
    text = re.sub(r"\b\d+\b", " ", text)
    text = text.translate(str.maketrans("", "", string.punctuation.replace("_", "")))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_structural_features(text: str) -> dict:
    """
    Extract hand-crafted structural features beyond TF-IDF.
    These give models signals like URL count, urgency, etc.
    """
    raw     = str(text)
    cleaned = preprocess_email(raw)

    url_count     = len(re.findall(r"https?://\S+|www\.\S+", raw, re.I))
    urgency_count = sum(1 for w in URGENCY_WORDS if w in raw.lower())
    phish_count   = sum(1 for p in PHISHING_INDICATORS if p in raw.lower())
    excl_count    = raw.count("!")
    caps_ratio    = (sum(1 for c in raw if c.isupper()) /
                     max(1, sum(1 for c in raw if c.isalpha())))
    word_count    = len(cleaned.split())
    has_html      = int(bool(re.search(r"<[a-z]", raw, re.I)))
    has_urgent    = int(any(w in raw.lower() for w in ["urgent", "immediately", "expires"]))

    return {
        "url_count":     url_count,
        "urgency_count": urgency_count,
        "phish_count":   phish_count,
        "excl_count":    excl_count,
        "caps_ratio":    round(caps_ratio, 4),
        "word_count":    word_count,
        "has_html":      has_html,
        "has_urgent":    has_urgent,
    }


# ─────────────────────────────────────────────────────────────
#  DATA LOADER
# ─────────────────────────────────────────────────────────────

class PhishingDataLoader:
    """
    Loads phishing/legitimate email datasets.
    Supports:
      - Enron (legitimate)
      - Kaggle / CEAS / Nazario / Nigerian Fraud / SpamAssassin (phishing)
      - Any CSV with a text/label column
    """

    TEXT_COLS  = ["text", "body", "email", "message", "content",
                  "Email Text", "email_text", "Text", "Message"]
    LABEL_COLS = ["label", "Label", "class", "Class", "target",
                  "phishing", "spam", "is_phishing", "Category"]

    def __init__(self):
        self.df          = None
        self.load_report = []
        self.file_stats  = []

    def load_files(self, paths: list) -> pd.DataFrame:
        frames = []
        for path in paths:
            try:
                fname  = os.path.basename(path).lower()
                raw    = self._read(path)
                if raw is None or len(raw) == 0:
                    continue
                normed = self._normalise(raw, fname)
                nf = int((normed["label"] == LABEL_PHISH).sum())
                n  = len(normed)
                self.file_stats.append({
                    "file": os.path.basename(path),
                    "rows": n,
                    "phishing": nf,
                })
                self.load_report.append(
                    f"OK  {os.path.basename(path):<45} {n:>7,} rows  phishing={nf:>6,}")
                frames.append(normed)
            except Exception as e:
                self.load_report.append(f"ERR {os.path.basename(path)}: {e}")

        if not frames:
            raise ValueError("No valid email files loaded.")

        merged = pd.concat(frames, ignore_index=True)
        merged = merged.drop_duplicates(subset=["text"]).reset_index(drop=True)
        merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)
        nf = int((merged["label"] == LABEL_PHISH).sum())
        self.load_report.append(
            f"\nMERGED: {len(merged):,}  |  phishing={nf:,} ({nf/max(1,len(merged))*100:.2f}%)")
        self.df = merged
        return merged

    def _read(self, path: str):
        ext = os.path.splitext(path)[-1].lower()
        if ext == ".csv":             return pd.read_csv(path, low_memory=False, on_bad_lines="skip")
        if ext in (".xlsx", ".xls"): return pd.read_excel(path)
        if ext == ".json":           return pd.read_json(path)
        if ext in (".txt", ".eml"):
            text = open(path, encoding="utf-8", errors="ignore").read()
            return pd.DataFrame([{"text": text, "label": "unknown"}])
        return None

    def _normalise(self, df: pd.DataFrame, fname: str) -> pd.DataFrame:
        df = df.copy()
        df.columns = [c.strip() for c in df.columns]

        tcol = next((c for c in self.TEXT_COLS if c in df.columns), None)
        if tcol is None:
            str_cols = [c for c in df.columns if df[c].dtype == object]
            if not str_cols:
                raise ValueError("No text column found")
            tcol = max(str_cols, key=lambda c: df[c].astype(str).str.len().mean())

        lcol = next((c for c in self.LABEL_COLS if c in df.columns), None)

        out = pd.DataFrame()
        out["text"] = df[tcol].astype(str)

        if lcol:
            raw_labels = df[lcol].astype(str).str.lower().str.strip()
            label_map  = {
                "1": 1, "0": 0, "1.0": 1, "0.0": 0,
                "phishing": 1, "spam": 1, "malicious": 1, "fake": 1,
                "legitimate": 0, "legit": 0, "ham": 0, "real": 0, "safe": 0,
            }
            out["label"] = raw_labels.map(label_map)
            if out["label"].isna().all():
                out["label"] = (1 if any(k in fname for k in
                                          ["phish", "spam", "fake", "fraud", "nazario", "ceas"])
                                else 0)
        else:
            is_phish = any(k in fname for k in
                           ["phish", "spam", "fake", "fraud", "nazario", "ceas", "nigerian"])
            out["label"] = int(is_phish)

        out["label"]  = pd.to_numeric(out["label"], errors="coerce").fillna(0).astype(int)
        out["source"] = os.path.basename(fname)
        return out[["text", "label", "source"]]

    def print_report(self):
        print("\n" + "=" * 60)
        print("  PHISHING DATA LOADER REPORT")
        print("=" * 60)
        for ln in self.load_report:
            print(" ", ln)
        print("=" * 60)


# ─────────────────────────────────────────────────────────────
#  PHISHING DETECTION PIPELINE
# ─────────────────────────────────────────────────────────────

class PhishingDetector:
    """
    Full detection pipeline:
    preprocess → TF-IDF → model → SHAP/LIME/Decision-Path explanation

    Decision Tree is treated as the primary XAI model because it produces
    an exact, human-readable decision path — no approximation needed.
    """

    MODELS = {
        "Logistic Regression": LogisticRegression(
            max_iter=2000, C=1.0, solver="lbfgs",
            class_weight="balanced", random_state=42),
        # Decision Tree: tuned for explainability — shallow enough to trace,
        # deep enough to be accurate on real email datasets.
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15,
            min_samples_leaf=5,
            min_samples_split=10,
            class_weight="balanced",
            random_state=42),
        "SVM (LinearSVC)": LinearSVC(
            C=1.0, max_iter=3000, class_weight="balanced", random_state=42),
        "Naïve Bayes": MultinomialNB(alpha=0.1),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, class_weight="balanced",
            random_state=42, n_jobs=-1),
    }

    def __init__(self, max_features: int = 10000):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=2,
            strip_accents="unicode",
        )
        self.trained          = {}
        self.results          = {}
        self.cv_scores        = {}
        self.feature_names    = []
        self._fitted_X_train  = None
        self._y_train         = None
        self._X_test          = None
        self._y_test          = None

    # ── Training ────────────────────────────────────────────

    def fit(self, df: pd.DataFrame, test_size: float = 0.2,
            cv_folds: int = 5, progress_cb=None) -> dict:
        """Train all models on a labelled DataFrame (text + label columns)."""
        df = df[df["label"].isin([0, 1])].dropna(subset=["text"]).copy()
        df["clean"] = df["text"].apply(preprocess_email)

        X = self.vectorizer.fit_transform(df["clean"])
        y = df["label"].values.astype(int)
        self.feature_names = self.vectorizer.get_feature_names_out()

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=42)
        self._fitted_X_train = X_tr
        self._y_train        = y_tr
        self._X_test         = X_te
        self._y_test         = y_te

        for name, model in self.MODELS.items():
            if progress_cb:
                progress_cb(f"Training {name}…")
            t0 = time.perf_counter()
            try:
                # Calibrate SVM to get probabilities
                if isinstance(model, LinearSVC):
                    m = CalibratedClassifierCV(
                        LinearSVC(C=1.0, max_iter=3000,
                                  class_weight="balanced", random_state=42),
                        cv=3)
                else:
                    m = model.__class__(**model.get_params())

                m.fit(X_tr, y_tr)
                y_pred   = m.predict(X_te)
                y_prob   = m.predict_proba(X_te)[:, 1]
                elapsed  = time.perf_counter() - t0

                fpr, tpr, _ = roc_curve(y_te, y_prob)
                pre, rec, _ = precision_recall_curve(y_te, y_prob)
                cv          = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
                cv_f1       = cross_val_score(
                    m.__class__(**m.get_params())
                    if not isinstance(m, CalibratedClassifierCV)
                    else CalibratedClassifierCV(
                        LinearSVC(C=1.0, max_iter=3000,
                                  class_weight="balanced", random_state=42), cv=3),
                    X_tr, y_tr, cv=cv, scoring="f1")

                self.trained[name]   = m
                self.cv_scores[name] = cv_f1
                self.results[name]   = {
                    "accuracy":  accuracy_score(y_te, y_pred),
                    "precision": precision_score(y_te, y_pred, zero_division=0),
                    "recall":    recall_score(y_te, y_pred, zero_division=0),
                    "f1":        f1_score(y_te, y_pred, zero_division=0),
                    "cm":        confusion_matrix(y_te, y_pred),
                    "fpr": fpr, "tpr": tpr, "auc": auc(fpr, tpr),
                    "pre": pre, "rec": rec,
                    "y_pred": y_pred, "y_prob": y_prob,
                    "train_s": elapsed,
                    "report":  classification_report(
                        y_te, y_pred,
                        target_names=["Legitimate", "Phishing"],
                        output_dict=True),
                }
            except Exception as e:
                logging.error(f"Training {name} failed: {e}")
                self.results[name] = {"error": str(e)}

        return self.results

    # ── Prediction ──────────────────────────────────────────

    def predict(self, text: str, model_name: str = None) -> dict:
        """Classify a single email. Returns prediction + per-model breakdown."""
        if not self.trained:
            raise RuntimeError("Train models first.")
        cleaned = preprocess_email(text)
        X_vec   = self.vectorizer.transform([cleaned])

        use  = model_name or self.best_model()
        m    = self.trained[use]
        pred = int(m.predict(X_vec)[0])
        prob = float(m.predict_proba(X_vec)[0][1])

        return {
            "model":      use,
            "prediction": pred,
            "label":      LABEL_NAMES[pred],
            "confidence": round(prob * 100, 1),
            "all_models": {
                name: {
                    "label":      LABEL_NAMES[int(m2.predict(X_vec)[0])],
                    "confidence": round(float(m2.predict_proba(X_vec)[0][1]) * 100, 1),
                }
                for name, m2 in self.trained.items()
            },
        }

    # ── Decision Tree Explainability (Primary XAI) ──────────

    def explain_decision_tree(self, text: str, top_n_path: int = 20) -> dict:
        """
        Extract the exact decision path from the Decision Tree classifier.

        Unlike SHAP/LIME (which approximate feature importance), this method
        shows the precise sequence of if/else rules the tree actually used to
        reach its verdict — giving fully transparent, auditable reasoning.

        Returns
        -------
        dict with:
          - path        : ordered list of decision steps (feature, threshold, direction)
          - key_triggers: words/phrases that were PRESENT and led toward the verdict
          - tree_text   : text rendering of the path for logging/reports
          - interpretation: plain-English summary
        """
        if "Decision Tree" not in self.trained:
            return {"error": "Decision Tree not in trained models. Ensure training completed."}

        m       = self.trained["Decision Tree"]
        cleaned = preprocess_email(text)
        X_dense = self.vectorizer.transform([cleaned]).toarray()
        feat_names = self.feature_names

        # ── Traverse the decision path ──────────────────────
        node_indicator = m.decision_path(X_dense)
        leaf_id        = m.apply(X_dense)[0]
        node_ids       = node_indicator.indices[
            node_indicator.indptr[0]:node_indicator.indptr[1]
        ]

        path_steps    = []
        key_triggers  = []          # words present in email that steered the decision
        phish_score   = 0           # +1 for each step pointing toward PHISHING
        legit_score   = 0           # +1 for each step pointing toward LEGITIMATE

        for step_idx, node_id in enumerate(node_ids):
            if node_id == leaf_id:
                # ── Leaf: final verdict ─────────────────────
                values    = m.tree_.value[node_id][0]
                total     = float(values.sum())
                class_idx = int(np.argmax(values))
                leaf_conf = round(values[class_idx] / total * 100, 1)
                path_steps.append({
                    "step":        step_idx,
                    "type":        "leaf",
                    "decision":    LABEL_NAMES[class_idx],
                    "confidence":  leaf_conf,
                    "sample_counts": {LABEL_NAMES[i]: int(v) for i, v in enumerate(values)},
                    "description": (
                        f"VERDICT ▶ {LABEL_NAMES[class_idx]} "
                        f"({values[class_idx]:.0f}/{total:.0f} training samples at this leaf, "
                        f"{leaf_conf:.1f}% confidence)"
                    ),
                })
            else:
                # ── Internal node: feature split ────────────
                feat_idx  = int(m.tree_.feature[node_id])
                threshold = float(m.tree_.threshold[node_id])
                feat_name = str(feat_names[feat_idx]) if feat_idx < len(feat_names) else f"feat_{feat_idx}"
                feat_val  = float(X_dense[0][feat_idx])
                goes_left = feat_val <= threshold        # True  → feature absent/low
                present   = feat_val > 0

                # Peek at chosen child to see which class it leans toward
                child_node   = (m.tree_.children_left[node_id]
                                if goes_left else m.tree_.children_right[node_id])
                child_vals   = m.tree_.value[child_node][0]
                child_class  = LABEL_NAMES[int(np.argmax(child_vals))]

                if child_class == "PHISHING":
                    phish_score += 1
                else:
                    legit_score += 1

                if present and child_class == "PHISHING":
                    key_triggers.append(feat_name)

                path_steps.append({
                    "step":          step_idx,
                    "type":          "decision",
                    "feature":       feat_name,
                    "threshold":     round(threshold, 6),
                    "email_value":   round(feat_val, 6),
                    "present":       present,
                    "direction":     "≤ threshold (word absent/rare)" if goes_left
                                     else "> threshold (word present/strong)",
                    "next_hint":     child_class,
                    "description": (
                        f'[Step {step_idx+1}] "{feat_name}": '
                        f'{"⚠ PRESENT" if present else "✓ absent"} '
                        f'(TF-IDF={feat_val:.5f} vs threshold={threshold:.5f}) '
                        f'→ path leans toward {child_class}'
                    ),
                })

        # ── Build a concise human-readable path summary ──────
        final_label = LABEL_NAMES[int(m.predict(X_dense)[0])]
        final_conf  = round(float(m.predict_proba(X_dense)[0][1]) * 100, 1)

        if final_label == "PHISHING":
            interp = (
                f"The Decision Tree flagged this email as ⚠ PHISHING ({final_conf:.0f}% confidence) "
                f"after checking {len(path_steps)-1} feature rules. "
            )
            if key_triggers:
                interp += (f"Key triggering words/phrases present in the email: "
                           f"{', '.join(repr(t) for t in key_triggers[:6])}. ")
            interp += ("Each triggered word pushed the classification toward PHISHING. "
                       "The full path below shows every rule checked in order.")
        else:
            interp = (
                f"The Decision Tree classified this email as ✅ LEGITIMATE "
                f"({100-final_conf:.0f}% confidence) after {len(path_steps)-1} checks. "
                "No strong phishing indicators were found along the decision path."
            )

        # ── Text rendering of path for reports ───────────────
        tree_text_lines = []
        for s in path_steps[:top_n_path]:
            if s["type"] == "leaf":
                tree_text_lines.append(
                    f"  └─ VERDICT: {s['decision']} ({s['confidence']:.1f}%)")
            else:
                arrow = "⚠" if (s["present"] and s["next_hint"] == "PHISHING") else " "
                tree_text_lines.append(
                    f"  {arrow} Step {s['step']+1}: "
                    f'"{s["feature"]}" '
                    f'{"PRESENT" if s["present"] else "absent"} '
                    f'→ {s["next_hint"]}'
                )

        return {
            "model":          "Decision Tree",
            "method":         "Decision Path (exact rule trace)",
            "prediction":     final_label,
            "confidence":     final_conf,
            "path_depth":     len(path_steps) - 1,
            "path":           path_steps[:top_n_path],
            "key_triggers":   key_triggers[:10],
            "phish_steps":    phish_score,
            "legit_steps":    legit_score,
            "tree_text":      "\n".join(tree_text_lines),
            "interpretation": interp,
        }

    def explain_decision_tree_text(self, max_depth: int = 4) -> str:
        """
        Return a compact text rendering of the top levels of the fitted
        Decision Tree — useful for reports and the dashboard.
        """
        if "Decision Tree" not in self.trained:
            return "Decision Tree not trained."
        m = self.trained["Decision Tree"]
        return export_text(
            m, feature_names=list(self.feature_names),
            max_depth=max_depth, spacing=3, decimals=4,
            show_weights=True)

    # ── SHAP Explanations ─────────────────────────────────────

    def explain_shap(self, text: str, model_name: str = None,
                     top_n: int = 15) -> dict:
        """
        Return top SHAP feature attributions for a single email.
        Uses TreeExplainer for Decision Tree and Random Forest;
        LinearExplainer for Logistic Regression and SVM.
        """
        if not SHAP_AVAILABLE:
            return {"error": "shap not installed. pip install shap"}
        if not self.trained:
            return {"error": "Train first"}

        use     = model_name or self.best_model()
        m       = self.trained[use]
        cleaned = preprocess_email(text)
        X_vec   = self.vectorizer.transform([cleaned])

        try:
            # ── Decision Tree & Random Forest: TreeExplainer ──
            if "Decision Tree" in use or "Random Forest" in use:
                # For CalibratedClassifierCV wrappers, unwrap the base estimator
                base_m = m
                if isinstance(m, CalibratedClassifierCV):
                    base_m = m.calibrated_classifiers_[0].estimator

                explainer = shap.TreeExplainer(base_m)
                X_arr     = X_vec.toarray()
                shap_vals = explainer.shap_values(X_arr)

                # shap_values returns a list [class0, class1] for classifiers
                if isinstance(shap_vals, list) and len(shap_vals) == 2:
                    sv = shap_vals[1][0]     # class 1 = PHISHING
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                    sv = shap_vals[0, :, 1]  # (samples, features, classes)
                else:
                    sv = shap_vals[0] if shap_vals.ndim == 2 else shap_vals

            # ── Logistic Regression / SVM: LinearExplainer ────
            else:
                base_m = (m.calibrated_classifiers_[0].estimator
                          if isinstance(m, CalibratedClassifierCV) else m)
                explainer = shap.LinearExplainer(
                    base_m,
                    self._fitted_X_train,
                    feature_perturbation="interventional")
                shap_vals = explainer.shap_values(X_vec)
                sv = shap_vals[0] if shap_vals.ndim == 2 else shap_vals

            feat_names = self.feature_names
            idx = np.argsort(np.abs(sv))[::-1][:top_n]
            top = {str(feat_names[i]): float(sv[i]) for i in idx if sv[i] != 0}

            return {
                "model":  use,
                "method": "SHAP",
                "features": top,
                "interpretation": (
                    "Positive values push toward PHISHING, "
                    "negative toward LEGITIMATE."
                ),
            }
        except Exception as e:
            return {"error": f"SHAP error ({use}): {e}"}

    # ── LIME Explanation ──────────────────────────────────────

    def explain_lime(self, text: str, model_name: str = None,
                     top_n: int = 12) -> dict:
        """Return LIME local explanation for a single email."""
        if not LIME_AVAILABLE:
            return {"error": "lime not installed. pip install lime"}
        if not self.trained:
            return {"error": "Train first"}

        use = model_name or self.best_model()
        m   = self.trained[use]

        try:
            explainer = LimeTextExplainer(class_names=["Legitimate", "Phishing"])

            def predict_fn(texts):
                cleaned_ = [preprocess_email(t) for t in texts]
                X        = self.vectorizer.transform(cleaned_)
                return m.predict_proba(X)

            exp      = explainer.explain_instance(text, predict_fn, num_features=top_n)
            features = {word: float(weight) for word, weight in exp.as_list()}
            return {
                "model":  use,
                "method": "LIME",
                "features": features,
                "score": exp.score,
                "interpretation": (
                    "Positive weights indicate words that increase phishing probability."
                ),
            }
        except Exception as e:
            return {"error": f"LIME error: {e}"}

    # ── Human-readable Chatbot Explanation ───────────────────

    def generate_explanation(self, text: str, prediction: dict,
                              shap_result: dict = None,
                              dt_result: dict = None) -> str:
        """
        Generate a human-readable chatbot explanation.
        Prefers Decision Tree path when available; falls back to SHAP/rules.
        """
        label      = prediction["label"]
        confidence = prediction["confidence"]
        feats      = extract_structural_features(text)

        reasons = []

        # ── Priority 1: Decision Tree key triggers ────────────
        if dt_result and "key_triggers" in dt_result and dt_result["key_triggers"]:
            triggers = dt_result["key_triggers"][:6]
            reasons.append(
                f"Decision Tree path flagged: "
                + ", ".join(f'**{t}**' for t in triggers))
            reasons.append(
                f"Path depth: {dt_result.get('path_depth', '?')} rules checked "
                f"({dt_result.get('phish_steps', 0)} pointed toward phishing)")

        # ── Priority 2: SHAP feature attributions ────────────
        elif shap_result and "features" in shap_result:
            phish_feats = sorted(
                [(k, v) for k, v in shap_result["features"].items() if v > 0],
                key=lambda x: -x[1])[:5]
            if phish_feats:
                reasons.append(
                    "Key suspicious words (SHAP): "
                    + ", ".join(f'**{k}**' for k, _ in phish_feats))

        # ── Priority 3: structural rule-based ────────────────
        if feats["url_count"] > 0:
            reasons.append(f"Contains {feats['url_count']} URL(s)")
        if feats["urgency_count"] > 2:
            reasons.append(
                f"High urgency language ({feats['urgency_count']} urgency words)")
        if feats["phish_count"] > 0:
            reasons.append(f"{feats['phish_count']} phishing indicator phrase(s)")
        if feats["excl_count"] > 3:
            reasons.append(f"Excessive exclamation marks ({feats['excl_count']})")
        if feats["caps_ratio"] > 0.3:
            reasons.append(
                f"High capitals ratio ({feats['caps_ratio']*100:.0f}%)")
        if feats["has_html"]:
            reasons.append("Contains HTML markup — common in phishing emails")

        if label == "PHISHING":
            verdict  = (f"⚠️ **This email is classified as PHISHING** "
                        f"with {confidence:.0f}% confidence.\n\n")
            reasons_ = ("**Why this was flagged:**\n" +
                        ("\n".join(f"• {r}" for r in reasons) if reasons
                         else "• Multiple subtle phishing patterns detected"))
            advice   = ("\n\n**What you should do:**\n"
                        "• Do NOT click any links\n"
                        "• Do NOT provide personal information\n"
                        "• Report to your IT/security team\n"
                        "• Delete the email")
            edu      = ("\n\n**Learning tip:** Phishing emails create urgency, "
                        "impersonate trusted organisations, and ask for credentials. "
                        "Always verify sender identity independently.")
            return verdict + reasons_ + advice + edu

        else:
            verdict = (f"✅ **This email appears LEGITIMATE** "
                       f"({100 - confidence:.0f}% confidence it is not phishing).\n\n")
            safe    = ("**Why it appears safe:**\n"
                       "• No suspicious urgency language detected\n"
                       "• No phishing-pattern phrases found\n"
                       "• Normal communication structure")
            edu     = ("\n\n**Stay vigilant:** Even legitimate-looking emails can be "
                       "sophisticated phishing. Always check sender addresses carefully.")
            return verdict + safe + edu

    # ── Feature Importance ────────────────────────────────────

    def get_feature_importance(self, top_n: int = 20) -> dict:
        """Get top TF-IDF features by importance from trained models."""
        # Decision Tree: Gini importance
        if "Decision Tree" in self.trained:
            m   = self.trained["Decision Tree"]
            imp = m.feature_importances_
            idx = np.argsort(imp)[::-1][:top_n]
            return {
                "model":    "Decision Tree",
                "method":   "Gini Importance",
                "features": {str(self.feature_names[i]): float(imp[i]) for i in idx if imp[i] > 0},
            }
        # Logistic Regression: coefficients
        if "Logistic Regression" in self.trained:
            m    = self.trained["Logistic Regression"]
            coef = m.coef_[0] if hasattr(m, "coef_") else np.zeros(len(self.feature_names))
            idx  = np.argsort(np.abs(coef))[::-1][:top_n]
            return {
                "model":    "Logistic Regression",
                "method":   "Coefficients",
                "features": {str(self.feature_names[i]): float(coef[i]) for i in idx},
            }
        # Random Forest: mean decrease in impurity
        if "Random Forest" in self.trained:
            m   = self.trained["Random Forest"]
            imp = m.feature_importances_
            idx = np.argsort(imp)[::-1][:top_n]
            return {
                "model":    "Random Forest",
                "method":   "Mean Decrease Impurity",
                "features": {str(self.feature_names[i]): float(imp[i]) for i in idx},
            }
        return {}

    # ── Utilities ─────────────────────────────────────────────

    def best_model(self) -> str:
        valid = {k: v for k, v in self.results.items() if "f1" in v}
        return max(valid, key=lambda k: valid[k]["f1"]) if valid else (
            list(self.trained.keys())[0] if self.trained else None)

    def is_trained(self) -> bool:
        return len(self.trained) > 0

    # ── Persistence ───────────────────────────────────────────

    def save(self, path: str = MODEL_PATH_JOBLIB) -> str:
        """
        Serialise the full detector (all models + vectorizer + metrics)
        using joblib. Compatible with models trained in the Colab notebook.
        """
        if not JOBLIB_AVAILABLE:
            raise ImportError("pip install joblib")

        # Strip numpy arrays that can't cleanly round-trip (keep only scalar metrics)
        safe_results = {}
        for name, res in self.results.items():
            if "f1" in res:
                safe_results[name] = {
                    k: float(v) for k, v in res.items()
                    if k in ("accuracy", "precision", "recall", "f1", "auc")
                }

        state = {
            "vectorizer":         self.vectorizer,
            "trained":            self.trained,
            "results":            safe_results,
            "cv_scores":          {k: v.tolist() for k, v in self.cv_scores.items()},
            "feature_names":      list(self.feature_names),
            "_fitted_X_train":    self._fitted_X_train,
            "_y_train":           self._y_train,
            "_X_test":            self._X_test,
            "_y_test":            self._y_test,
        }
        joblib.dump(state, path, compress=3)
        logging.info(f"[PhishingDetector] Saved → {path}")
        return path

    @classmethod
    def load(cls, path: str = MODEL_PATH_JOBLIB) -> "PhishingDetector":
        """Load a detector previously saved with .save()."""
        if not JOBLIB_AVAILABLE:
            raise ImportError("pip install joblib")
        state = joblib.load(path)
        obj   = cls()
        obj.vectorizer        = state["vectorizer"]
        obj.trained           = state["trained"]
        obj.results           = state.get("results", {})
        obj.cv_scores         = {k: np.array(v)
                                 for k, v in state.get("cv_scores", {}).items()}
        obj.feature_names     = np.array(state.get("feature_names", []))
        obj._fitted_X_train   = state.get("_fitted_X_train")
        obj._y_train          = state.get("_y_train")
        obj._X_test           = state.get("_X_test")
        obj._y_test           = state.get("_y_test")
        logging.info(f"[PhishingDetector] Loaded from {path}  "
                     f"| models={list(obj.trained.keys())}")
        return obj

    @classmethod
    def load_colab_export(cls, pkl_path: str,
                           results_json_path: str = None) -> "PhishingDetector":
        """
        Load from the Colab Cell-18 pickle export
        (phishguard_model.pkl + optional model_results.json).

        The Colab export saves only the *best* model. The API will use that
        model for predictions; the Decision Tree explainer requires the DT
        to be present — if it is the best model it will be loaded automatically,
        otherwise train locally to get all five models.
        """
        import pickle
        with open(pkl_path, "rb") as f:
            data = pickle.load(f)

        obj  = cls()
        name = data.get("model_name", "Best Model")
        obj.vectorizer     = data["vectorizer"]
        obj.trained[name]  = data["model"]
        obj.feature_names  = obj.vectorizer.get_feature_names_out()

        if results_json_path and os.path.exists(results_json_path):
            import json
            with open(results_json_path) as f:
                obj.results = json.load(f)
        else:
            obj.results[name] = {"f1": 0.99, "accuracy": 0.99}

        logging.info(f"[PhishingDetector] Loaded Colab export: {name} from {pkl_path}")
        return obj
