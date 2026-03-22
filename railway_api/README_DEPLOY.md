Railway Deployment Folder
=========================

Deploy this folder as the Railway service root.

Included files
--------------
- app.py: Flask API entrypoint
- phishing_pipeline.py: ML pipeline used by the API
- requirements.txt: Python dependencies for Railway
- Procfile: Railway start command (Gunicorn)
- .python-version: pins Python runtime to 3.12
- nixpacks.toml: Railway/Nixpacks runtime pin

Optional model files (for real trained predictions)
----------------------------------------------------
Place these files in this same folder before deploying:
- phishguard_model.joblib (preferred)
- or phishguard_model.pkl (fallback)
- model_results.json (optional metadata)

Without model files, the API starts in `awaiting_upload` mode and requires
uploaded labelled emails via `POST /train`.
Demo data remains available only as an explicit fallback via `POST /train/fallback`.

Railway steps
-------------
1. Push repo to GitHub.
2. In Railway, create a new project from this repo.
3. Set Root Directory to: railway_api
4. Deploy.
5. Verify:
   - GET /health
   - POST /data/upload (multipart with one or more files as `files`)
   - GET /data/status
   - POST /train
   - POST /predict
   - GET /dashboard

Dashboard data loading workflow
-------------------------------
1. Open `/dashboard`.
2. Upload one or more dataset files.
3. Click **Train Uploaded Data**.
4. Run a quick prediction to confirm end-to-end behavior.
5. Use **Train Demo Fallback** only when no dataset is available.

Notes
-----
- This folder is Linux-compatible (no pywin32 dependency).
- Use HTTPS Railway URL in extension content.js and popup.js.
- If Railway fails with "mise ... python@... 404", re-check that Root Directory is set to railway_api so these runtime pin files are used.
- This service is configured for long uploads/training (`gunicorn --timeout 1200`).
- Adjust upload cap with env var `MAX_UPLOAD_MB` (default `350`).
