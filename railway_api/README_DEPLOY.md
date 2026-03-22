Railway Deployment Folder
=========================

Deploy this folder as the Railway service root.

Included files
--------------
- app.py: Flask API entrypoint
- phishing_pipeline.py: ML pipeline used by the API
- requirements.txt: Python dependencies for Railway
- Procfile: Railway start command (Gunicorn)

Optional model files (for real trained predictions)
----------------------------------------------------
Place these files in this same folder before deploying:
- phishguard_model.joblib (preferred)
- or phishguard_model.pkl (fallback)
- model_results.json (optional metadata)

Without model files, the API auto-trains demo data on startup.

Railway steps
-------------
1. Push repo to GitHub.
2. In Railway, create a new project from this repo.
3. Set Root Directory to: railway_api
4. Deploy.
5. Verify:
   - GET /health
   - POST /predict
   - GET /dashboard

Notes
-----
- This folder is Linux-compatible (no pywin32 dependency).
- Use HTTPS Railway URL in extension content.js and popup.js.
