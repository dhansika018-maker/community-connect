# Community Connect — online deployment version

Flask app for resident issue reporting, manager workflow, private evidence photos, Google sign-in, exact-file duplicate detection, and optional AI-image screening.

## What this version does
- Google sign-in for personal Gmail and Google Workspace/college accounts, provided the Google OAuth consent screen is configured for the intended audience.
- Google identities must return a verified email. First-time Google users become residents by default.
- Manager access is granted only to emails explicitly listed in `MANAGER_EMAILS` (comma-separated). Do not let users choose their own role.
- Password login remains available for locally registered resident accounts. Demo accounts are seeded only outside `APP_ENV=production`.
- SHA-256 exact duplicate detection, actual image-byte validation, image dimension checks and metadata warnings.
- Optional Sightengine `genai,deepfake` screening. Scores are evidence for human review, not proof that a photo is fake. Provider errors are surfaced as manual-review flags.
- SQLite and uploaded images use configurable data paths; the included Render blueprint mounts persistent storage at `/var/data`.
- CSRF protection, secure production session cookies, upload size limit and authenticated/private photo access.

## Deploy to Render
1. Create a GitHub repository under an account you control and upload the contents of this folder. Do not commit `.env`, databases, API keys, or uploaded photos.
2. In Render, create a Blueprint from that repository and use `render.yaml`, or create a Web Service with build command `pip install -r requirements.txt` and start command `gunicorn app:app --workers 2 --threads 4 --timeout 90`.
3. This blueprint uses a paid Render Starter service because it attaches a persistent disk. Without persistent storage, the SQLite database and uploads can disappear on redeploy/restart. For larger/production use, move to managed PostgreSQL plus object storage.
4. In the Render service environment, set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `MANAGER_EMAILS` (e.g. the exact manager Google email address). Render generates `COMMUNITY_CONNECT_SECRET` from the blueprint.
5. Configure Google OAuth as described below, then redeploy.
6. Optional: set `SIGHTENGINE_API_USER` and `SIGHTENGINE_API_SECRET` to enable AI image screening. Without them, duplicate and file checks still work and each photo is flagged for manual review because AI screening is unavailable.
7. After deployment, test sign-in, resident issue creation, manager assignment, photo viewing permissions, repair submission, and resident confirm/reopen with two separate accounts.

## Google OAuth configuration (no passwords shared with us)
1. Open Google Cloud Console using an account you control: https://console.cloud.google.com/ . Create/select a project.
2. Configure Google Auth Platform / OAuth consent screen. For teammates using personal Gmail and college Workspace accounts, choose the audience that allows external users (often **External** for a student project), and publish/configure test users as Google currently requires. An unverified app may show a warning or have user limits until configured/verified.
3. Create an OAuth client of type **Web application**.
4. After Render gives your service a URL, add its origin to Authorized JavaScript origins if requested, and add this exact redirect URI to Authorized redirect URIs:
   `https://YOUR-RENDER-SERVICE.onrender.com/auth/google/callback`
5. Copy the OAuth Client ID and Client Secret into Render's environment variables. Never put the secret in source code or share it in chat.
6. Add the exact Google email(s) for the project manager(s) to `MANAGER_EMAILS`. Every other Google account is a resident.

Google docs: https://developers.google.com/identity/protocols/oauth2/web-server
Render Flask docs: https://render.com/docs/deploy-flask
Render environment variables: https://render.com/docs/configure-environment-variables
Render persistent disks: https://render.com/docs/disks

## AI photo screening
The app calls Sightengine's `genai,deepfake` models when API credentials are configured. Create your own account, check its current terms, pricing and usage limits, and put the API user/secret in Render environment variables. A score is probabilistic; it can miss manipulated images and can flag legitimate photos. Managers should review the original context and never reject a safety/maintenance report solely on the score. Exact duplicate detection is independent of AI detection and only detects byte-identical files (not resized/cropped versions).

Docs: https://sightengine.com/docs/ai-generated-image-detection

## Local run
Python 3.11+ recommended:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. Local demo credentials (development only):
- Resident: `resident@communityconnect.demo` / `Resident@123`
- Manager: `manager@communityconnect.demo` / `Manager@123`

## Important limitations
- This is a student project starter, not a security-audited production service.
- AI screening needs a separate provider account and configured API credentials; the model cannot conclusively prove authenticity.
- Password-based registration does not send email verification. Use Google sign-in for verified Google identities.
- There is no email notification delivery, password reset, college-directory verification, or real QR scanning yet.
- Keep manager account access limited. Back up the database and uploaded evidence.
