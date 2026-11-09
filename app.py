import os, hashlib, secrets, io, json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError
import requests
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.environ.get("COMMUNITY_CONNECT_DATA_DIR", APP_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "community_connect.db")
UPLOAD_DIR = os.environ.get("COMMUNITY_CONNECT_UPLOAD_DIR", os.path.join(DATA_DIR, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
production = os.environ.get("APP_ENV", "development").lower() == "production"
secret_key = os.environ.get("COMMUNITY_CONNECT_SECRET")
if production and not secret_key:
    raise RuntimeError("Set COMMUNITY_CONNECT_SECRET in production before starting the app.")
app.secret_key = secret_key or secrets.token_hex(32)
app.config.update(
    APP_ENV=os.environ.get("APP_ENV", "development"),
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", ""),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=production,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)
CSRFProtect(app)
oauth = OAuth(app)
if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google", client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

def db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT,
            google_sub TEXT UNIQUE,
            role TEXT NOT NULL CHECK(role IN ('resident','manager')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_code TEXT NOT NULL UNIQUE,
            location TEXT NOT NULL,
            category TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            asset_id INTEGER NOT NULL REFERENCES assets(id),
            resident_id INTEGER NOT NULL REFERENCES users(id),
            safety INTEGER NOT NULL,
            affected INTEGER NOT NULL,
            waiting INTEGER NOT NULL,
            recurrence INTEGER NOT NULL,
            priority INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Reported',
            assigned_to TEXT,
            repair_note TEXT,
            before_photo TEXT,
            after_photo TEXT,
            photo_review TEXT,
            photo_flags TEXT,
            resident_verdict TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS issue_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            actor_id INTEGER REFERENCES users(id),
            event TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        user_cols = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
        if "google_sub" not in user_cols:
            c.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        # SQLite cannot drop NOT NULL from an existing password_hash column; fresh deployments use the nullable schema.
        assets = [
            ("Water Pump A", "CC-WP-001", "Basement pump room", "Water"),
            ("Streetlight 07", "CC-SL-007", "North entrance road", "Lighting"),
            ("Garbage Point B", "CC-GP-002", "Block B service lane", "Waste"),
            ("Lift 2", "CC-LF-002", "Block A, second lift", "Lift"),
            ("Road Section C", "CC-RD-003", "Near clubhouse", "Road")
        ]
        for a in assets:
            c.execute("INSERT OR IGNORE INTO assets(name,asset_code,location,category) VALUES(?,?,?,?)", a)
        # Demo logins for presentation only. Replace these passwords before any real deployment.
        demos = [] if production else [
            ("Demo Resident", "resident@communityconnect.demo", "Resident@123", "resident"),
            ("Demo Manager", "manager@communityconnect.demo", "Manager@123", "manager")
        ]
        for name, email, password, role in demos:
            c.execute("INSERT OR IGNORE INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                      (name, email, generate_password_hash(password), role, now()))
        # Seed illustrative records only when no issue records exist.
        if c.execute("SELECT COUNT(*) FROM issues").fetchone()[0] == 0:
            resident = c.execute("SELECT id FROM users WHERE email=?", ("resident@communityconnect.demo",)).fetchone()
            pump = c.execute("SELECT id FROM assets WHERE asset_code='CC-WP-001'").fetchone()
            if resident and pump:
                t = now()
                c.execute("""INSERT INTO issues(title,description,asset_id,resident_id,safety,affected,waiting,recurrence,priority,status,assigned_to,created_at,updated_at)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          ("Water leakage near pump", "Water pooling beside the pump room entrance.", pump["id"], resident["id"], 3, 4, 3, 4, 73, "Assigned", "Maintenance Team A", t, t))

def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    with db() as c:
        return c.execute("SELECT id,name,email,role FROM users WHERE id=?", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def role_required(role):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if u["role"] != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def priority_score(safety, affected, waiting, recurrence):
    # Transparent weighted score: 35%, 25%, 20%, 20%, each input 0–5.
    return int(round(7*safety + 5*affected + 4*waiting + 4*recurrence))

def ai_photo_screen(data):
    """Optional Sightengine screening. Scores are signals for human review, not proof."""
    api_user = os.environ.get("SIGHTENGINE_API_USER")
    api_secret = os.environ.get("SIGHTENGINE_API_SECRET")
    if not api_user or not api_secret:
        return None, ["AI screening is not configured; duplicate and file-integrity checks still ran"]
    try:
        response = requests.post(
            "https://api.sightengine.com/1.0/check.json",
            data={"models": "genai,deepfake", "api_user": api_user, "api_secret": api_secret},
            files={"media": ("upload.jpg", data, "application/octet-stream")}, timeout=20
        )
        response.raise_for_status()
        result = response.json()
        if result.get("status") != "success":
            return None, ["AI screening service returned an inconclusive result"]
        kind = result.get("type") or {}
        score = kind.get("ai_generated")
        flags = []
        if isinstance(score, (int, float)):
            if score >= float(os.environ.get("AI_REVIEW_THRESHOLD", "0.65")):
                flags.append(f"AI detector review flag: {score:.0%} AI-generated likelihood (not proof)")
        # Preserve a generic flag if provider returns a deepfake signal in a future/schema variant.
        deepfake = kind.get("deepfake")
        if isinstance(deepfake, (int, float)) and deepfake >= 0.65:
            flags.append(f"Possible manipulated/deepfake content flagged for human review ({deepfake:.0%})")
        elif isinstance(deepfake, dict):
            vals = [v for v in deepfake.values() if isinstance(v, (int, float))]
            if vals and max(vals) >= 0.65:
                flags.append(f"Possible manipulated/deepfake content flagged for human review ({max(vals):.0%})")
        return score, flags
    except (requests.RequestException, ValueError, TypeError):
        app.logger.exception("AI image screening failed")
        return None, ["AI screening unavailable; photo requires manual review"]

def save_photo(file_obj, issue_id, kind):
    if not file_obj or not file_obj.filename:
        return None, ["No photo supplied"] if kind == "after" else []
    original = secure_filename(file_obj.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_EXTENSIONS:
        return None, ["Unsupported file type; use JPG, PNG, or WEBP"]
    data = file_obj.read()
    if not data:
        return None, ["Empty file"]
    digest = hashlib.sha256(data).hexdigest()
    flags = []
    # Validate actual image bytes, not only the filename.
    try:
        import io
        image = Image.open(io.BytesIO(data))
        image.verify()
        image = Image.open(io.BytesIO(data))
        width, height = image.size
        if width < 240 or height < 240:
            flags.append("Very low image resolution")
        if width > 10000 or height > 10000:
            return None, ["Image dimensions are too large"]
        exif = image.getexif()
        if not exif:
            flags.append("No EXIF metadata found (common for screenshots and many messaging apps too)")
        else:
            # Flag only for review; metadata can be missing or changed legitimately.
            dt = exif.get(306) or exif.get(36867)
            if dt:
                try:
                    photo_time = datetime.strptime(str(dt), "%Y:%m:%d %H:%M:%S")
                    if (datetime.now() - photo_time).total_seconds() > 60*60*24*365*5:
                        flags.append("Photo timestamp is more than 5 years old")
                except Exception:
                    flags.append("Photo timestamp could not be interpreted")
    except (UnidentifiedImageError, OSError, ValueError):
        return None, ["File is not a valid readable image"]
    _, ai_flags = ai_photo_screen(data)
    flags.extend(ai_flags)
    with db() as c:
        dup = c.execute("""SELECT id,before_photo,after_photo FROM issues
                            WHERE before_photo IS NOT NULL OR after_photo IS NOT NULL""").fetchall()
        for row in dup:
            for path in (row["before_photo"], row["after_photo"]):
                if path:
                    try:
                        existing_path = os.path.join(UPLOAD_DIR, os.path.basename(path))
                        if os.path.exists(existing_path):
                            with open(existing_path, "rb") as f:
                                if hashlib.sha256(f.read()).hexdigest() == digest:
                                    flags.append(f"Exact duplicate of an existing issue photo (issue #{row['id']})")
                                    break
                    except OSError:
                        pass
            if any("Exact duplicate" in f for f in flags):
                break
    filename = f"issue_{issue_id}_{kind}_{secrets.token_hex(5)}.{ext}"
    target = os.path.join(UPLOAD_DIR, filename)
    with open(target, "wb") as f:
        f.write(data)
    return "uploads/" + filename, flags

def event(issue_id, actor_id, message):
    with db() as c:
        c.execute("INSERT INTO issue_events(issue_id,actor_id,event,created_at) VALUES(?,?,?,?)",
                  (issue_id, actor_id, message, now()))

@app.context_processor
def inject_globals():
    return {"user": current_user(), "current_year": datetime.now().year}

@app.route("/")
def index():
    if current_user(): return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if production:
        flash("New accounts must use verified Google sign-in on the deployed service.", "info")
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or "@" not in email or len(password) < 10:
            flash("Enter your name, a valid email, and a password with at least 10 characters.", "danger")
            return render_template("register.html")
        try:
            with db() as c:
                c.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                          (name, email, generate_password_hash(password), "resident", now()))
            flash("Account created. You can now sign in. New registrations are resident accounts.", "success")
            return redirect(url_for("login"))
        except Exception:
            flash("That email may already be registered. Try signing in instead.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as c:
            row = c.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if row and row["password_hash"] and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session.permanent = True
            flash(f"Welcome back, {row['name']}.", "success")
            return redirect(url_for("dashboard"))
        flash("Email or password was not recognized.", "danger")
    return render_template("login.html")

@app.route("/auth/google")
def google_login():
    if oauth.create_client("google") is None:
        flash("Google sign-in is not configured yet. Use email/password until the deployment steps are completed.", "warning")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    if oauth.create_client("google") is None:
        abort(503)
    try:
        token = oauth.google.authorize_access_token()
        info = token.get("userinfo") or oauth.google.parse_id_token(token, nonce=None)
    except Exception:
        app.logger.exception("Google sign-in failed")
        flash("Google sign-in did not complete. Please try again.", "danger")
        return redirect(url_for("login"))
    email = (info.get("email") or "").strip().lower()
    google_sub = info.get("sub")
    if not email or not google_sub or info.get("email_verified") is not True:
        flash("Google did not provide a verified email address. Please try another account.", "danger")
        return redirect(url_for("login"))
    managers = {x.strip().lower() for x in os.environ.get("MANAGER_EMAILS", "").split(",") if x.strip()}
    role = "manager" if email in managers else "resident"
    name = info.get("name") or email.split("@")[0]
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE google_sub=? OR email=? COLLATE NOCASE", (google_sub, email)).fetchone()
        if row:
            # Do not silently link a Google identity to a pre-existing password account.
            if row["google_sub"] and row["google_sub"] != google_sub:
                flash("This email is linked to a different Google identity. Contact the project administrator.", "danger")
                return redirect(url_for("login"))
            if not row["google_sub"] and row["password_hash"]:
                flash("An account already exists for this email. Sign in with that account or ask the administrator to link it safely.", "danger")
                return redirect(url_for("login"))
            c.execute("UPDATE users SET google_sub=?,role=? WHERE id=?", (google_sub, role, row["id"]))
            uid = row["id"]
        else:
            cur = c.execute("INSERT INTO users(name,email,password_hash,google_sub,role,created_at) VALUES(?,?,?,?,?,?)",
                            (name, email, None, google_sub, role, now()))
            uid = cur.lastrowid
    session.clear()
    session["user_id"] = uid
    session.permanent = True
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("index"))

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    # Check the owning issue before serving private evidence.
    try:
        issue_id = int(filename.split("_", 2)[1])
    except (ValueError, IndexError):
        abort(404)
    u = current_user()
    with db() as c:
        issue = c.execute("SELECT resident_id FROM issues WHERE id=?", (issue_id,)).fetchone()
    if not issue or (u["role"] != "manager" and issue["resident_id"] != u["id"]):
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    with db() as c:
        assets = c.execute("SELECT * FROM assets ORDER BY name").fetchall()
        if u["role"] == "manager":
            issues = c.execute("""SELECT i.*, a.name AS asset_name, a.asset_code, u.name AS resident_name
                                  FROM issues i JOIN assets a ON a.id=i.asset_id JOIN users u ON u.id=i.resident_id
                                  ORDER BY CASE i.status WHEN 'Reported' THEN 0 WHEN 'Assigned' THEN 1 WHEN 'Repair submitted' THEN 2 ELSE 3 END, i.created_at DESC""").fetchall()
        else:
            issues = c.execute("""SELECT i.*, a.name AS asset_name, a.asset_code, u.name AS resident_name
                                  FROM issues i JOIN assets a ON a.id=i.asset_id JOIN users u ON u.id=i.resident_id
                                  WHERE i.resident_id=? ORDER BY i.created_at DESC""", (u["id"],)).fetchall()
    return render_template("dashboard.html", issues=issues, assets=assets)

@app.route("/report", methods=["GET", "POST"])
@login_required
@role_required("resident")
def report():
    with db() as c:
        assets = c.execute("SELECT * FROM assets ORDER BY name").fetchall()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        try:
            asset_id = int(request.form.get("asset_id"))
            safety = max(0, min(5, int(request.form.get("safety", 0))))
            affected = max(0, min(5, int(request.form.get("affected", 0))))
            waiting = max(0, min(5, int(request.form.get("waiting", 0))))
            recurrence = max(0, min(5, int(request.form.get("recurrence", 0))))
        except (TypeError, ValueError):
            flash("Please check the asset and priority values.", "danger")
            return render_template("report.html", assets=assets)
        if not title or not description:
            flash("Please add a short title and description.", "danger")
            return render_template("report.html", assets=assets)
        with db() as c:
            asset = c.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if not asset: abort(400)
            # recurrence is auto-influenced by same asset history; resident value is still shown transparently.
            prior = c.execute("SELECT COUNT(*) FROM issues WHERE asset_id=? AND status!='Resolved'", (asset_id,)).fetchone()[0]
            recurrence = max(recurrence, min(5, prior))
            score = priority_score(safety, affected, waiting, recurrence)
            t = now()
            cur = c.execute("""INSERT INTO issues(title,description,asset_id,resident_id,safety,affected,waiting,recurrence,priority,status,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,'Reported',?,?)""",
                            (title, description, asset_id, current_user()["id"], safety, affected, waiting, recurrence, score, t, t))
            issue_id = cur.lastrowid
        photo_path = None
        flags = []
        if request.files.get("before_photo") and request.files["before_photo"].filename:
            photo_path, flags = save_photo(request.files["before_photo"], issue_id, "before")
        review = "Review required" if flags else ("No automated flags" if photo_path else "No photo supplied")
        with db() as c:
            c.execute("UPDATE issues SET before_photo=?, photo_review=?, photo_flags=? WHERE id=?",
                      (photo_path, review, "; ".join(flags), issue_id))
        event(issue_id, current_user()["id"], "Issue reported")
        flash(f"Issue #{issue_id} created. Priority score: {score}/100.", "success")
        return redirect(url_for("issue_detail", issue_id=issue_id))
    return render_template("report.html", assets=assets)

@app.route("/issue/<int:issue_id>")
@login_required
def issue_detail(issue_id):
    u = current_user()
    with db() as c:
        issue = c.execute("""SELECT i.*, a.name AS asset_name, a.asset_code, a.location, u.name AS resident_name
                             FROM issues i JOIN assets a ON a.id=i.asset_id JOIN users u ON u.id=i.resident_id WHERE i.id=?""",
                          (issue_id,)).fetchone()
        if not issue: abort(404)
        if u["role"] != "manager" and issue["resident_id"] != u["id"]: abort(403)
        events = c.execute("SELECT e.*, u.name AS actor_name FROM issue_events e LEFT JOIN users u ON u.id=e.actor_id WHERE e.issue_id=? ORDER BY e.created_at DESC", (issue_id,)).fetchall()
    return render_template("issue_detail.html", issue=issue, events=events)

@app.route("/issue/<int:issue_id>/manage", methods=["POST"])
@login_required
@role_required("manager")
def manage_issue(issue_id):
    assigned = request.form.get("assigned_to", "").strip()
    status = request.form.get("status", "Reported")
    note = request.form.get("repair_note", "").strip()
    if status not in {"Reported", "Assigned", "Repair submitted", "Resolved", "Reopened"}: abort(400)
    with db() as c:
        issue = c.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
        if not issue: abort(404)
    after_path = issue["after_photo"]
    flags = []
    if request.files.get("after_photo") and request.files["after_photo"].filename:
        after_path, flags = save_photo(request.files["after_photo"], issue_id, "after")
    if status == "Repair submitted" and not after_path:
        flash("Upload a repair photo before submitting a repair for resident verification.", "danger")
        return redirect(url_for("issue_detail", issue_id=issue_id))
    review = "Review required" if flags else ("No automated flags" if after_path else issue["photo_review"])
    with db() as c:
        c.execute("""UPDATE issues SET assigned_to=?,status=?,repair_note=?,after_photo=?,photo_review=?,photo_flags=?,updated_at=? WHERE id=?""",
                  (assigned or None, status, note or None, after_path, review, "; ".join(flags) if flags else issue["photo_flags"], now(), issue_id))
    event(issue_id, current_user()["id"], f"Manager updated status to {status}" + (f"; assigned to {assigned}" if assigned else ""))
    flash("Issue updated.", "success")
    return redirect(url_for("issue_detail", issue_id=issue_id))

@app.route("/issue/<int:issue_id>/verdict", methods=["POST"])
@login_required
@role_required("resident")
def verdict(issue_id):
    decision = request.form.get("decision")
    if decision not in {"confirm", "reopen"}: abort(400)
    with db() as c:
        issue = c.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
        if not issue or issue["resident_id"] != current_user()["id"]: abort(403)
        if decision == "confirm":
            c.execute("UPDATE issues SET status='Resolved',resident_verdict='Confirmed by resident',updated_at=? WHERE id=?", (now(), issue_id))
            msg = "Resident confirmed resolution"
        else:
            c.execute("UPDATE issues SET status='Reopened',resident_verdict='Reopened by resident',updated_at=? WHERE id=?", (now(), issue_id))
            msg = "Resident reopened issue"
    event(issue_id, current_user()["id"], msg)
    flash("Your response has been saved.", "success")
    return redirect(url_for("issue_detail", issue_id=issue_id))

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to view or change this page."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="That page or issue could not be found."), 404

@app.errorhandler(413)
def too_large(e):
    flash("Upload is too large. The maximum upload size is 8 MB.", "danger")
    return redirect(request.referrer or url_for("dashboard"))

init_db()
if __name__ == "__main__":
    # Local-only development server. Do not expose this server directly to the internet.
    app.run(debug=False, host="127.0.0.1", port=5000)
