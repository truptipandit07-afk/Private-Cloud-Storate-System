"""Private Cloud Storage - Flask + SQLite. Optional Nextcloud (WebDAV) mirroring."""
import os, sqlite3, secrets, uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, send_from_directory, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.abspath(os.path.dirname(__file__))
STORAGE = os.path.join(BASE, "storage")
DB = os.path.join(BASE, "cloud.db")
QUOTA = 1024 ** 3  # 1 GB per user
os.makedirs(STORAGE, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY, owner INTEGER NOT NULL, name TEXT NOT NULL,
            stored TEXT NOT NULL, size INTEGER NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS shares(
            id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, token TEXT UNIQUE NOT NULL,
            expires TEXT);
        """)

# ---------- helpers ----------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("csrf") != session["csrf"]:
            abort(400, "Bad CSRF token")

@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_hex(16))
    return {"csrf": session["csrf"], "user": session.get("user")}

@app.template_filter("size")
def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def own_file(fid):
    f = db().execute("SELECT * FROM files WHERE id=? AND owner=?", (fid, session["uid"])).fetchone()
    if not f:
        abort(404)
    return f

def user_dir(uid):
    p = os.path.join(STORAGE, str(uid))
    os.makedirs(p, exist_ok=True)
    return p

def nextcloud_push(path, name):
    """Optional: mirror upload to Nextcloud via WebDAV when env vars are set."""
    url, usr, pwd = (os.environ.get(k) for k in ("NEXTCLOUD_URL", "NEXTCLOUD_USER", "NEXTCLOUD_PASS"))
    if not (url and usr and pwd):
        return
    try:
        import requests
        with open(path, "rb") as fh:
            requests.put(f"{url.rstrip('/')}/remote.php/dav/files/{usr}/{name}",
                         data=fh, auth=(usr, pwd), timeout=60)
    except Exception as e:
        app.logger.warning("Nextcloud sync failed: %s", e)

# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        if len(u) < 3 or len(p) < 8:
            flash("Username min 3 chars, password min 8 chars.")
        else:
            try:
                db().execute("INSERT INTO users(username,pw) VALUES(?,?)", (u, generate_password_hash(p)))
                db().commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already taken.")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        r = db().execute("SELECT * FROM users WHERE username=?", (request.form["username"].strip(),)).fetchone()
        if r and check_password_hash(r["pw"], request.form["password"]):
            session.clear()
            session.update(uid=r["id"], user=r["username"], csrf=secrets.token_hex(16))
            return redirect(url_for("index"))
        flash("Invalid credentials.")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- files ----------
@app.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()
    rows = db().execute("SELECT * FROM files WHERE owner=? AND name LIKE ? ORDER BY created DESC",
                        (session["uid"], f"%{q}%")).fetchall()
    shares = {}
    for s in db().execute("SELECT s.* FROM shares s JOIN files f ON f.id=s.file_id WHERE f.owner=?",
                          (session["uid"],)):
        shares.setdefault(s["file_id"], []).append(s)
    used = db().execute("SELECT COALESCE(SUM(size),0) FROM files WHERE owner=?", (session["uid"],)).fetchone()[0]
    return render_template("index.html", files=rows, shares=shares, used=used, quota=QUOTA, q=q)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    used = db().execute("SELECT COALESCE(SUM(size),0) FROM files WHERE owner=?", (session["uid"],)).fetchone()[0]
    for f in request.files.getlist("files"):
        name = secure_filename(f.filename or "")
        if not name:
            continue
        stored = uuid.uuid4().hex
        path = os.path.join(user_dir(session["uid"]), stored)
        f.save(path)
        size = os.path.getsize(path)
        if used + size > QUOTA:
            os.remove(path)
            flash(f"Quota exceeded, '{name}' skipped.")
            continue
        used += size
        db().execute("INSERT INTO files(owner,name,stored,size,created) VALUES(?,?,?,?,?)",
                     (session["uid"], name, stored, size, datetime.now().strftime("%Y-%m-%d %H:%M")))
        db().commit()
        nextcloud_push(path, name)
    return redirect(url_for("index"))

@app.route("/download/<int:fid>")
@login_required
def download(fid):
    f = own_file(fid)
    return send_from_directory(user_dir(session["uid"]), f["stored"], as_attachment=True, download_name=f["name"])

@app.route("/rename/<int:fid>", methods=["POST"])
@login_required
def rename(fid):
    own_file(fid)
    name = secure_filename(request.form["name"])
    if name:
        db().execute("UPDATE files SET name=? WHERE id=?", (name, fid))
        db().commit()
    return redirect(url_for("index"))

@app.route("/delete/<int:fid>", methods=["POST"])
@login_required
def delete(fid):
    f = own_file(fid)
    try:
        os.remove(os.path.join(user_dir(session["uid"]), f["stored"]))
    except FileNotFoundError:
        pass
    db().execute("DELETE FROM shares WHERE file_id=?", (fid,))
    db().execute("DELETE FROM files WHERE id=?", (fid,))
    db().commit()
    return redirect(url_for("index"))

# ---------- sharing ----------
@app.route("/share/<int:fid>", methods=["POST"])
@login_required
def share(fid):
    own_file(fid)
    days = int(request.form.get("days", 7))
    exp = (datetime.now() + timedelta(days=days)).isoformat() if days else None
    db().execute("INSERT INTO shares(file_id,token,expires) VALUES(?,?,?)", (fid, secrets.token_urlsafe(16), exp))
    db().commit()
    return redirect(url_for("index"))

@app.route("/unshare/<int:sid>", methods=["POST"])
@login_required
def unshare(sid):
    db().execute("DELETE FROM shares WHERE id=? AND file_id IN (SELECT id FROM files WHERE owner=?)",
                 (sid, session["uid"]))
    db().commit()
    return redirect(url_for("index"))

@app.route("/s/<token>")
def public(token):
    s = db().execute("SELECT * FROM shares WHERE token=?", (token,)).fetchone()
    if not s or (s["expires"] and datetime.fromisoformat(s["expires"]) < datetime.now()):
        abort(404)
    f = db().execute("SELECT * FROM files WHERE id=?", (s["file_id"],)).fetchone()
    return send_from_directory(user_dir(f["owner"]), f["stored"], as_attachment=True, download_name=f["name"])

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
