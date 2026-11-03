import os, re, io, sys, json, time, uuid, shutil, signal, shlex, sqlite3, zipfile, secrets, logging, threading, subprocess, hmac, hashlib
import urllib.request, urllib.parse
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file, session, g
from flask_cors import CORS
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
TZ_NAME = os.getenv("TZ") or "Asia/Ho_Chi_Minh"      # giờ hiển thị trong log (đổi bằng biến môi trường TZ)
os.environ["TZ"] = TZ_NAME
if hasattr(time, "tzset"): time.tzset()
try:
    import resource            # chỉ có trên Linux/macOS: dùng để giới hạn RAM cho chương trình người dùng
except ImportError:
    resource = None

load_dotenv()
try:
    import config as _cfg          # file config.py cạnh backend.py (xem hướng dẫn trong file đó)
except Exception:
    _cfg = None

def cfg(name, default=""):
    """Ưu tiên biến môi trường (Render > Environment), sau đó đến config.py."""
    v = os.getenv(name)
    if v is not None and v.strip() != "":
        return v
    v = getattr(_cfg, name, default) if _cfg else default
    return default if v is None else v


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MB = 1024 * 1024
logging.basicConfig(level=logging.INFO)

def cfg_int(name, default):
    try: return int(str(cfg(name, default)).strip())
    except ValueError: return int(default)

def cfg_bool(name, default="0"):
    return str(cfg(name, default)).strip().lower() in ("1", "true", "yes", "on")

# ------------------------------------------------------------------ cấu hình
DB_PATH = os.getenv("DB_PATH", "").strip() or os.path.join(BASE_DIR, "data", "pyhost.db")
ADMIN_EMAIL = str(cfg("ADMIN_EMAIL")).strip().lower()
ADMIN_PASSWORD = str(cfg("ADMIN_PASSWORD"))
GOOGLE_CLIENT_ID = str(cfg("GOOGLE_CLIENT_ID")).strip()
FACEBOOK_APP_ID = str(cfg("FACEBOOK_APP_ID")).strip()
FACEBOOK_APP_SECRET = str(cfg("FACEBOOK_APP_SECRET")).strip()
ALLOW_REGISTER = cfg_bool("ALLOW_REGISTER", "1")
AUTO_APPROVE = cfg_bool("AUTO_APPROVE", "0")          # 0 = tài khoản mới phải chờ admin duyệt (khuyên dùng)
MAX_PROJECTS = cfg_int("MAX_PROJECTS", 5)             # số dự án tối đa mỗi người (admin không giới hạn)
MAX_RUN_USER = cfg_int("MAX_RUNNING_PER_USER", 2)     # số chương trình chạy cùng lúc mỗi người (admin không giới hạn)
MAX_RUN_TOTAL = cfg_int("MAX_RUNNING_TOTAL", 8)       # tổng số chương trình chạy cùng lúc trên máy chủ
USER_QUOTA = cfg_int("USER_QUOTA_MB", 200) * MB       # dung lượng tệp mỗi người
RUN_MEM = cfg_int("RUN_MEM_MB", 400) * MB             # RAM tối đa mỗi chương trình
UPLOAD_MAX = 25 * MB
LOG_MAX = 1 * MB
PENDING_MSG = "Đã đăng ký xong. Tài khoản đang chờ admin duyệt, bạn đăng nhập sau khi được duyệt nhé."
CORS_LIST = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

SECRET_KEY = str(cfg("SECRET_KEY")).strip()
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.warning("Chưa đặt SECRET_KEY: phiên đăng nhập sẽ mất mỗi lần máy chủ khởi động lại.")

app = Flask(__name__, static_folder="static")
# Render đứng sau proxy: lấy IP thật của người dùng để rate-limit không bị gộp chung
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 40 * MB
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None" if CORS_LIST else "Lax",
    SESSION_COOKIE_SECURE=bool(CORS_LIST) or bool(os.getenv("RENDER")) or os.getenv("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per minute"], storage_uri="memory://")
if CORS_LIST:   # chỉ bật CORS khi chủ động khai báo origin (frontend tách riêng)
    CORS(app, resources={r"/api/*": {"origins": CORS_LIST}}, supports_credentials=True)
# ------------------------------------------------------------------ cơ sở dữ liệu (SQLite)
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1, token_ver INTEGER NOT NULL DEFAULT 0,
        failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0, created REAL NOT NULL, last_login REAL)""",
    """CREATE TABLE IF NOT EXISTS projects(
        id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL, entry TEXT NOT NULL DEFAULT '', args TEXT NOT NULL DEFAULT '',
        auto_restart INTEGER NOT NULL DEFAULT 1, run_wanted INTEGER NOT NULL DEFAULT 0,
        env TEXT NOT NULL DEFAULT '{}', created REAL NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_proj_user ON projects(user_id)",
    """CREATE TABLE IF NOT EXISTS api_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL, prefix TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, created REAL NOT NULL, last_used REAL)""",
]

def _connect():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def db():
    if "db" not in g: g.db = _connect()
    return g.db

@app.teardown_appcontext
def _close_db(_exc):
    c = g.pop("db", None)
    if c is not None: c.close()

def q(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]

def q1(sql, args=()):
    r = db().execute(sql, args).fetchone()
    return dict(r) if r else None

def ex(sql, args=(), commit=True):
    cur = db().execute(sql, args)
    if commit: db().commit()
    return cur

def init_db():
    global DB_PATH
    try:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    except OSError:
        DB_PATH = os.path.join(tempfile.gettempdir(), "huy_ai.db")
        logging.warning("Không ghi được vào thư mục dữ liệu, tạm dùng %s", DB_PATH)
    c = _connect()
    try:
        c.execute("PRAGMA journal_mode=WAL")
        for s in SCHEMA: c.execute(s)
        c.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        try: c.execute("ALTER TABLE users ADD COLUMN social INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE projects ADD COLUMN py TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError: pass
        c.commit()
    finally:
        c.close()
    with app.app_context():
        seed_admin()

def seed_admin():
    """Tài khoản admin: ADMIN_EMAIL / ADMIN_PASSWORD (config.py hoặc biến môi trường); đổi giá trị là đổi mật khẩu admin.
    Nếu chưa khai báo thì tự tạo admin@huy.local với mật khẩu cố định suy ra từ SECRET_KEY và in ra log để bạn đăng nhập lần đầu."""
    global ADMIN_EMAIL, ADMIN_PASSWORD
    if not ADMIN_EMAIL or len(ADMIN_PASSWORD) < 8:
        if ADMIN_PASSWORD: logging.warning("ADMIN_PASSWORD phải từ 8 ký tự -> dùng tài khoản admin tự tạo.")
        ADMIN_EMAIL = ADMIN_EMAIL or "admin@huy.local"
        ADMIN_PASSWORD = hmac.new(SECRET_KEY.encode(), b"admin-password", hashlib.sha256).hexdigest()[:14]
        logging.warning("=== ADMIN TỰ TẠO === email: %s | mật khẩu: %s  (hãy đặt ADMIN_EMAIL/ADMIN_PASSWORD của bạn trong config.py hoặc Render > Environment)", ADMIN_EMAIL, ADMIN_PASSWORD)
    now = time.time()
    u = q1("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,))
    if u is None:
        ex("INSERT INTO users(email,name,pw_hash,is_admin,created) VALUES(?,?,?,1,?)",
           (ADMIN_EMAIL, "Admin", generate_password_hash(ADMIN_PASSWORD), now))
        logging.info("Đã tạo tài khoản admin %s", ADMIN_EMAIL)
    else:
        if not check_password_hash(u["pw_hash"], ADMIN_PASSWORD):
            ex("UPDATE users SET pw_hash=?, token_ver=token_ver+1 WHERE id=?", (generate_password_hash(ADMIN_PASSWORD), u["id"]))
        ex("UPDATE users SET is_admin=1, is_active=1, failed=0, locked_until=0, social=0 WHERE id=?", (u["id"],))
    ex("UPDATE users SET is_admin=0 WHERE email<>? AND is_admin=1", (ADMIN_EMAIL,))

# ------------------------------------------------------------------ tài khoản / phiên đăng nhập
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")
MAX_FAILED, LOCK_SECONDS = 8, 15 * 60

def public_user(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "is_admin": bool(u["is_admin"])}

def current_user():
    if "user" in g: return g.user
    u = None
    uid = session.get("uid")
    if uid:
        row = q1("SELECT * FROM users WHERE id=?", (uid,))
        if row and row["is_active"] and row["token_ver"] == session.get("tv"): u = row
    if u is None:
        ah = request.headers.get("Authorization", "")
        if ah.startswith("Bearer ph_") and len(ah) < 120:
            row = q1("SELECT u.*, t.id AS tid FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?", (hashlib.sha256(ah[7:].strip().encode()).hexdigest(),))
            if row and row["is_active"]:
                u = row; g.via_token = True
                try: ex("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), row["tid"]))
                except Exception: pass
    g.user = u
    return u

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if current_user() is None:
            return jsonify({"error": "Bạn chưa đăng nhập hoặc phiên đã hết hạn."}), 401
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if u is None: return jsonify({"error": "Bạn chưa đăng nhập hoặc phiên đã hết hạn."}), 401
        if not u["is_admin"]: return jsonify({"error": "Chỉ admin mới được dùng chức năng này."}), 403
        return fn(*a, **kw)
    return wrapper

def start_session(u):
    session.clear()
    session.permanent = True
    session["uid"], session["tv"] = u["id"], u["token_ver"]

def json_body():
    return request.get_json(silent=True) or {}

@app.post("/api/auth/register")
@limiter.limit("10 per hour")
def register():
    if not ALLOW_REGISTER:
        return jsonify({"error": "Máy chủ đang tắt đăng ký tài khoản mới. Liên hệ admin."}), 403
    d = json_body()
    name = str(d.get("name", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    pw = str(d.get("password", ""))
    if not (2 <= len(name) <= 40): return jsonify({"error": "Tên hiển thị phải từ 2 đến 40 ký tự."}), 400
    if len(email) > 120 or not EMAIL_RE.match(email): return jsonify({"error": "Email không hợp lệ."}), 400
    if not (8 <= len(pw) <= 128): return jsonify({"error": "Mật khẩu phải từ 8 đến 128 ký tự."}), 400
    if email == ADMIN_EMAIL or q1("SELECT 1 AS x FROM users WHERE email=?", (email,)):
        return jsonify({"error": "Email này đã được đăng ký."}), 409
    now = time.time()
    uid = ex("INSERT INTO users(email,name,pw_hash,is_active,created,last_login) VALUES(?,?,?,?,?,?)",
             (email, name, generate_password_hash(pw), 1 if AUTO_APPROVE else 0, now, now)).lastrowid
    u = q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u["is_active"]:
        return jsonify({"pending": True, "message": PENDING_MSG}), 202
    start_session(u)
    return jsonify({"user": public_user(u)})

@app.post("/api/auth/login")
@limiter.limit("10 per minute")
def login():
    d = json_body()
    email = str(d.get("email", "")).strip().lower()
    pw = str(d.get("password", ""))
    u = q1("SELECT * FROM users WHERE email=?", (email,)) if email else None
    bad = jsonify({"error": "Email hoặc mật khẩu không đúng."}), 401
    if u is None:
        check_password_hash(DUMMY_HASH, pw)   # giữ thời gian phản hồi gần như nhau
        return bad
    now = time.time()
    if u["locked_until"] > now:
        mins = int((u["locked_until"] - now) // 60) + 1
        return jsonify({"error": f"Nhập sai quá nhiều lần. Thử lại sau {mins} phút."}), 429
    if not check_password_hash(u["pw_hash"], pw):
        failed = u["failed"] + 1
        if failed >= MAX_FAILED: ex("UPDATE users SET failed=0, locked_until=? WHERE id=?", (now + LOCK_SECONDS, u["id"]))
        else: ex("UPDATE users SET failed=? WHERE id=?", (failed, u["id"]))
        return bad
    if not u["is_active"]:
        return jsonify({"error": "Tài khoản đang chờ admin duyệt hoặc đã bị khóa."}), 403
    ex("UPDATE users SET failed=0, locked_until=0, last_login=? WHERE id=?", (now, u["id"]))
    start_session(u)
    return jsonify({"user": public_user(u)})


# ------------------------------------------------------------------ đăng nhập bằng Google / Facebook
def http_json(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "huy-ai"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))

@app.get("/api/auth/config")
@limiter.exempt
def auth_config():
    return jsonify({"google": GOOGLE_CLIENT_ID, "facebook": FACEBOOK_APP_ID, "register": ALLOW_REGISTER})

def social_login(email, name, allow_admin=False):
    """Đăng nhập/tạo tài khoản từ nhà cung cấp đã xác minh email. Trả về response."""
    email = (email or "").strip().lower()
    name = (name or email.split("@")[0] or "Người dùng").strip()[:40]
    if len(name) < 2: name = (name + " ·")[:40]
    if not EMAIL_RE.match(email) or len(email) > 120:
        return jsonify({"error": "Không lấy được email hợp lệ từ tài khoản này."}), 400
    now = time.time()
    u = q1("SELECT * FROM users WHERE email=?", (email,))
    if u is None:
        if not ALLOW_REGISTER:
            return jsonify({"error": "Máy chủ đang tắt đăng ký tài khoản mới. Liên hệ admin."}), 403
        uid = ex("INSERT INTO users(email,name,pw_hash,social,is_active,created,last_login) VALUES(?,?,?,1,?,?,?)",
                 (email, name, generate_password_hash(secrets.token_urlsafe(32)), 1 if AUTO_APPROVE else 0, now, now)).lastrowid
    else:
        if u["is_admin"] and not allow_admin:
            return jsonify({"error": "Tài khoản admin chỉ đăng nhập bằng email + mật khẩu hoặc Google."}), 403
        if not u["is_active"]:
            return jsonify({"error": "Tài khoản đang chờ admin duyệt hoặc đã bị khóa."}), 403
        uid = u["id"]
        if not u["social"] and not u["is_admin"]:
            # chống chiếm tài khoản: email chưa từng được xác minh khi đăng ký bằng mật khẩu -> vô hiệu mật khẩu cũ
            ex("UPDATE users SET pw_hash=?, token_ver=token_ver+1, social=1 WHERE id=?", (generate_password_hash(secrets.token_urlsafe(32)), uid))
        ex("UPDATE users SET last_login=? WHERE id=?", (now, uid))
    u = q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u["is_active"]:
        return jsonify({"pending": True, "message": PENDING_MSG}), 202
    start_session(u)
    return jsonify({"user": public_user(u)})

@app.post("/api/auth/google")
@limiter.limit("20 per minute")
def auth_google():
    if not GOOGLE_CLIENT_ID: return jsonify({"error": "Máy chủ chưa bật đăng nhập Google."}), 503
    tok = str(json_body().get("credential", ""))
    if not tok or len(tok) > 4000: return jsonify({"error": "Thiếu thông tin đăng nhập Google."}), 400
    try:
        d = http_json("https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": tok}))
    except Exception:
        return jsonify({"error": "Google từ chối phiên đăng nhập này. Thử lại."}), 401
    if d.get("aud") != GOOGLE_CLIENT_ID or d.get("iss") not in ("accounts.google.com", "https://accounts.google.com") \
       or str(d.get("email_verified")).lower() != "true" or int(d.get("exp", 0) or 0) < time.time():
        return jsonify({"error": "Phiên đăng nhập Google không hợp lệ."}), 401
    return social_login(d.get("email"), d.get("name"), allow_admin=True)

@app.post("/api/auth/facebook")
@limiter.limit("20 per minute")
def auth_facebook():
    if not (FACEBOOK_APP_ID and FACEBOOK_APP_SECRET): return jsonify({"error": "Máy chủ chưa bật đăng nhập Facebook."}), 503
    tok = str(json_body().get("accessToken", ""))
    if not tok or len(tok) > 1000: return jsonify({"error": "Thiếu thông tin đăng nhập Facebook."}), 400
    try:
        dbg = http_json("https://graph.facebook.com/debug_token?" + urllib.parse.urlencode(
            {"input_token": tok, "access_token": FACEBOOK_APP_ID + "|" + FACEBOOK_APP_SECRET})).get("data", {})
        if not dbg.get("is_valid") or str(dbg.get("app_id")) != FACEBOOK_APP_ID:
            return jsonify({"error": "Phiên đăng nhập Facebook không hợp lệ."}), 401
        prof = http_json("https://graph.facebook.com/me?" + urllib.parse.urlencode({"fields": "id,name,email", "access_token": tok}))
    except Exception:
        return jsonify({"error": "Facebook từ chối phiên đăng nhập này. Thử lại."}), 401
    if not prof.get("id"): return jsonify({"error": "Không đọc được hồ sơ Facebook."}), 401
    # Facebook không phải lúc nào cũng trả email: khi thiếu thì dùng định danh riêng của Facebook
    email = prof.get("email") or f"fb_{prof['id']}@facebook.local"
    return social_login(email, prof.get("name"))

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/auth/me")
def me():
    u = current_user()
    if u is None: return jsonify({"error": "Chưa đăng nhập."}), 401
    return jsonify({"user": public_user(u)})

@app.post("/api/auth/password")
@limiter.limit("10 per hour")
@login_required
def change_password():
    d, u = json_body(), current_user()
    old, new = str(d.get("current", "")), str(d.get("new", ""))
    if not check_password_hash(u["pw_hash"], old): return jsonify({"error": "Mật khẩu hiện tại không đúng."}), 400
    if not (8 <= len(new) <= 128): return jsonify({"error": "Mật khẩu mới phải từ 8 đến 128 ký tự."}), 400
    if u["is_admin"] and ADMIN_PASSWORD:
        return jsonify({"error": "Mật khẩu admin được đặt bằng biến môi trường ADMIN_PASSWORD trên máy chủ; hãy đổi ở đó."}), 400
    ex("UPDATE users SET pw_hash=?, token_ver=token_ver+1 WHERE id=?", (generate_password_hash(new), u["id"]))
    start_session(q1("SELECT * FROM users WHERE id=?", (u["id"],)))
    return jsonify({"ok": True})

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(self), geolocation=()"
    if request.path.startswith("/api/") and "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
@limiter.exempt
def home():
    return send_from_directory("static", "index.html")

@app.get("/favicon.ico")
@limiter.exempt
def favicon():
    return "", 204

@app.get("/api/health")
@limiter.exempt
def health():
    with PLOCK: n = sum(1 for v in PROCS.values() if v["kind"] == "run")
    return jsonify({"ok": True, "app": "Python Host", "version": "h1", "running": n, "register": ALLOW_REGISTER,
                    "config_py_loaded": _cfg is not None, "admin_email_set": bool(ADMIN_EMAIL)})

# ------------------------------------------------------------------ máy chủ chạy file Python
PROCS = {}          # project_id -> {"proc","kind","started","uid","stopping"}
LAST = {}           # project_id -> {"code","ended","kind","stopped"}
RESTARTS = {}       # project_id -> [thời điểm tự khởi động lại]
PLOCK = threading.RLock()
NAME_RE = re.compile(r"^[^\x00-\x1f/\\]{1,120}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

def proj_root(): return os.path.join(os.path.dirname(DB_PATH) or ".", "projects")
def pdir(pid): return os.path.join(proj_root(), pid)
def wdir(pid): return os.path.join(pdir(pid), "files")
def libdir(pid): return os.path.join(pdir(pid), "libs")
def logp(pid): return os.path.join(pdir(pid), "run.log")

def raw_all(sql, args=()):
    c = _connect()
    try: return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally: c.close()

def raw_exec(sql, args=()):
    c = _connect()
    try:
        c.execute(sql, args); c.commit()
    finally: c.close()

def dir_size(path):
    total = 0
    for root, _d, files in os.walk(path):
        for f in files:
            try: total += os.path.getsize(os.path.join(root, f))
            except OSError: pass
    return total

def user_usage(uid):
    return sum(dir_size(pdir(p["id"])) for p in q("SELECT id FROM projects WHERE user_id=?", (uid,)))

def fmt_size(n):
    return f"{n / 1024:.0f} KB" if n < MB else f"{n / MB:.1f} MB"

def safe_join(base, rel):
    rel = str(rel or "").replace("\\", "/").strip().lstrip("/")
    parts = []
    for part in rel.split("/"):
        if part in ("", "."): continue
        if part == ".." or "\x00" in part or len(part) > 150: raise ValueError("Đường dẫn không hợp lệ.")
        parts.append(part)
    if not parts or len(parts) > 12: raise ValueError("Đường dẫn không hợp lệ.")
    root = os.path.realpath(base)
    full = os.path.realpath(os.path.join(root, *parts))
    if not full.startswith(root + os.sep): raise ValueError("Đường dẫn không hợp lệ.")
    return full, "/".join(parts)

def plog(pid, text):
    try:
        with open(logp(pid), "ab") as f:
            f.write((time.strftime("[%H:%M:%S] ") + text + "\n").encode("utf-8", errors="replace"))
    except OSError:
        pass

def read_tail(path, n):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - n))
            return f.read().decode("utf-8", errors="replace"), size
    except OSError:
        return "", 0

def rss_mb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"): return round(int(line.split()[1]) / 1024, 1)
    except (OSError, ValueError):
        pass
    return None

def status_of(pid):
    with PLOCK: st = PROCS.get(pid)
    if st:
        info = {"state": "installing" if st["kind"] == "install" else "running", "pid": st["proc"].pid,
                "started": st["started"], "stopping": bool(st.get("stopping"))}
        m = rss_mb(st["proc"].pid)
        if m is not None: info["mem_mb"] = m
        return info
    last = LAST.get(pid)
    if last and last["kind"] == "run" and not last.get("stopped") and last["code"] not in (0, None):
        return {"state": "crashed", "code": last["code"]}
    return {"state": "stopped"}

def user_env(p):
    try: d = json.loads(p.get("env") or "{}")
    except ValueError: d = {}
    return {k: str(v)[:4000] for k, v in d.items() if ENV_KEY_RE.match(str(k))}

def build_env(p):
    """Môi trường sạch cho chương trình người dùng: KHÔNG chứa SECRET_KEY, mật khẩu admin hay key của máy chủ."""
    pid = p["id"]
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": wdir(pid), "LANG": "C.UTF-8",
           "PYTHONUNBUFFERED": "1", "TZ": TZ_NAME, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": libdir(pid)}
    env.update(user_env(p))
    return env

def _limits_run():
    if resource is None: return
    for lim, val in ((resource.RLIMIT_AS, RUN_MEM), (resource.RLIMIT_NOFILE, 512), (resource.RLIMIT_FSIZE, 200 * MB), (resource.RLIMIT_CORE, 0)):
        try: resource.setrlimit(lim, (val, val))
        except (ValueError, OSError): pass

def _limits_install():
    if resource is None: return
    for lim, val in ((resource.RLIMIT_NOFILE, 1024), (resource.RLIMIT_FSIZE, 400 * MB), (resource.RLIMIT_CORE, 0)):
        try: resource.setrlimit(lim, (val, val))
        except (ValueError, OSError): pass

def guess_entry(pid):
    wd = wdir(pid)
    try: names = sorted(n for n in os.listdir(wd) if n.lower().endswith(".py") and os.path.isfile(os.path.join(wd, n)))
    except OSError: return ""
    for pref in ("main.py", "bot.py", "app.py", "run.py", "index.py"):
        if pref in names: return pref
    return names[0] if names else ""

def _pump(pid, proc, kind):
    path, f = logp(pid), None
    try:
        f = open(path, "ab")
        fd = proc.stdout.fileno()
        while True:
            chunk = os.read(fd, 8192)
            if not chunk: break
            f.write(chunk); f.flush()
            if f.tell() > LOG_MAX:
                f.close(); os.replace(path, path + ".1"); f = open(path, "ab")
    except Exception:
        pass
    finally:
        if f:
            try: f.close()
            except Exception: pass
    code = proc.wait()
    _on_exit(pid, proc, kind, code)

def _on_exit(pid, proc, kind, code):
    stopping, then_run = False, False
    with PLOCK:
        st = PROCS.get(pid)
        if st and st["proc"] is proc:
            stopping = bool(st.get("stopping")); then_run = bool(st.get("then_run"))
            PROCS.pop(pid, None)
    LAST[pid] = {"code": code, "ended": time.time(), "kind": kind, "stopped": stopping}
    plog(pid, ("■ Cài thư viện xong" if kind == "install" else "■ Chương trình đã dừng") + f" (mã thoát {code})" + (" — do bạn dừng" if stopping else ""))
    if kind == "install":
        try:
            p = (raw_all("SELECT * FROM projects WHERE id=?", (pid,)) or [None])[0]
            if p and code == 0 and not stopping:
                os.makedirs(libdir(pid), exist_ok=True)
                with open(os.path.join(libdir(pid), ".req_sig"), "w") as fh: fh.write(req_sig(p) or "")
                if then_run:
                    plog(pid, "✔ Đã cài xong thư viện, đang chạy chương trình…")
                    start_process(p, "run")
            elif p and then_run and not stopping:
                plog(pid, "⚠ Cài thư viện bị lỗi nên chưa chạy chương trình. Sửa requirements.txt rồi bấm Chạy lại.")
                raw_exec("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
        except Exception as exc:
            plog(pid, "⚠ Lỗi sau khi cài thư viện: " + str(exc))
        return
    if kind != "run" or stopping: return
    try:
        p = (raw_all("SELECT * FROM projects WHERE id=?", (pid,)) or [None])[0]
        if not p or not p["run_wanted"]: return
        if p["auto_restart"] and code != 0: _schedule_restart(pid)
        else: raw_exec("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
    except Exception:
        logging.exception("on_exit")

def _schedule_restart(pid):
    now = time.time()
    with PLOCK:
        hist = [t for t in RESTARTS.get(pid, []) if now - t < 600]
        if len(hist) >= 8:
            RESTARTS[pid] = hist
            give_up = True
        else:
            hist.append(now); RESTARTS[pid] = hist
            give_up = False
            delay = min(60, 3 * (2 ** (len(hist) - 1)))
    if give_up:
        plog(pid, "⚠ Lỗi liên tục (8 lần trong 10 phút) nên đã ngừng tự khởi động lại. Hãy sửa lỗi rồi bấm Chạy.")
        raw_exec("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
        return
    plog(pid, f"↻ Sẽ tự khởi động lại sau {delay} giây…")
    t = threading.Timer(delay, _auto_start, (pid,)); t.daemon = True; t.start()

def _auto_start(pid):
    try:
        p = (raw_all("SELECT * FROM projects WHERE id=?", (pid,)) or [None])[0]
        if not p or not p["run_wanted"]: return
        with PLOCK:
            if pid in PROCS: return
        start_process(p, "run")
    except Exception as exc:
        plog(pid, "⚠ Không tự khởi động lại được: " + str(exc))

PY_VERSIONS = ["3.9", "3.10", "3.11", "3.12", "3.13"]
PY_CACHE = {}
PY_LOCK = threading.Lock()

def py_dir(): return os.path.join(os.path.dirname(DB_PATH) or ".", "pythons")

def resolve_python(ver, pid=None):
    """Trả về đường dẫn python đúng phiên bản. Rỗng = Python của máy chủ. Thiếu thì tự tải bằng uv (cần mạng, lần đầu ~10-60 giây)."""
    ver = (ver or "").strip()
    if not ver: return sys.executable
    if ver not in PY_VERSIONS: raise ValueError("Phiên bản Python không hỗ trợ.")
    if f"{sys.version_info.major}.{sys.version_info.minor}" == ver: return sys.executable
    with PY_LOCK:
        exe = PY_CACHE.get(ver)
        if exe and os.path.exists(exe): return exe
        exe = shutil.which(f"python{ver}")
        if not exe:
            env = dict(os.environ, UV_PYTHON_INSTALL_DIR=os.path.join(py_dir(), "uv"), UV_PYTHON_PREFERENCE="only-managed")
            uv = [shutil.which("uv")] if shutil.which("uv") else [sys.executable, "-m", "uv"]
            if pid: plog(pid, f"⬇ Đang tải Python {ver} (chỉ lần đầu, vui lòng chờ)…")
            try:
                r = subprocess.run(uv + ["python", "install", ver], env=env, capture_output=True, text=True, timeout=100)
                if r.returncode != 0: raise ValueError(f"Không tải được Python {ver}: " + (r.stderr or r.stdout or "").strip()[-300:])
                r = subprocess.run(uv + ["python", "find", ver], env=env, capture_output=True, text=True, timeout=30)
                exe = (r.stdout or "").strip().splitlines()[-1] if r.returncode == 0 and r.stdout.strip() else ""
            except (OSError, subprocess.TimeoutExpired):
                raise ValueError(f"Không tải được Python {ver}. Máy chủ cần có mạng và thư viện uv, hoặc đã cài sẵn python{ver}.")
        if not exe or not os.path.exists(exe): raise ValueError(f"Máy chủ chưa có Python {ver}.")
        PY_CACHE[ver] = exe
        return exe

def req_sig(p):
    f = os.path.join(wdir(p["id"]), "requirements.txt")
    if not os.path.isfile(f): return None
    with open(f, "rb") as fh: return hashlib.sha1(fh.read() + b"|" + (p.get("py") or "").encode()).hexdigest()

def need_install(p):
    sig = req_sig(p)
    if not sig: return False
    try:
        with open(os.path.join(libdir(p["id"]), ".req_sig")) as fh: return fh.read().strip() != sig
    except OSError: return True

def start_process(p, kind="run", then_run=False):
    pid, uid = p["id"], p["user_id"]
    wd = wdir(pid)
    os.makedirs(wd, exist_ok=True); os.makedirs(libdir(pid), exist_ok=True)
    owner = (raw_all("SELECT is_admin FROM users WHERE id=?", (uid,)) or [{"is_admin": 0}])[0]
    if kind == "run" and need_install(p):
        plog(pid, "📦 Có requirements.txt chưa cài, tự cài thư viện trước khi chạy…")
        return start_process(p, "install", then_run=True)
    exe = resolve_python(p.get("py") or "", pid)
    with PLOCK:
        if pid in PROCS: raise ValueError("Dự án đang chạy hoặc đang cài thư viện.")
        if kind == "run":
            total = sum(1 for v in PROCS.values() if v["kind"] == "run")
            mine = sum(1 for v in PROCS.values() if v["kind"] == "run" and v["uid"] == uid)
            if total >= MAX_RUN_TOTAL: raise ValueError(f"Máy chủ đang chạy tối đa {MAX_RUN_TOTAL} chương trình. Hãy thử lại sau.")
            if not owner["is_admin"] and mine >= MAX_RUN_USER: raise ValueError(f"Mỗi tài khoản chạy tối đa {MAX_RUN_USER} chương trình cùng lúc. Hãy dừng bớt một dự án.")
        if kind == "run":
            entry = (p["entry"] or "").strip() or guess_entry(pid)
            if not entry: raise ValueError("Chưa có file Python để chạy. Hãy tải lên file .py và chọn file chạy trong Cài đặt.")
            full, entry = safe_join(wd, entry)
            if not os.path.isfile(full) or not entry.lower().endswith(".py"): raise ValueError(f"Không tìm thấy file chạy: {entry}")
            try: extra = shlex.split(p["args"] or "")[:20]
            except ValueError: raise ValueError("Tham số dòng lệnh không hợp lệ.")
            cmd = [exe, "-u", entry] + extra
            shown = f"python{(p.get('py') or '')} " + " ".join(shlex.quote(c) for c in cmd[2:])
        else:
            if not os.path.isfile(os.path.join(wd, "requirements.txt")): raise ValueError("Không có file requirements.txt để cài.")
            cmd = [exe, "-m", "pip", "install", "-r", "requirements.txt", "--target", libdir(pid), "--no-cache-dir", "--disable-pip-version-check", "--upgrade"]
            shown = "pip install -r requirements.txt"
        if os.path.exists(logp(pid)) and os.path.getsize(logp(pid)) > LOG_MAX:
            try: os.replace(logp(pid), logp(pid) + ".1")
            except OSError: pass
        plog(pid, "▶ " + shown)
        proc = subprocess.Popen(cmd, cwd=wd, env=build_env(p), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True, close_fds=True, preexec_fn=_limits_run if kind == "run" else _limits_install)
        PROCS[pid] = {"proc": proc, "kind": kind, "started": time.time(), "uid": uid, "stopping": False, "then_run": then_run}
    LAST.pop(pid, None)
    threading.Thread(target=_pump, args=(pid, proc, kind), daemon=True).start()
    if kind == "install":
        def watchdog():
            time.sleep(900)
            if proc.poll() is None:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
        threading.Thread(target=watchdog, daemon=True).start()
    return proc

def stop_process(pid):
    with PLOCK: st = PROCS.get(pid)
    if not st: return False
    st["stopping"] = True
    proc = st["proc"]
    try: os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError): pass
    def killer():
        time.sleep(6)
        if proc.poll() is None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError): pass
    threading.Thread(target=killer, daemon=True).start()
    return True

def wait_stopped(pid, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        with PLOCK:
            if pid not in PROCS: return True
        time.sleep(0.2)
    return False

def resume_all():
    """Sau khi máy chủ khởi động lại: tự chạy lại các dự án đang ở trạng thái 'chạy'."""
    try:
        for p in raw_all("SELECT p.* FROM projects p JOIN users u ON u.id=p.user_id WHERE p.run_wanted=1 AND u.is_active=1"):
            try:
                plog(p["id"], "↻ Máy chủ vừa khởi động lại, tự chạy lại dự án…")
                start_process(p, "run")
            except Exception as exc:
                plog(p["id"], "⚠ Không tự chạy lại được: " + str(exc))
                raw_exec("UPDATE projects SET run_wanted=0 WHERE id=?", (p["id"],))
    except Exception:
        logging.exception("resume_all")

# ------------------------------------------------------------------ API dự án
def own_project(pid):
    u = current_user()
    p = q1("SELECT * FROM projects WHERE id=? AND user_id=?", (str(pid or ""), u["id"]))
    return p

def project_json(p, detail=False):
    pid = p["id"]
    d = {"id": pid, "name": p["name"], "entry": p["entry"] or guess_entry(pid), "args": p["args"], "auto_restart": bool(p["auto_restart"]),
         "run_wanted": bool(p["run_wanted"]), "py": (p.get("py") or ""), "py_default": f"{sys.version_info.major}.{sys.version_info.minor}", "py_versions": PY_VERSIONS, "created": p["created"], "status": status_of(pid), "size": dir_size(pdir(pid))}
    if detail: d["env"] = user_env(p)
    return d

def not_found(): return jsonify({"error": "Không tìm thấy dự án."}), 404

@app.get("/api/projects")
@login_required
def list_projects():
    rows = q("SELECT * FROM projects WHERE user_id=? ORDER BY created DESC", (current_user()["id"],))
    u = current_user()
    return jsonify({"projects": [project_json(p) for p in rows], "limits": {
        "max_projects": None if u["is_admin"] else MAX_PROJECTS, "max_running": None if u["is_admin"] else MAX_RUN_USER,
        "quota": None if u["is_admin"] else USER_QUOTA, "usage": user_usage(u["id"]), "mem_mb": RUN_MEM // MB}})

@app.post("/api/projects")
@limiter.limit("30 per hour")
@login_required
def create_project():
    u = current_user()
    name = str(json_body().get("name", "")).strip()
    if not (1 <= len(name) <= 40): return jsonify({"error": "Tên dự án từ 1 đến 40 ký tự."}), 400
    if not u["is_admin"] and q1("SELECT COUNT(*) AS n FROM projects WHERE user_id=?", (u["id"],))["n"] >= MAX_PROJECTS:
        return jsonify({"error": f"Mỗi tài khoản tối đa {MAX_PROJECTS} dự án."}), 403
    pid = uuid.uuid4().hex[:16]
    os.makedirs(wdir(pid), exist_ok=True)
    ex("INSERT INTO projects(id,user_id,name,created) VALUES(?,?,?,?)", (pid, u["id"], name, time.time()))
    return jsonify({"project": project_json(q1("SELECT * FROM projects WHERE id=?", (pid,)), True)})

def list_files(pid):
    base, out = wdir(pid), []
    for root, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for f in sorted(files):
            full = os.path.join(root, f)
            try: st = os.stat(full)
            except OSError: continue
            out.append({"path": os.path.relpath(full, base).replace(os.sep, "/"), "size": st.st_size, "mtime": st.st_mtime})
            if len(out) >= 1500: return out
    return out

@app.get("/api/projects/<pid>")
@login_required
def get_project(pid):
    p = own_project(pid)
    if not p: return not_found()
    return jsonify({"project": project_json(p, True), "files": list_files(pid)})

@app.patch("/api/projects/<pid>")
@login_required
def update_project(pid):
    p = own_project(pid)
    if not p: return not_found()
    d = json_body()
    sets, args = [], []
    if "name" in d:
        name = str(d["name"]).strip()
        if not (1 <= len(name) <= 40): return jsonify({"error": "Tên dự án từ 1 đến 40 ký tự."}), 400
        sets.append("name=?"); args.append(name)
    if "entry" in d:
        entry = str(d["entry"]).strip()
        if entry:
            try: _full, entry = safe_join(wdir(pid), entry)
            except ValueError as e: return jsonify({"error": str(e)}), 400
            if not entry.lower().endswith(".py"): return jsonify({"error": "File chạy phải có đuôi .py"}), 400
        sets.append("entry=?"); args.append(entry)
    if "args" in d:
        a = str(d["args"]).strip()
        if len(a) > 300: return jsonify({"error": "Tham số tối đa 300 ký tự."}), 400
        sets.append("args=?"); args.append(a)
    if "py" in d:
        v = str(d["py"]).strip()
        if v and v not in PY_VERSIONS: return jsonify({"error": "Phiên bản Python không hỗ trợ."}), 400
        sets.append("py=?"); args.append(v)
    if "auto_restart" in d:
        sets.append("auto_restart=?"); args.append(1 if d["auto_restart"] else 0)
    if "env" in d:
        env = d["env"]
        if not isinstance(env, dict) or len(env) > 50: return jsonify({"error": "Biến môi trường không hợp lệ (tối đa 50)."}), 400
        clean = {}
        for k, v in env.items():
            if not ENV_KEY_RE.match(str(k)): return jsonify({"error": f"Tên biến không hợp lệ: {k}"}), 400
            clean[str(k)] = str(v)[:4000]
        sets.append("env=?"); args.append(json.dumps(clean))
    if sets:
        ex("UPDATE projects SET " + ",".join(sets) + " WHERE id=?", tuple(args) + (pid,))
    return jsonify({"project": project_json(q1("SELECT * FROM projects WHERE id=?", (pid,)), True)})

def destroy_project(pid):
    stop_process(pid); wait_stopped(pid, 8)
    shutil.rmtree(pdir(pid), ignore_errors=True)
    LAST.pop(pid, None); RESTARTS.pop(pid, None)

@app.delete("/api/projects/<pid>")
@login_required
def delete_project(pid):
    if not own_project(pid): return not_found()
    destroy_project(pid)
    ex("DELETE FROM projects WHERE id=?", (pid,))
    return jsonify({"ok": True})

def extract_zip(data, dest, budget):
    try: zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile: raise ValueError("File .zip bị lỗi.")
    infos = [i for i in zf.infolist() if not i.is_dir() and "__MACOSX" not in i.filename and not os.path.basename(i.filename).startswith("._")]
    if len(infos) > 3000: raise ValueError("File .zip có quá nhiều tệp (tối đa 3000).")
    total = sum(i.file_size for i in infos)
    if total > 150 * MB or total > budget: raise ValueError("Giải nén vượt giới hạn dung lượng.")
    names = [i.filename.replace("\\", "/").lstrip("/") for i in infos]
    tops = {n.split("/")[0] for n in names}
    strip = len(tops) == 1 and all("/" in n for n in names)
    count = 0
    for i, n in zip(infos, names):
        rel = n.split("/", 1)[1] if strip else n
        try: full, _ = safe_join(dest, rel)
        except ValueError: continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with zf.open(i) as src, open(full, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        count += 1
    return count, total

@app.post("/api/projects/<pid>/upload")
@limiter.limit("60 per hour")
@login_required
def upload_files(pid):
    p = own_project(pid)
    if not p: return not_found()
    u = current_user()
    files = request.files.getlist("files")
    if not files: return jsonify({"error": "Bạn chưa chọn file."}), 400
    extract = request.form.get("extract", "1") != "0"
    sub = request.form.get("dir", "").strip()
    wd = wdir(pid); os.makedirs(wd, exist_ok=True)
    used = user_usage(u["id"])
    saved = []
    for f in files[:60]:
        fname = os.path.basename(str(f.filename or "").replace("\\", "/"))
        if not fname or not NAME_RE.match(fname): continue
        data = f.read(UPLOAD_MAX + 1)
        if len(data) > UPLOAD_MAX: return jsonify({"error": f"{fname} lớn hơn {UPLOAD_MAX // MB} MB."}), 413
        left = (1 << 60) if u["is_admin"] else USER_QUOTA - used
        if len(data) > left: return jsonify({"error": f"Hết dung lượng ({USER_QUOTA // MB} MB). Hãy xóa bớt tệp."}), 413
        try:
            if extract and fname.lower().endswith(".zip"):
                n, size = extract_zip(data, os.path.join(wd, sub) if sub else wd, left)
                used += size; saved.append(f"{fname} (giải nén {n} tệp)")
            else:
                full, rel = safe_join(wd, (sub + "/" if sub else "") + fname)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as out: out.write(data)
                used += len(data); saved.append(rel)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    if not (p["entry"] or "").strip():
        g_entry = guess_entry(pid)
        if g_entry: ex("UPDATE projects SET entry=? WHERE id=?", (g_entry, pid))
    return jsonify({"saved": saved, "files": list_files(pid)})

@app.get("/api/projects/<pid>/file")
@login_required
def read_file(pid):
    if not own_project(pid): return not_found()
    try: full, rel = safe_join(wdir(pid), request.args.get("path", ""))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    if not os.path.isfile(full): return jsonify({"error": "Không có file này."}), 404
    if os.path.getsize(full) > 1 * MB: return jsonify({"error": "File quá lớn để sửa trên web (tối đa 1 MB)."}), 413
    try:
        with open(full, "rb") as f: text = f.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "Đây là file nhị phân, không sửa được trên web."}), 415
    return jsonify({"path": rel, "content": text})

@app.put("/api/projects/<pid>/file")
@limiter.limit("240 per hour")
@login_required
def write_file(pid):
    p = own_project(pid)
    if not p: return not_found()
    d = json_body()
    content = d.get("content")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 2 * MB: return jsonify({"error": "Nội dung trống hoặc quá lớn (tối đa 2 MB)."}), 400
    try: full, rel = safe_join(wdir(pid), d.get("path", ""))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    u = current_user()
    if not u["is_admin"] and user_usage(u["id"]) + len(content.encode("utf-8")) > USER_QUOTA: return jsonify({"error": "Hết dung lượng lưu trữ."}), 413
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="") as f: f.write(content)
    if not (p["entry"] or "").strip() and rel.lower().endswith(".py"): ex("UPDATE projects SET entry=? WHERE id=?", (guess_entry(pid), pid))
    return jsonify({"ok": True, "path": rel})

@app.delete("/api/projects/<pid>/file")
@login_required
def delete_file(pid):
    p = own_project(pid)
    if not p: return not_found()
    try: full, rel = safe_join(wdir(pid), request.args.get("path", ""))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    if os.path.isdir(full): shutil.rmtree(full, ignore_errors=True)
    elif os.path.isfile(full): os.remove(full)
    else: return jsonify({"error": "Không có file này."}), 404
    return jsonify({"ok": True})

# ------------------------------------------------------------------ API nâng cao
from flask import Response, stream_with_context
import codecs
CPU_PREV = {}
STREAMS = [0]
SLOCK = threading.Lock()

def session_only(fn):
    @wraps(fn)
    def w(*a, **kw):
        if current_user() is None: return jsonify({"error": "Bạn chưa đăng nhập hoặc phiên đã hết hạn."}), 401
        if g.get("via_token"): return jsonify({"error": "Thao tác này chỉ dùng được khi đăng nhập bằng trình duyệt."}), 403
        return fn(*a, **kw)
    return w

@app.get("/api/tokens")
@session_only
def list_tokens():
    rows = raw_all("SELECT id,name,prefix,created,last_used FROM api_tokens WHERE user_id=? ORDER BY id DESC", (current_user()["id"],))
    return jsonify({"tokens": [dict(r) for r in rows]})

@app.post("/api/tokens")
@session_only
def create_token():
    u = current_user(); d = json_body()
    name = str(d.get("name") or "Token").strip()[:40] or "Token"
    if (raw_all("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id=?", (u["id"],)) or [{"n": 0}])[0]["n"] >= 10:
        return jsonify({"error": "Tối đa 10 token. Hãy xóa bớt token cũ."}), 400
    tok = "ph_" + secrets.token_urlsafe(32)
    raw_exec("INSERT INTO api_tokens(user_id,name,prefix,token_hash,created) VALUES(?,?,?,?,?)",
             (u["id"], name, tok[:9], hashlib.sha256(tok.encode()).hexdigest(), time.time()))
    return jsonify({"token": tok, "name": name, "note": "Token chỉ hiện một lần, hãy lưu lại ngay."}), 201

@app.delete("/api/tokens/<int:tid>")
@session_only
def delete_token(tid):
    raw_exec("DELETE FROM api_tokens WHERE id=? AND user_id=?", (tid, current_user()["id"]))
    return jsonify({"ok": True})

def cpu_percent(pid):
    try:
        with open(f"/proc/{pid}/stat") as f: x = f.read().rsplit(")", 1)[1].split()
        ticks = (int(x[11]) + int(x[12])) / os.sysconf("SC_CLK_TCK"); threads = int(x[17])
    except (OSError, ValueError, IndexError): return None, None
    t = time.time(); prev = CPU_PREV.get(pid)
    CPU_PREV[pid] = (t, ticks)
    if not prev or t - prev[0] < 0.2:
        time.sleep(0.25); t2 = time.time()
        try:
            with open(f"/proc/{pid}/stat") as f: y = f.read().rsplit(")", 1)[1].split()
            t3 = (int(y[11]) + int(y[12])) / os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError, IndexError): return None, threads
        CPU_PREV[pid] = (t2, t3)
        return round(max(0, t3 - ticks) / max(0.01, t2 - t) * 100, 1), threads
    return round(max(0, ticks - prev[1]) / (t - prev[0]) * 100, 1), threads

def dir_bytes(path):
    n = 0
    for r, _, fs in os.walk(path):
        for fn in fs:
            try: n += os.path.getsize(os.path.join(r, fn))
            except OSError: pass
    return n

@app.get("/api/projects/<pid>/stats")
@login_required
def project_stats(pid):
    p = own_project(pid)
    if not p: return not_found()
    st = status_of(pid); out = {"status": st, "files_bytes": dir_bytes(wdir(pid)), "libs_bytes": dir_bytes(libdir(pid)),
                                "restarts_10m": len([t for t in RESTARTS.get(pid, []) if time.time() - t < 600])}
    if st.get("pid"):
        cpu, th = cpu_percent(st["pid"]); out.update(cpu=cpu, threads=th, uptime=round(time.time() - st["started"]))
    else: CPU_PREV.pop(pid, None)
    return jsonify(out)

def _sse(ev, data): return f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

@app.get("/api/projects/<pid>/logs/stream")
@login_required
def log_stream(pid):
    """Log trực tiếp (Server-Sent Events). Mỗi phiên tối đa 10 phút, trình duyệt tự nối lại."""
    if not own_project(pid): return not_found()
    with SLOCK:
        if STREAMS[0] >= 4: return jsonify({"error": "Đang có quá nhiều luồng log mở cùng lúc."}), 429
        STREAMS[0] += 1
    path = logp(pid)
    def gen():
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            text, pos = read_tail(path, 30000)
            yield _sse("init", {"text": text, "status": status_of(pid)})
            end, last = time.time() + 600, 0
            while time.time() < end:
                try: size = os.path.getsize(path)
                except OSError: size = 0
                if size < pos: pos = 0; dec.reset(); yield _sse("reset", {})
                if size > pos:
                    with open(path, "rb") as f: f.seek(pos); data = f.read(65536)
                    pos += len(data)
                    yield _sse("log", {"text": dec.decode(data)})
                    continue
                if time.time() - last > 2: last = time.time(); yield _sse("status", status_of(pid))
                time.sleep(0.5)
            yield _sse("bye", {})
        finally:
            with SLOCK: STREAMS[0] -= 1
    return Response(stream_with_context(gen()), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/projects/<pid>/export")
@login_required
def export_project(pid):
    p = own_project(pid)
    if not p: return not_found()
    base, buf, total = wdir(pid), io.BytesIO(), 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r, _, fs in os.walk(base):
            for fn in fs:
                full = os.path.join(r, fn); total += os.path.getsize(full)
                if total > 50 * MB: return jsonify({"error": "Dự án quá lớn để xuất (trên 50 MB)."}), 413
                z.write(full, os.path.relpath(full, base))
    buf.seek(0)
    safe = re.sub(r"[^\w.-]+", "_", p["name"]).strip("_") or "project"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=safe + ".zip")

@app.post("/api/projects/<pid>/rename")
@login_required
def rename_file(pid):
    p = own_project(pid)
    if not p: return not_found()
    d = json_body()
    try:
        src, old = safe_join(wdir(pid), d.get("path", ""))
        dst, new = safe_join(wdir(pid), d.get("new", ""))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    if not os.path.exists(src): return jsonify({"error": "Không có file này."}), 404
    if old == new: return jsonify({"ok": True, "path": new})
    if os.path.exists(dst): return jsonify({"error": "Đã có file trùng tên này."}), 409
    if os.path.isfile(src) and old.lower().endswith(".py") and not new.lower().endswith(".py") and (p["entry"] or "") == old:
        return jsonify({"error": "Đây là file chạy chính, tên mới phải có đuôi .py."}), 400
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    os.rename(src, dst)
    if (p["entry"] or "") == old: ex("UPDATE projects SET entry=? WHERE id=?", (new, pid))
    return jsonify({"ok": True, "path": new})

@app.get("/api/projects/<pid>/download")
@login_required
def download_file(pid):
    if not own_project(pid): return not_found()
    try: full, rel = safe_join(wdir(pid), request.args.get("path", ""))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    if not os.path.isfile(full): return jsonify({"error": "Không có file này."}), 404
    return send_file(full, as_attachment=True, download_name=os.path.basename(full))

@app.post("/api/projects/<pid>/start")
@limiter.limit("60 per hour")
@login_required
def start_project(pid):
    p = own_project(pid)
    if not p: return not_found()
    try: start_process(p, "run")
    except ValueError as e: return jsonify({"error": str(e)}), 400
    except OSError as e: return jsonify({"error": "Không khởi động được: " + str(e)}), 500
    RESTARTS.pop(pid, None)
    ex("UPDATE projects SET run_wanted=1 WHERE id=?", (pid,))
    return jsonify({"status": status_of(pid)})

@app.post("/api/projects/<pid>/stop")
@login_required
def stop_project(pid):
    if not own_project(pid): return not_found()
    ex("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
    stop_process(pid)
    return jsonify({"status": status_of(pid)})

@app.post("/api/projects/<pid>/restart")
@limiter.limit("60 per hour")
@login_required
def restart_project(pid):
    p = own_project(pid)
    if not p: return not_found()
    ex("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
    stop_process(pid)
    if not wait_stopped(pid, 10): return jsonify({"error": "Chương trình chưa dừng kịp, thử lại sau vài giây."}), 409
    try: start_process(p, "run")
    except ValueError as e: return jsonify({"error": str(e)}), 400
    RESTARTS.pop(pid, None)
    ex("UPDATE projects SET run_wanted=1 WHERE id=?", (pid,))
    return jsonify({"status": status_of(pid)})

@app.post("/api/projects/<pid>/install")
@limiter.limit("20 per hour")
@login_required
def install_requirements(pid):
    p = own_project(pid)
    if not p: return not_found()
    try: start_process(p, "install")
    except ValueError as e: return jsonify({"error": str(e)}), 400
    return jsonify({"status": status_of(pid)})

@app.get("/api/projects/<pid>/logs")
@login_required
def get_logs(pid):
    if not own_project(pid): return not_found()
    try: n = max(1000, min(200000, int(request.args.get("tail", 40000))))
    except ValueError: n = 40000
    text, size = read_tail(logp(pid), n)
    return jsonify({"text": text, "size": size, "status": status_of(pid)})

@app.post("/api/projects/<pid>/logs/clear")
@login_required
def clear_logs(pid):
    if not own_project(pid): return not_found()
    try: open(logp(pid), "wb").close()      # cắt rỗng (tiến trình đang chạy vẫn ghi tiếp được)
    except OSError: pass
    try: os.remove(logp(pid) + ".1")
    except OSError: pass
    return jsonify({"ok": True})

# ------------------------------------------------------------------ admin
@app.get("/api/admin/users")
@admin_required
def admin_users():
    users = q("SELECT id,email,name,is_admin,is_active,created,last_login FROM users ORDER BY is_active ASC, created DESC")
    projs = q("SELECT id,user_id FROM projects")
    for u in users:
        mine = [p for p in projs if p["user_id"] == u["id"]]
        u["projects"] = len(mine)
        u["running"] = sum(1 for p in mine if status_of(p["id"])["state"] == "running")
        u["storage"] = sum(dir_size(pdir(p["id"])) for p in mine)
    stats = {"users": len(users), "pending": sum(1 for u in users if not u["is_active"]), "projects": len(projs),
             "running": sum(u["running"] for u in users), "storage": sum(u["storage"] for u in users),
             "register": ALLOW_REGISTER, "auto_approve": AUTO_APPROVE, "max_running_total": MAX_RUN_TOTAL}
    return jsonify({"users": users, "stats": stats})

@app.get("/api/admin/processes")
@admin_required
def admin_processes():
    out = []
    with PLOCK: items = list(PROCS.items())
    for pid, st in items:
        p = q1("SELECT p.name, u.email FROM projects p JOIN users u ON u.id=p.user_id WHERE p.id=?", (pid,))
        if not p: continue
        out.append({"id": pid, "name": p["name"], "email": p["email"], "kind": st["kind"], "pid": st["proc"].pid,
                    "started": st["started"], "mem_mb": rss_mb(st["proc"].pid)})
    return jsonify({"processes": out})

@app.post("/api/admin/projects/<pid>/stop")
@admin_required
def admin_stop_project(pid):
    raw_exec("UPDATE projects SET run_wanted=0 WHERE id=?", (pid,))
    return jsonify({"ok": stop_process(pid)})

def target_user(uid):
    t = q1("SELECT * FROM users WHERE id=?", (uid,))
    if not t: return None, (jsonify({"error": "Không tìm thấy người dùng."}), 404)
    if t["is_admin"]: return None, (jsonify({"error": "Không thể thao tác trên tài khoản admin."}), 400)
    return t, None

@app.post("/api/admin/users/<int:uid>/active")
@admin_required
def admin_set_active(uid):
    t, err = target_user(uid)
    if err: return err
    active = 1 if json_body().get("active") else 0
    ex("UPDATE users SET is_active=?, token_ver=token_ver+1 WHERE id=?", (active, uid))
    if not active:   # khóa tài khoản: dừng hết chương trình đang chạy của người này
        for p in q("SELECT id FROM projects WHERE user_id=?", (uid,)):
            ex("UPDATE projects SET run_wanted=0 WHERE id=?", (p["id"],))
            stop_process(p["id"])
    return jsonify({"ok": True, "active": bool(active)})

@app.post("/api/admin/users/<int:uid>/password")
@admin_required
def admin_reset_password(uid):
    t, err = target_user(uid)
    if err: return err
    pw = str(json_body().get("password", ""))
    if not (8 <= len(pw) <= 128): return jsonify({"error": "Mật khẩu mới phải từ 8 đến 128 ký tự."}), 400
    ex("UPDATE users SET pw_hash=?, token_ver=token_ver+1, failed=0, locked_until=0 WHERE id=?", (generate_password_hash(pw), uid))
    return jsonify({"ok": True})

@app.delete("/api/admin/users/<int:uid>")
@admin_required
def admin_delete_user(uid):
    t, err = target_user(uid)
    if err: return err
    for p in q("SELECT id FROM projects WHERE user_id=?", (uid,)):
        destroy_project(p["id"])
    ex("DELETE FROM users WHERE id=?", (uid,))
    return jsonify({"ok": True})

@app.errorhandler(429)
def rate_limited(_):
    return jsonify({"error": "Bạn thao tác quá nhanh. Vui lòng đợi một chút rồi thử lại."}), 429

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Yêu cầu quá lớn. Giới hạn mỗi lần tải lên là 40 MB."}), 413

init_db()
os.makedirs(proj_root(), exist_ok=True)
if not os.getenv("PYHOST_NO_RESUME"):
    _t = threading.Timer(3, resume_all); _t.daemon = True; _t.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
