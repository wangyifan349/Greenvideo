# app.py
import os
import sqlite3
import hashlib
from flask import (
    Flask, g, request, redirect, url_for, flash, session,
    send_from_directory, abort, render_template_string
)
from werkzeug.utils import secure_filename
from functools import wraps

# -------------------------
# Configuration
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'app.db')
ALLOWED_EXTENSIONS = {'mp4', 'webm', 'ogg', 'mov', 'mkv'}
# In production replace with a secure random key
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=500 * 1024 * 1024  # 500 MB
)

# -------------------------
# Database helpers
# -------------------------
def get_db():
    """Return a sqlite3.Connection for the current request context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database tables if missing."""
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        title TEXT,
        description TEXT,
        public INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    """Close DB connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_first_request
def setup_app():
    """Initialize DB before first request."""
    init_db()

# -------------------------
# Auth helpers
# -------------------------
def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def login_required(f):
    """Decorator to protect routes that require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    """Return current logged-in user row or None."""
    if 'user_id' not in session:
        return None
    db = get_db()
    cur = db.execute('SELECT id, username FROM users WHERE id = ?', (session['user_id'],))
    return cur.fetchone()

# -------------------------
# Utilities
# -------------------------
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def lcs_length(a: str, b: str) -> int:
    """Compute length of longest common subsequence (LCS) between two strings."""
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0
    prev = [0] * (lb + 1)
    for i in range(1, la + 1):
        cur = [0] * (lb + 1)
        ai = a[i - 1]
        for j in range(1, lb + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = max(prev[j], cur[j - 1])
        prev = cur
    return prev[lb]

def username_similarity_score(query: str, username: str) -> float:
    """Return a similarity score between 0 and 1 based on LCS normalized by average length."""
    if not query or not username:
        return 0.0
    lcs = lcs_length(query.lower(), username.lower())
    avg_len = (len(query) + len(username)) / 2.0
    return lcs / avg_len if avg_len > 0 else 0.0

# -------------------------
# Templates (no nesting)
# Each template is a complete HTML document; layout is reused by string formatting.
# -------------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {{
        --brand-green: #e9f7ef;
        --accent-green: #61b15a;
        --muted: #6c757d;
      }}
      body {{ background: var(--brand-green); padding-top: 70px; }}
      .navbar-brand {{ color: #fff !important; font-weight: 600; }}
      .card {{ border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.06); }}
      .btn-accent {{ background: var(--accent-green); border-color: var(--accent-green); color: #fff; }}
      .btn-accent:hover {{ background: #4f9d4a; border-color: #4f9d4a; }}
      .truncate {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
      .video-thumb {{ max-height: 160px; object-fit: cover; width: 100%; border-radius: 8px; }}
      footer {{ margin-top: 48px; padding: 24px 0; color: var(--muted); }}
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-success fixed-top">
      <div class="container-fluid">
        <a class="navbar-brand" href="{index_url}">Greenvideo</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navCollapse">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navCollapse">
          <form class="d-flex ms-3" role="search" action="{search_url}" method="get">
            <input class="form-control me-2" type="search" name="q" placeholder="Search username" value="{search_value}">
            <button class="btn btn-outline-light" type="submit">Search</button>
          </form>
          <ul class="navbar-nav ms-auto mb-2 mb-lg-0">
            {nav_items}
          </ul>
        </div>
      </div>
    </nav>

    <main class="container my-4">
      {flashes}
      {content}
    </main>

    <footer class="container text-center">
      <small>&copy; {year} Greenvideo — lightweight demo</small>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

def render_page(title: str, content_html: str, search_value: str = '') -> str:
    """Render full page by injecting nav, flashes, and content into base HTML."""
    user = get_current_user()
    if user:
        nav_items = (
            f'<li class="nav-item"><a class="nav-link" href="{url_for("upload")}">Upload</a></li>'
            f'<li class="nav-item"><a class="nav-link" href="{url_for("dashboard")}">Dashboard</a></li>'
            f'<li class="nav-item"><a class="nav-link" href="{url_for("logout")}">Logout ({user["username"]})</a></li>'
        )
    else:
        nav_items = (
            f'<li class="nav-item"><a class="nav-link" href="{url_for("login")}">Login</a></li>'
            f'<li class="nav-item"><a class="nav-link" href="{url_for("register")}">Register</a></li>'
        )

    # Render flash messages
    flashes = ''
    messages = session.pop('_flashes', []) if '_flashes' in session else []
    if messages:
        flashes = '<div class="mb-3">'
        for m in messages:
            flashes += f'<div class="alert alert-info alert-dismissible fade show" role="alert">{m}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>'
        flashes += '</div>'

    return render_template_string(
        BASE_HTML.format(
            title=title,
            index_url=url_for('index'),
            search_url=url_for('search'),
            search_value=search_value,
            nav_items=nav_items,
            flashes=flashes,
            content=content_html,
            year=2025
        )
    )

# -------------------------
# Templates: content fragments
# These are smaller HTML blocks inserted into base layout.
# -------------------------
def render_index_content(videos, search_results=None, search_query=''):
    """Main index content showing recent public videos and optional search results."""
    search_block = ''
    if search_results is not None:
        if search_results:
            items = ''.join(f'<a class="list-group-item list-group-item-action" href="{url_for("user_videos", username=name)}">{name}</a>' for name in search_results)
            search_block = f'''
            <div class="mb-3">
              <h5>Search results for "<strong>{search_query}</strong>"</h5>
              <div class="list-group">{items}</div>
            </div>
            '''
        else:
            search_block = f'<div class="mb-3"><p>No users found for "<strong>{search_query}</strong>".</p></div>'

    cards = ''
    if videos:
        cards += '<div class="row row-cols-1 row-cols-md-3 g-3">'
        for v in videos:
            title = v['title'] or v['filename']
            username = v['username']
            created = v['created_at']
            cards += f'''
            <div class="col">
              <div class="card h-100">
                <div class="card-body d-flex flex-column">
                  <h5 class="card-title truncate">{title}</h5>
                  <p class="card-text mb-2">By <a href="{url_for('user_videos', username=username)}">{username}</a></p>
                  <p class="card-text text-muted small mb-2">{created}</p>
                  <div class="mt-auto">
                    <a class="btn btn-accent btn-sm" href="{url_for('watch', video_id=v['id'])}">Watch</a>
                  </div>
                </div>
              </div>
            </div>
            '''
        cards += '</div>'
    else:
        cards = '<p>No public videos yet.</p>'

    return f'''
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h2>Recent Public Videos</h2>
    </div>
    {search_block}
    {cards}
    '''

def render_register_content():
    return '''
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card p-4">
          <h3>Register</h3>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">Username</label>
              <input class="form-control" name="username" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input type="password" class="form-control" name="password" required>
            </div>
            <button class="btn btn-accent" type="submit">Register</button>
          </form>
        </div>
      </div>
    </div>
    '''

def render_login_content():
    return '''
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card p-4">
          <h3>Login</h3>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">Username</label>
              <input class="form-control" name="username" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input type="password" class="form-control" name="password" required>
            </div>
            <button class="btn btn-accent" type="submit">Login</button>
          </form>
        </div>
      </div>
    </div>
    '''

def render_upload_content():
    return '''
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card p-4">
          <h3>Upload Video</h3>
          <form method="post" enctype="multipart/form-data">
            <div class="mb-3">
              <label class="form-label">Video file</label>
              <input class="form-control" type="file" name="video" accept="video/*" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Title</label>
              <input class="form-control" name="title">
            </div>
            <div class="mb-3">
              <label class="form-label">Description</label>
              <textarea class="form-control" name="description" rows="3"></textarea>
            </div>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="public" name="public" checked>
              <label class="form-check-label" for="public">Make public</label>
            </div>
            <button class="btn btn-accent" type="submit">Upload</button>
          </form>
        </div>
      </div>
    </div>
    '''

def render_dashboard_content(videos):
    if not videos:
        return '<p>No videos uploaded yet.</p>'
    items = ''
    for v in videos:
        title = v['title'] or v['filename']
        desc = (v['description'] or '')[:120]
        created = v['created_at']
        public = 'Public' if v['public'] == 1 else 'Hidden'
        items += f'''
        <div class="card mb-3">
          <div class="card-body d-flex justify-content-between align-items-start">
            <div>
              <h5 class="card-title">{title}</h5>
              <p class="card-text small text-muted">Uploaded: {created} • {public}</p>
              <p class="card-text truncate">{desc}</p>
            </div>
            <div class="text-end">
              <a class="btn btn-primary btn-sm mb-2" href="{url_for('watch', video_id=v['id'])}">Watch</a>
              <form method="post" action="{url_for('manage', video_id=v['id'])}">
                <input type="hidden" name="action" value="toggle">
                <button class="btn btn-secondary btn-sm mb-2" type="submit">{'Make Hidden' if v['public'] == 1 else 'Make Public'}</button>
              </form>
              <form method="post" action="{url_for('manage', video_id=v['id'])}" onsubmit="return confirm('Delete this video?');">
                <input type="hidden" name="action" value="delete">
                <button class="btn btn-danger btn-sm" type="submit">Delete</button>
              </form>
            </div>
          </div>
        </div>
        '''
    return f'''
    <h3>Your Videos</h3>
    {items}
    '''

def render_user_videos_content(profile, videos):
    if videos:
        cards = '<div class="row row-cols-1 row-cols-md-3 g-3">'
        for v in videos:
            title = v['title'] or v['filename']
            created = v['created_at']
            cards += f'''
            <div class="col">
              <div class="card h-100">
                <div class="card-body d-flex flex-column">
                  <h5 class="card-title truncate">{title}</h5>
                  <p class="card-text text-muted small mb-2">{created}</p>
                  <div class="mt-auto">
                    <a class="btn btn-accent btn-sm" href="{url_for('watch', video_id=v['id'])}">Watch</a>
                  </div>
                </div>
              </div>
            </div>
            '''
        cards += '</div>'
    else:
        cards = '<p>No public videos from this user.</p>'

    return f'''
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h2>Videos by {profile["username"]}</h2>
    </div>
    {cards}
    '''

def render_watch_content(video):
    title = video['title'] or video['filename']
    desc = video['description'] or ''
    uploaded = video['created_at']
    public = 'Public' if video['public'] == 1 else 'Hidden'
    username = video['username']
    return f'''
    <div class="row">
      <div class="col-md-8">
        <div class="card p-3 mb-3">
          <h3>{title}</h3>
          <p class="text-muted">By <a href="{url_for('user_videos', username=username)}">{username}</a></p>
          <video class="w-100" controls>
            <source src="{url_for('uploaded_file', filename=video['filename'])}">
            Your browser does not support the video tag.
          </video>
          <p class="mt-3">{desc}</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card p-3">
          <p class="mb-1"><strong>Filename:</strong> {video['filename']}</p>
          <p class="mb-1"><strong>Uploaded:</strong> {uploaded}</p>
          <p class="mb-1"><strong>Visibility:</strong> {public}</p>
        </div>
      </div>
    </div>
    '''

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    """Show recent public videos on homepage."""
    db = get_db()
    cur = db.execute('SELECT v.*, u.username FROM videos v JOIN users u ON v.user_id = u.id WHERE v.public = 1 ORDER BY v.created_at DESC LIMIT 12')
    videos = cur.fetchall()
    content = render_index_content(videos)
    return render_page('Home - Greenvideo', content)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if not username or not password:
            session.setdefault('_flashes', []).append('Username and password required')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_password(password)))
            db.commit()
            session.setdefault('_flashes', []).append('Registered successfully, please login')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            session.setdefault('_flashes', []).append('Username already exists')
            return redirect(url_for('register'))
    content = render_register_content()
    return render_page('Register - Greenvideo', content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        db = get_db()
        cur = db.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if row and row['password_hash'] == hash_password(password):
            session['user_id'] = row['id']
            session.setdefault('_flashes', []).append('Login successful')
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        session.setdefault('_flashes', []).append('Invalid username or password')
        return redirect(url_for('login'))
    content = render_login_content()
    return render_page('Login - Greenvideo', content)

@app.route('/logout')
def logout():
    """Log out current user."""
    session.pop('user_id', None)
    session.setdefault('_flashes', []).append('Logged out')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload a video file and create a DB entry."""
    if request.method == 'POST':
        if 'video' not in request.files:
            session.setdefault('_flashes', []).append('No file part')
            return redirect(url_for('upload'))
        file = request.files['video']
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        public_flag = 1 if request.form.get('public') == 'on' or request.form.get('public') else 0
        if file.filename == '':
            session.setdefault('_flashes', []).append('No selected file')
            return redirect(url_for('upload'))
        if not allowed_file(file.filename):
            session.setdefault('_flashes', []).append('Unsupported file type')
            return redirect(url_for('upload'))
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        final_filename = filename
        counter = 1
        while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], final_filename)):
            final_filename = f"{base}_{counter}{ext}"
            counter += 1
        path = os.path.join(app.config['UPLOAD_FOLDER'], final_filename)
        file.save(path)
        db = get_db()
        db.execute('INSERT INTO videos (user_id, filename, title, description, public) VALUES (?, ?, ?, ?, ?)',
                   (session['user_id'], final_filename, title, description, public_flag))
        db.commit()
        session.setdefault('_flashes', []).append('Upload successful')
        return redirect(url_for('dashboard'))
    content = render_upload_content()
    return render_page('Upload - Greenvideo', content)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded video file, enforcing visibility checks."""
    db = get_db()
    cur = db.execute('SELECT v.*, u.username FROM videos v JOIN users u ON v.user_id = u.id WHERE v.filename = ?', (filename,))
    row = cur.fetchone()
    if not row:
        abort(404)
    if row['public'] == 0:
        user = get_current_user()
        if not user or user['username'] != row['username']:
            abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/dashboard')
@login_required
def dashboard():
    """Show current user's videos and management actions."""
    user = get_current_user()
    db = get_db()
    cur = db.execute('SELECT * FROM videos WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    videos = cur.fetchall()
    content = render_dashboard_content(videos)
    return render_page('Dashboard - Greenvideo', content)

@app.route('/manage/<int:video_id>', methods=['POST'])
@login_required
def manage(video_id):
    """Manage a video: toggle public/hidden or delete (owner-only)."""
    action = request.form.get('action')
    db = get_db()
    cur = db.execute('SELECT * FROM videos WHERE id = ?', (video_id,))
    vid = cur.fetchone()
    if not vid:
        session.setdefault('_flashes', []).append('Video not found')
        return redirect(url_for('dashboard'))
    if vid['user_id'] != session['user_id']:
        abort(403)
    if action == 'delete':
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], vid['filename']))
        except OSError:
            pass
        db.execute('DELETE FROM videos WHERE id = ?', (video_id,))
        db.commit()
        session.setdefault('_flashes', []).append('Deleted')
    elif action == 'toggle':
        new_public = 0 if vid['public'] == 1 else 1
        db.execute('UPDATE videos SET public = ? WHERE id = ?', (new_public, video_id))
        db.commit()
        session.setdefault('_flashes', []).append('Visibility updated')
    return redirect(url_for('dashboard'))

@app.route('/user/<username>')
def user_videos(username):
    """Display public videos for a given username."""
    db = get_db()
    cur = db.execute('SELECT id, username FROM users WHERE username = ?', (username,))
    user_row = cur.fetchone()
    if not user_row:
        abort(404)
    cur = db.execute('SELECT * FROM videos WHERE user_id = ? AND public = 1 ORDER BY created_at DESC', (user_row['id'],))
    videos = cur.fetchall()
    content = render_user_videos_content(user_row, videos)
    return render_page(f"{user_row['username']} - Greenvideo", content)

@app.route('/search')
def search():
    """Search users by username similarity and show results in descending order."""
    q = (request.args.get('q') or '').strip()
    if not q:
        return redirect(url_for('index'))
    db = get_db()
    cur = db.execute('SELECT id, username FROM users')
    all_users = cur.fetchall()
    scored = []
    for u in all_users:
        score = username_similarity_score(q, u['username'])
        if score > 0:
            scored.append((score, u['username']))
    scored.sort(key=lambda x: x[0], reverse=True)  # descending by similarity
    results = [name for _, name in scored[:50]]
    # recent public videos
    cur = db.execute('SELECT v.*, u.username FROM videos v JOIN users u ON v.user_id = u.id WHERE v.public = 1 ORDER BY v.created_at DESC LIMIT 12')
    videos = cur.fetchall()
    content = render_index_content(videos, search_results=results, search_query=q)
    return render_page(f"Search - {q}", content, search_value=q)

@app.route('/watch/<int:video_id>')
def watch(video_id):
    """Watch page for a single video with visibility enforcement."""
    db = get_db()
    cur = db.execute('SELECT v.*, u.username FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = ?', (video_id,))
    vid = cur.fetchone()
    if not vid:
        abort(404)
    if vid['public'] == 0:
        user = get_current_user()
        if not user or user['username'] != vid['username']:
            abort(403)
    content = render_watch_content(vid)
    return render_page(f"{vid['title'] or vid['filename']} - Greenvideo", content)

# -------------------------
# Run
# -------------------------
if __name__ == '__main__':
    app.run(debug=True)
