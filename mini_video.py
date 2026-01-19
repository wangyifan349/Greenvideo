"""
Mini Video Platform - Flask + SQLite3 + Inline HTML/CSS

This program implements a minimal YouTube/Bilibili-like video platform,
using the Flask web framework and SQLite3 for storing user accounts.
All HTML, CSS, and JavaScript are inline in this file.

Main Features:

- User registration, login, logout, and password change. 
  Passwords are securely hashed and stored in an SQLite3 table.
- Each registered user has a directory under ./static/<username>/.
  All their uploaded .mp4 videos are stored in their directory.
  The system does NOT store video metadata in the database.
- Videos are displayed by scanning the file system when needed.
  The index page shows the latest videos (newest file mtime).
  Channel pages show all videos for a user (by filesystem scan).
- Only .mp4 uploads are allowed, with up to 1GB per upload.
- Each user can upload and delete their own videos.
  Deletion is only allowed for the owner of the file.
- Search page for fuzzy matching (case-insensitive substring search) of usernames,
  with results ordered by username (descending).
- User interface is based on Bootstrap 5 with a gold color theme,
  included inline in a <style> tag.
- All variables and functions use descriptive (natural English) names.
- Code is heavily commented for clarity and review.

Directory Structure:

  project/
    |-- mini_video.py
    |-- static/
          |-- <username1>/
          |     |-- video1.mp4, ...
          |-- <username2>/
          |     |-- video2.mp4, ...
          ...

To set up and run:
    1. Save this script as mini_video.py.
    2. Create a writable empty folder named 'static' in the same location.
    3. Install dependencies: pip install Flask Werkzeug
    4. Run: python mini_video.py
    5. Browse to http://127.0.0.1:5000/

Note: This program is intended for study and demo only. It lacks advanced 
security and should not be public-facing or used for production.
"""

import os                                 # For directory and file management
from pathlib import Path                  # Safer file path management than string methods
import sqlite3                            # For user database management
from flask import (Flask, render_template_string, request, redirect, url_for, flash,
                   session, abort)        # Main Flask imports
from werkzeug.security import generate_password_hash, check_password_hash # Safe password handling
from werkzeug.utils import secure_filename # Prevents dangerous filenames (e.g. "../../../...")

# ---- Configuration constants ----
ALLOWED_EXTENSIONS = {'.mp4'}             # Only allow .mp4 uploads
MAX_CONTENT_LENGTH = 1_000_000_000        # 1 GB upload limit

BASE_DIRECTORY = Path(__file__).resolve().parent    # Directory of the script
DATABASE_PATH = BASE_DIRECTORY / "users.sqlite3"    # Location of the database file

# Initialize Flask app and configuration
app = Flask(__name__, static_folder="static")    # static_folder holds all user files
app.config['SECRET_KEY'] = 'REPLACE_THIS_WITH_RANDOM' # Needed for session handling, set random in production
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH # Flask will reject uploads larger than this

# ---- DATABASE SETUP AND UTILITIES ----
def get_database():
    """Connect to the SQLite3 user database and return a connection object."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row         # Rows will allow column access by key
    return conn

def initialize_database():
    """Set up the users table. If it already exists, does nothing."""
    with get_database() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,   -- Primary key, auto increments
            username TEXT UNIQUE NOT NULL,          -- Username, must be unique
            password_hash TEXT NOT NULL             -- Hashed user password
        )''') # This SQL creates the table if needed
        db.commit()  # Save changes

initialize_database()    # Ensure database and table present on startup

# ---- AUTHENTICATION HELPERS ----
from functools import wraps
def login_required(view_function):
    """Decorator: Only allow logged-in users to access the route."""
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:                  # User must have logged in; "user_id" is set at login
            flash("Please log in.", "warning")        # Flash message for UI
            return redirect(url_for('login'))         # Redirect to login form
        return view_function(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Return the row for the currently logged-in user, or None if no login."""
    if "user_id" in session:
        with get_database() as db:
            user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone() # SQL: returns user's row by id
            return user
    return None

# ---- VIDEO FILE MANAGEMENT HELPERS ----
def get_user_video_filenames(username):
    """
    Return all .mp4 video filenames for the specified user.
    Scan ./static/<username> folder, sorted by mtime descending.
    """
    user_directory = Path(app.static_folder) / username
    if not user_directory.exists():
        return []
    video_files = [
        file_path.name
        for file_path in user_directory.iterdir()
        if file_path.is_file() and file_path.suffix.lower() in ALLOWED_EXTENSIONS  # Only .mp4
    ]
    # Sort by last modification time (newest first)
    video_files = sorted(
        video_files,
        key=lambda filename: (user_directory / filename).stat().st_mtime,
        reverse=True
    )
    return video_files

def get_all_latest_videos(limit=18):
    """
    Aggregate (username, filename, modified_time) dictionaries for all .mp4 user files.
    Sort by modified_time (newest first), then return up to 'limit' items.
    """
    all_videos = []
    static_directory = Path(app.static_folder)
    if static_directory.exists():
        for username in os.listdir(static_directory):
            user_dir = static_directory / username
            if user_dir.is_dir():
                for file_name in get_user_video_filenames(username):
                    file_path = user_dir / file_name
                    all_videos.append({
                        'username': username,                              # Owner's user name
                        'filename': file_name,                             # .mp4 file name
                        'modified_time': file_path.stat().st_mtime         # Unix time, for sorting
                    })
    # Sort for latest uploads first
    return sorted(all_videos, key=lambda v: v['modified_time'], reverse=True)[:limit]

# ---- HTML BASE FOR ALL PAGES (inline, not external) ----
HTML_BASE = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title or "Mini-Video" }}</title>
    <!-- Bootstrap 5 from CDN (UI framework) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
    :root {
        --bs-warning: #d4af37;           /* "Gold" color for Bootstrap's 'warning' palette */
        --bs-warning-rgb: 212,175,55;
    }
    .bg-black { background: #000 !important; }
    </style>
    {%- block headextra %}{% endblock %}
</head>
<body class="bg-dark text-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-black border-bottom border-warning">
  <div class="container-fluid">
    <a class="navbar-brand text-warning" href="{{ url_for('index') }}">Mini-Video</a>
    <form class="d-flex" action="{{ url_for('search') }}" method="get">
      <input class="form-control me-2" name="query" placeholder="Search username">
    </form>
    <ul class="navbar-nav ms-auto mb-2 mb-lg-0">
      {% if user %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('upload') }}">Upload</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('channel', username=user['username']) }}">{{ user['username'] }}</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
      {% else %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
      {% endif %}
    </ul>
  </div>
</nav>
<div class="container py-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
      <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
        {{ message }}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    {% endfor %}
  {% endwith %}
  {%- block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>
{%- block scripts %}{% endblock %}
</body>
</html>
'''

# --------------------- ROUTES / MAIN LOGIC ---------------------

@app.route('/')
def index():
    """
    Homepage: show a grid of the latest uploaded videos from all users,
    sorted newest first.
    """
    video_list = get_all_latest_videos()      # Get all latest 18 videos (see helper above)
    user = get_current_user()                 # Current login, or None
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="mb-3 text-warning">Latest uploads</h3>
<div class="row row-cols-1 row-cols-md-3 g-4">
{% for video in video_list %}
  <div class="col">
    <div class="card bg-secondary h-100">
      <!-- Show the video with a poster (first frame preview), plays muted -->
      <video class="card-img-top" src="{{ url_for('static', filename=video.username ~ '/' ~ video.filename) }}#t=1"
             style="object-fit: cover" muted></video>
      <div class="card-body">
        <h5 class="card-title text-truncate">{{ video.filename }}</h5>
        <p class="card-text"><a href="{{ url_for('channel', username=video.username) }}" class="text-warning">{{ video.username }}</a></p>
      </div>
    </div>
  </div>
{% endfor %}
</div>
{% endblock %}
        ''',
        title="Mini-Video",
        video_list=video_list, user=user
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Register a new user account using username/password.  
    Creates user's directory on disk if successful.
    """
    if request.method == 'POST':
        username = request.form['username'].strip()          # Input username (whitespace removed)
        password = request.form['password']                  # Input password
        if not username or not password:
            flash("All fields are required.", "danger")      # Validation: must fill all
        else:
            try:
                with get_database() as db:
                    db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",    # SQL: add user row
                               (username, generate_password_hash(password)))                   # Hash password!
                    db.commit()                                                               # Save to DB
                Path(app.static_folder, username).mkdir(parents=True, exist_ok=True)           # Make folder for user videos
                flash("Registered! Please log in.", "success")
                return redirect(url_for('login'))                                              # Redirect after registration
            except sqlite3.IntegrityError:            # Username already exists (unique index)
                flash("Username already taken.", "danger")
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">Register</h3>
<form method="POST">
  <div class="mb-3">
    <input class="form-control" name="username" placeholder="Username">
  </div>
  <div class="mb-3">
    <input class="form-control" name="password" type="password" placeholder="Password">
  </div>
  <button class="btn btn-warning">Register</button>
</form>
{% endblock %}
        ''',
        title="Register",
        user=get_current_user()
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Log in an existing user. Passwords are checked against the hash.
    On successful login, session['user_id'] is set.
    """
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        with get_database() as db:
            user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()   # SQL: find by username
            if user_row and check_password_hash(user_row['password_hash'], password):                 # Verify password
                session['user_id'] = user_row['id']                                                   # Set session cookie
                flash("Logged in!", "success")
                return redirect(url_for('index'))
        flash("Invalid username or password.", "danger")
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">Login</h3>
<form method="POST">
  <div class="mb-3">
    <input class="form-control" name="username" placeholder="Username">
  </div>
  <div class="mb-3">
    <input class="form-control" name="password" type="password" placeholder="Password">
  </div>
  <button class="btn btn-warning">Login</button>
</form>
{% endblock %}
        ''',
        title="Login",
        user=get_current_user()
    )

@app.route('/logout')
def logout():
    """Clears the session, thus logging out the current user."""
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Allows the currently logged-in user to change their password.
    Old password must be verified.
    """
    if request.method == 'POST':
        old_password = request.form['old_password']                 # Existing password (input)
        new_password = request.form['new_password']                 # Desired new password (input)
        user = get_current_user()
        if not check_password_hash(user['password_hash'], old_password):   # Right side: compares hashes
            flash('Old password is incorrect.', 'danger')
        elif len(new_password) < 4:
            flash('Password too short.', 'danger')
        else:
            with get_database() as db:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",     # SQL: update with hash
                           (generate_password_hash(new_password), user['id']))
                db.commit()
            flash('Password changed.', 'success')
            return redirect(url_for('index'))
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">Change Password</h3>
<form method="POST">
  <div class="mb-3">
    <input class="form-control" name="old_password" placeholder="Current password" type="password">
  </div>
  <div class="mb-3">
    <input class="form-control" name="new_password" placeholder="New password" type="password">
  </div>
  <button class="btn btn-warning">Change</button>
</form>
{% endblock %}
        ''',
        title="Change Password",
        user=get_current_user()
    )

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """
    Allows authenticated user to upload a new .mp4 file to their channel.
    Only .mp4 allowed; files are stored as static/<username>/<filename>.
    """
    if request.method == 'POST':
        uploaded_file = request.files.get('file')                       # Get uploaded file (from form)
        if not uploaded_file or uploaded_file.filename == '':
            flash("No file selected.", "danger")
            return redirect(request.url)
        if Path(uploaded_file.filename).suffix.lower() not in ALLOWED_EXTENSIONS:
            flash("Only mp4 files are allowed.", "danger")
            return redirect(request.url)
        file_name = secure_filename(uploaded_file.filename)            # Clean filename (no path traversal etc)
        current_username = get_current_user()['username']
        user_directory = Path(app.static_folder) / current_username
        user_directory.mkdir(exist_ok=True)
        save_path = user_directory / file_name
        # If file already exists, add Unix timestamp at front to avoid replacing existing
        if save_path.exists():
            import time
            file_name = f"{int(time.time())}_{file_name}"              # Prefix with timestamp if needed
            save_path = user_directory / file_name
        uploaded_file.save(save_path)                                  # Save binary to disk
        flash("Upload successful.", "success")
        return redirect(url_for("channel", username=current_username))
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">Upload video</h3>
<form method="POST" enctype="multipart/form-data">
  <div class="mb-3">
    <input class="form-control" type="file" name="file" accept=".mp4">
  </div>
  <button class="btn btn-warning">Upload</button>
</form>
{% endblock %}
        ''',
        title="Upload Video",
        user=get_current_user()
    )

@app.route('/user/<username>')
def channel(username):
    """
    Main channel page for a specific user.
    Lists all their .mp4 files (from filesystem).
    If the logged-in user is the owner, shows delete buttons and password change link.
    """
    with get_database() as db:
        owner = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()  # Get owner's row
    if not owner:
        flash("No such user.", "danger")
        return redirect(url_for('index'))
    user = get_current_user()
    file_names = get_user_video_filenames(username)
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">{{ owner.username }}'s channel</h3>
{% if user and user.id == owner.id %}
  <a class="btn btn-outline-warning btn-sm mb-3" href="{{ url_for('change_password') }}">Change password</a>
{% endif %}
<div class="row row-cols-1 row-cols-md-3 g-4">
  {% for file_name in file_names %}
    <div class="col">
      <div class="card bg-secondary h-100">
        <video class="card-img-top" src="{{ url_for('static', filename=owner.username ~ '/' ~ file_name) }}#t=1" muted style="object-fit: cover"></video>
        <div class="card-body">
          <h5 class="card-title text-truncate">{{ file_name }}</h5>
        </div>
        {% if user and user.id == owner.id %}
          <!-- Only owner sees delete buttons for their videos -->
          <form class="card-footer p-0" action="{{ url_for('delete_video', username=owner.username, filename=file_name) }}" method="POST"
                onsubmit="return confirm('Delete video?');">
            <button class="btn btn-sm btn-danger w-100">Delete</button>
          </form>
        {% endif %}
      </div>
    </div>
  {% endfor %}
</div>
{% endblock %}
        ''',
        title=username + " channel",
        owner=owner,
        user=user,
        file_names=file_names
    )

@app.route('/delete/<username>/<filename>', methods=['POST'])
@login_required
def delete_video(username, filename):
    """
    File deletion route: removes the specified video from disk if the user owns it.
    """
    user = get_current_user()
    if user['username'] != username:
        abort(403)                        # Only the channel owner is allowed
    file_path = Path(app.static_folder) / username / filename
    if file_path.exists() and file_path.is_file():
        file_path.unlink()                # Remove video from file system
        flash("Video deleted.", "success")
    else:
        flash("Video not found.", "danger")
    return redirect(url_for('channel', username=username))

@app.route('/search')
def search():
    """
    Fuzzy search for usernames (case-insensitive, descending order).
    Uses SQL LIKE with wildcards for substring match.
    """
    query = request.args.get('query','').strip()
    users_found = []
    if query:
        with get_database() as db:
            like_pattern = f"%{query}%"
            users_found = db.execute(
                "SELECT * FROM users WHERE username LIKE ? COLLATE NOCASE ORDER BY username DESC",   # Fuzzy match, case-insensitive, descending order
                (like_pattern,)
            ).fetchall()
    return render_template_string(
        HTML_BASE + '''
{% block content %}
<h3 class="text-warning">Search: "{{ query }}"</h3>
{% if users_found %}
  <ul class="list-group">
    {% for user_row in users_found %}
      <li class="list-group-item bg-dark"><a class="text-warning" href="{{ url_for('channel', username=user_row.username) }}">{{ user_row.username }}</a></li>
    {% endfor %}
  </ul>
{% elif query %}
  <p>No users found.</p>
{% endif %}
{% endblock %}
        ''',
        title="User Search",
        query=query,
        users_found=users_found,
        user=get_current_user()
    )

# ---- Start the web server ----
if __name__ == '__main__':
    app.run(debug=True)   # Enables debug mode for development (remove debug=True for production)
