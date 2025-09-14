# README — Greenvideo

Greenvideo is a minimal single-file Flask app (app.py) for self-hosted video sharing. Users can register/login, upload videos (mp4/webm/ogg/mov/mkv up to 500MB), mark videos public or hidden, manage their videos (toggle visibility, delete), and search other users by username with an LCS-based similarity ranking. Public videos are viewable on user pages. The app stores files in ./uploads and metadata in app.db (SQLite).

## Quick run (very simple) 🚀

1. Clone the repo:
   ```
   git clone https://github.com/wangyifan349/greenvideo.git
   ```
2. Change into the project directory:
   ```
   cd greenvideo
   ```
3. Create a virtual environment and activate it:
   ```
   python -m venv venv && source venv/bin/activate
   ```
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Ensure uploads folder exists (the app will create it automatically if missing):
   ```
   mkdir -p uploads
   ```
6. Run the app:
   ```
   python app.py
   ```
7. Open http://127.0.0.1:5000 in your browser 🎉

---

## File overview 📁

- `app.py` — main single-file Flask application (routes, DB init, templates rendered as strings, video upload/serve logic, user auth). Edit `SECRET_KEY` in environment for production.  
- `uploads/` — directory where uploaded video files are saved.  
- `app.db` — SQLite database created on first run, stores users and videos.

---

## License (AGPL-3.0) 📜

This project is released under the GNU Affero General Public License v3.0. See LICENSE file or https://www.gnu.org/licenses/.

Author: github.com/wangyifan349 💚
