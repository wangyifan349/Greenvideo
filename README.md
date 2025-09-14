README — Greenvideo
===================

Greenvideo is a minimal single-file Flask app (app.py) for self-hosted video sharing. Users can register/login, upload videos (mp4/webm/ogg/mov/mkv up to 500MB), mark videos public or hidden, manage their videos (toggle visibility, delete), and search other users by username with an LCS-based similarity ranking. Public videos are viewable on user pages. The app stores files in ./uploads and metadata in app.db (SQLite).

Quick run (very simple) 🚀

1. Clone: git clone https://github.com/wangyifan349/greenvideo.git


cd greenvideo  

4. Create venv & install: python -m venv venv && source venv/bin/activate


pip install -r requirements.txt


6. Ensure uploads folder exists (app will create it automatically): mkdir -p uploads  
7. Run: python app.py  
8. Open http://127.0.0.1:5000 in your browser 🎉

File overview 📁
- app.py — main single-file Flask application (routes, DB init, templates rendered as strings, video upload/serve logic, user auth). Edit SECRET_KEY in environment for production.  
- uploads/ — directory where uploaded video files are saved.  
- app.db — SQLite database created on first run, stores users and videos.

Security & production notes ⚠️
This is a demo. For production: set a strong SECRET_KEY, run behind HTTPS, implement stricter file validation and virus scanning, consider external storage (S3), use proper session/cookie settings, and harden DB/permissions.

License (AGPL-3.0) 📜
This project is released under the GNU Affero General Public License v3.0. See LICENSE file or https://www.gnu.org/licenses/.

Author
github.com/wangyifan349 💚
