from flask import Flask, request, jsonify, send_file
import hashlib, json, os, secrets
from werkzeug.exceptions import BadRequest
from functools import lru_cache
import threading

app = Flask(__name__)
FILE = os.getenv("PASSWORD_FILE", "passwords.json")  # configurable via env var
LOCK = threading.Lock()  # thread safety for file operations

# --- Utility functions ---
@lru_cache(maxsize=1)
def load_data():
    """Load password data with caching for speed."""
    if not os.path.exists(FILE):
        return {}
    with open(FILE, "r") as f:
        return json.load(f)

def save_data(data):
    """Save password data safely with file lock."""
    with LOCK:
        with open(FILE, "w") as f:
            json.dump(data, f, indent=4)
        load_data.cache_clear()  # clear cache after update

def hash_password(password, salt=None):
    """Salt + hash password securely."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return {"salt": salt, "hash": hashed}

# --- Routes ---
@app.route("/")
def index():
    return send_file("index.html")

@app.route("/add", methods=["POST"])
def add_password():
    try:
        data = request.get_json(force=True)
        site, username, password = data.get("site"), data.get("username"), data.get("password")

        if not site or not username or not password:
            raise BadRequest("❌ All fields are required.")

        passwords = load_data()
        passwords[site] = {"username": username, **hash_password(password)}
        save_data(passwords)

        return jsonify({"status": "success", "message": "✅ Password saved securely!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/view")
def view_password():
    site = request.args.get("site")
    passwords = load_data()
    if site in passwords:
        info = passwords[site]
        return jsonify({
            "site": site,
            "username": info["username"],
            "hashed_password": info["hash"],
            "salt": info["salt"]
        })
    return jsonify({"status": "error", "message": "❌ No data found for this site."}), 404

# --- Security & Performance Best Practices ---
# 1. Use environment variables for secrets & file paths.
# 2. Thread-safe file writes with LOCK.
# 3. Cached reads with lru_cache for speed.
# 4. Salted hashing for stronger security.
# 5. Deploy with gunicorn/uwsgi instead of Flask dev server.
# 6. Always run behind HTTPS + reverse proxy (Nginx).

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
