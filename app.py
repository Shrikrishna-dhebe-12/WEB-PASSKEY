from flask import Flask, request, jsonify, send_file
import hashlib, json, os, secrets, time
from werkzeug.exceptions import BadRequest
from tqdm import tqdm  # for animation

app = Flask(__name__)
FILE = "passwords.json"

# --- Utility functions ---
def load_data():
    if not os.path.exists(FILE):
        return {}
    with open(FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)  # unique salt per password
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return {"salt": salt, "hash": hashed}

def animate_action(action="Processing"):
    for _ in tqdm(range(30), desc=action, ncols=70, ascii=True):
        time.sleep(0.02)

# --- Routes ---
@app.route("/")
def index():
    return send_file("index.html")

@app.route("/add", methods=["POST"])
def add_password():
    try:
        data = request.get_json(force=True)
        site = data.get("site")
        username = data.get("username")
        password = data.get("password")

        if not site or not username or not password:
            raise BadRequest("❌ All fields are required.")

        animate_action("🔒 Saving Password")  # animation

        passwords = load_data()
        passwords[site] = {
            "username": username,
            **hash_password(password)
        }
        save_data(passwords)
        return jsonify({"status": "success", "message": "✅ Password saved securely!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/view")
def view_password():
    site = request.args.get("site")
    animate_action("🔍 Fetching Data")  # animation
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

# --- Security best practices ---
# 1. Always use HTTPS in production.
# 2. Store secrets (like FILE path) in environment variables.
# 3. Consider encrypting the JSON file with a master key.
# 4. Use proper authentication before allowing add/view routes.
# 5. Deploy behind a reverse proxy (e.g., Nginx) with rate limiting.

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
