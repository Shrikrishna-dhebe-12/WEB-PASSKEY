from flask import Flask, request, jsonify, send_file
import hashlib, json, os

app = Flask(__name__)
FILE = "passwords.json"

# Load and save
def load_data():
    if not os.path.exists(FILE):
        return {}
    with open(FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Serve HTML
@app.route("/")
def index():
    return send_file("index.html")

# Add password
@app.route("/add", methods=["POST"])
def add_password():
    data = request.get_json()
    site = data.get("site")
    username = data.get("username")
    password = data.get("password")

    if not site or not username or not password:
        return "❌ All fields are required."

    passwords = load_data()
    passwords[site] = {"username": username, "password": hash_password(password)}
    save_data(passwords)
    return "✅ Password saved successfully!"

# View password
@app.route("/view")
def view_password():
    site = request.args.get("site")
    passwords = load_data()
    if site in passwords:
        info = passwords[site]
        return f"Site: {site}\nUsername: {info['username']}\nHashed Password: {info['password']}"
    return "❌ No data found for this site."

if __name__ == "__main__":
    app.run(debug=True)