from flask import Flask, request, jsonify, send_file
from werkzeug.exceptions import BadRequest

import hashlib
import json
import os
import secrets
import threading
from functools import lru_cache

app = Flask(__name__)

PASSWORD_FILE = os.getenv(
    "PASSWORD_FILE",
    "passwords.json"
)

LOCK = threading.Lock()


@lru_cache(maxsize=1)
def load_data():
    if not os.path.isfile(PASSWORD_FILE):
        return {}

    with open(
        PASSWORD_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def save_data(data):
    with LOCK:
        with open(
            PASSWORD_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                data,
                file,
                indent=2
            )

    load_data.cache_clear()


def hash_password(password: str, salt: str = None) -> dict:
    salt = salt or secrets.token_hex(16)

    return {
        "salt": salt,
        "hash": hashlib.sha256(
            f"{salt}{password}".encode()
        ).hexdigest()
    }


@app.get("/")
def index():
    return send_file("index.html")


@app.post("/add")
def add_password():
    try:
        payload = request.get_json(force=True)

        site = str(
            payload.get("site", "")
        ).strip().lower()

        username = str(
            payload.get("username", "")
        ).strip()

        password = str(
            payload.get("password", "")
        ).strip()

        if not all(
            (site, username, password)
        ):
            raise BadRequest(
                "All fields are required."
            )

        passwords = load_data()

        passwords[site] = {
            "username": username,
            **hash_password(password)
        }

        save_data(passwords)

        return jsonify(
            status="success",
            message="Password saved securely."
        )

    except Exception as error:
        return jsonify(
            status="error",
            message=str(error)
        ), 400


@app.get("/view")
def view_password():
    site = (
        request.args.get(
            "site",
            ""
        )
        .strip()
        .lower()
    )

    if not site:
        return jsonify(
            status="error",
            message="Site parameter is required."
        ), 400

    passwords = load_data()

    info = passwords.get(site)

    if not info:
        return jsonify(
            status="error",
            message="No data found for this site."
        ), 404

    return jsonify(
        site=site,
        username=info["username"],
        hashed_password=info["hash"],
        salt=info["salt"]
    )


@app.get("/sites")
def list_sites():
    return jsonify(
        sites=sorted(
            load_data().keys()
        )
    )


@app.delete("/delete")
def delete_password():
    site = (
        request.args.get(
            "site",
            ""
        )
        .strip()
        .lower()
    )

    if not site:
        return jsonify(
            status="error",
            message="Site parameter is required."
        ), 400

    passwords = load_data()

    if site not in passwords:
        return jsonify(
            status="error",
            message="Site not found."
        ), 404

    del passwords[site]

    save_data(passwords)

    return jsonify(
        status="success",
        message="Password deleted successfully."
    )


if __name__ == "__main__":
    app.run(
        debug=False,
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        ),
        threaded=True
    )
