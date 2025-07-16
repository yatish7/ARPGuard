from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "arp_logs.json")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

@app.route("/")
def dashboard():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []
    except Exception as e:
        print(f"[ERROR] Failed to read logs: {e}")
        logs = []

    return render_template("dashboard.html", logs=logs)

@app.route("/api/upload", methods=["POST"])
def upload_alert():
    try:
        data = request.get_json()

        if not all(k in data for k in ("timestamp", "mac", "ips")):
            return jsonify({"error": "Invalid alert format"}), 400

        # Load existing logs or initialize
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []

        # Append and save
        logs.append(data)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)

        return jsonify({"message": "Alert uploaded successfully"}), 200

    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
