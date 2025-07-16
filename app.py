from flask import Flask, render_template
import json
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    alerts = []
    log_file = os.path.join("logs", "arp_logs.json")
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)
