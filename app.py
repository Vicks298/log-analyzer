from flask import Flask, render_template, request
from analyzer import analyze_log, generate_incident_report
import os
import json

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["logfile"]
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        alerts = analyze_log(file_path)

        incident_report = generate_incident_report(alerts)

        report_path = os.path.join(
            REPORT_FOLDER,
            f"{incident_report['incident_id']}.json"
        )

        with open(report_path, "w") as f:
            json.dump(incident_report, f, indent=4)

        return render_template(
            "results.html",
            alerts=alerts,
            report=incident_report
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)



