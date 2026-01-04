from flask import Flask, render_template, request
from analyzer import analyze_log
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["logfile"]
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        alerts = analyze_log(file_path)
        return render_template("results.html", alerts=alerts)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)


