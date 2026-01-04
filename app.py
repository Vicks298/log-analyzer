import json
from analyzer import analyze_log

LOG_FILE = "sample_logs/auth.log"
REPORT_FILE = "reports/alert_report.json"

def main():
    alerts = analyze_log(LOG_FILE)

    report = {
        "summary": {
            "total_alerts": len(alerts),
            "status": "ALERT" if alerts else "OK"
        },
        "alerts": alerts
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    if alerts:
        print("🚨 Suspicious activity detected")
        print(f"📄 Report saved to {REPORT_FILE}")
    else:
        print("✅ No threats detected")

if __name__ == "__main__":
    main()


