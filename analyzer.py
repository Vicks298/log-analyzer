import re
import uuid
import json
import os
from datetime import datetime
from rules import (
    FAILED_LOGIN_THRESHOLD_LOW,
    FAILED_LOGIN_THRESHOLD_MEDIUM,
    FAILED_LOGIN_THRESHOLD_HIGH,
    MITRE_ATTACK_MAPPING
)

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def determine_severity(count):
    if count >= FAILED_LOGIN_THRESHOLD_HIGH:
        return "HIGH"
    elif count >= FAILED_LOGIN_THRESHOLD_MEDIUM:
        return "MEDIUM"
    elif count >= FAILED_LOGIN_THRESHOLD_LOW:
        return "LOW"
    return None


def analyze_log(file_path):
    failed_attempts = {}

    with open(file_path, "r") as log_file:
        for line in log_file:
            match = re.search(
                r"(\w+\s+\d+\s[\d:]+).*Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)",
                line
            )

            if match:
                timestamp, user, ip = match.groups()
                key = (ip, user)

                if key not in failed_attempts:
                    failed_attempts[key] = {
                        "count": 0,
                        "timestamps": []
                    }

                failed_attempts[key]["count"] += 1
                failed_attempts[key]["timestamps"].append(timestamp)

    alerts = []

    for (ip, user), data in failed_attempts.items():
        severity = determine_severity(data["count"])

        if severity:
            attack_type = "Possible Brute Force"
            mitre = MITRE_ATTACK_MAPPING.get(attack_type, {})

            alerts.append({
                "ip": ip,
                "user": user,
                "failed_attempts": data["count"],
                "timestamps": data["timestamps"],
                "severity": severity,
                "attack_type": attack_type,
                "mitre": mitre
            })

    return alerts


def generate_incident_report(alerts):
    incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    failed_logins = sum(a["failed_attempts"] for a in alerts)
    suspicious_ips = list({a["ip"] for a in alerts})

    severity = "LOW"
    if alerts:
        severity = max(
            [a["severity"] for a in alerts],
            key=lambda x: ["LOW", "MEDIUM", "HIGH"].index(x)
        )

    attack_type = alerts[0]["attack_type"] if alerts else "N/A"
    mitre = MITRE_ATTACK_MAPPING.get(attack_type, {})

    report = {
        "incident_id": incident_id,
        "generated_at": timestamp,
        "severity": severity,

        "mitre_attack": mitre,

        "executive_summary": (
            f"{failed_logins} failed login attempts detected. "
            f"Activity classified as {severity} severity."
        ),

        "ioc_table": [
            {
                "ip": a["ip"],
                "user": a["user"],
                "failed_attempts": a["failed_attempts"]
            } for a in alerts
        ],

        "mitigation_strategy": [
            "Block offending IP addresses",
            "Apply rate limiting on authentication endpoints",
            "Enforce strong password policies",
            "Enable multi-factor authentication (MFA)",
            "Continue monitoring authentication logs"
        ]
    }

    # Save SOC-style JSON report
    report_path = os.path.join(REPORT_DIR, f"{incident_id}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    return report






