import re
from rules import (
    FAILED_LOGIN_THRESHOLD_LOW,
    FAILED_LOGIN_THRESHOLD_MEDIUM,
    FAILED_LOGIN_THRESHOLD_HIGH
)

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
                timestamp = match.group(1)
                user = match.group(2)
                ip = match.group(3)

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
            alerts.append({
                "ip": ip,
                "user": user,
                "failed_attempts": data["count"],
                "timestamps": data["timestamps"],
                "severity": severity,
                "attack_type": "Possible Brute Force"
            })

    return alerts


