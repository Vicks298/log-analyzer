FAILED_LOGIN_THRESHOLD_LOW = 3
FAILED_LOGIN_THRESHOLD_MEDIUM = 5
FAILED_LOGIN_THRESHOLD_HIGH = 8

# =========================
# MITRE ATT&CK MAPPINGS
# =========================

MITRE_ATTACK_MAPPING = {
    "Possible Brute Force": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "subtechnique": "Password Guessing"
    }
}



