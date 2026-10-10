#!/usr/bin/env python3
"""
exercise_02_permission_analyzer.py — Android Permission Risk Analyzer (Skeleton)
Usage: python exercise_02_permission_analyzer.py

This exercise uses a hardcoded sample permission list to avoid requiring a real APK.
Goal: build a risk table, score each permission, detect dangerous combos, and
output an overall risk level.
"""

# Sample permission list for the exercise.
# In a real tool this would be parsed from AndroidManifest.xml (see exercise_01 / sol01).
SAMPLE_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]

# ─────────────────────────────────────────────────────────────────────────────
# DANGEROUS permissions list (subset that requires runtime grant)
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
}

# ─────────────────────────────────────────────────────────────────────────────
# TODO: build a risk scoring dict
# ─────────────────────────────────────────────────────────────────────────────
# Create a dict PERMISSION_RISK that maps permission name → (severity, explanation)
# Include at least these:
#   INTERNET → ("LOW", "Network access")
#   RECORD_AUDIO → ("HIGH", "Microphone access")
#   CAMERA → ("HIGH", "Camera access")
#   READ_SMS → ("HIGH", "Read SMS messages")
#   SEND_SMS → ("HIGH", "Send SMS messages — potential fraud")
#   ACCESS_FINE_LOCATION → ("HIGH", "Precise location")
#   ACCESS_BACKGROUND_LOCATION → ("HIGH", "Background location — persistent tracking")
#   READ_CONTACTS → ("MEDIUM", "Read contacts")
#   RECEIVE_BOOT_COMPLETED → ("MEDIUM", "Run at boot — persistence mechanism")
#   VIBRATE → ("LOW", "Vibrate the device")
#   WAKE_LOCK → ("LOW", "Prevent CPU sleep")
#   REQUEST_INSTALL_PACKAGES → ("HIGH", "Install additional packages — dropper")
#   BIND_DEVICE_ADMIN → ("CRITICAL", "Device admin — prevents removal")
#   BIND_ACCESSIBILITY_SERVICE → ("CRITICAL", "Screen scraping / auto-tap")

PERMISSION_RISK = {
    # TODO: populate this dict
}


def score_permission(perm):
    """
    TODO: Implement this function.

    Return (severity, explanation) for a given permission string.
    - Check PERMISSION_RISK for a direct match.
    - If the permission is in DANGEROUS_PERMISSIONS but not in PERMISSION_RISK,
      return ("MEDIUM", "Dangerous permission — requires runtime grant").
    - Otherwise return ("LOW", "Normal/unknown permission").
    """
    # TODO: implement
    return ("UNKNOWN", "not implemented")


# ─────────────────────────────────────────────────────────────────────────────
# TODO: define dangerous combos
# ─────────────────────────────────────────────────────────────────────────────
# Create a list DANGEROUS_COMBOS where each element is:
#   (frozenset_of_permissions, severity, description)
# Example:
#   (frozenset({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"}),
#    "CRITICAL", "Possible remote mic tap")
#
# Include at least:
#   RECORD_AUDIO + INTERNET → "Possible remote microphone tap" (CRITICAL)
#   CAMERA + INTERNET → "Possible remote camera streaming" (CRITICAL)
#   READ_SMS + SEND_SMS → "SMS fraud / 2FA interception" (CRITICAL)
#   ACCESS_FINE_LOCATION + ACCESS_BACKGROUND_LOCATION → "Persistent location tracking" (HIGH)
#   READ_CONTACTS + INTERNET → "Contact exfiltration" (HIGH)

DANGEROUS_COMBOS = [
    # TODO: populate
]


def detect_combos(permissions_set):
    """
    TODO: Implement this function.

    Check permissions_set against each entry in DANGEROUS_COMBOS.
    Return list of (severity, description) for each combo present.
    A combo is present when all permissions in the frozenset are in permissions_set.
    """
    # TODO: implement
    return []


def compute_overall_risk(per_perm_scores, combo_findings):
    """
    TODO: Implement this function.

    Given:
      per_perm_scores: list of (permission, severity, explanation)
      combo_findings: list of (severity, description)

    Return overall risk label: "CRITICAL", "HIGH", "MEDIUM", or "LOW".
    Rules:
    - CRITICAL if any combo is CRITICAL OR any permission is CRITICAL
    - HIGH if any combo is HIGH OR 3+ permissions are HIGH
    - MEDIUM if any permission is HIGH or 3+ are MEDIUM
    - LOW otherwise
    """
    # TODO: implement
    return "UNKNOWN"


def main():
    permissions = SAMPLE_PERMISSIONS
    permissions_set = set(permissions)

    print("=" * 65)
    print("  Android Permission Risk Analyzer")
    print("=" * 65)
    print(f"\nAnalyzing {len(permissions)} permission(s):\n")

    # Per-permission table
    per_perm_scores = []
    print(f"  {'Severity':<12} {'Permission':<55}")
    print(f"  {'─'*12} {'─'*55}")
    for perm in sorted(permissions):
        severity, explanation = score_permission(perm)
        per_perm_scores.append((perm, severity, explanation))
        print(f"  {severity:<12} {perm}")
        print(f"               {explanation}")

    # Combo detection
    combo_findings = detect_combos(permissions_set)
    if combo_findings:
        print(f"\n  ── Dangerous Combinations Detected ──")
        for sev, desc in combo_findings:
            print(f"  [{sev}] {desc}")

    # Overall risk
    overall = compute_overall_risk(per_perm_scores, combo_findings)
    print(f"\n  Overall Risk Level: {overall}")
    print()


if __name__ == "__main__":
    main()
