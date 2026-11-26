
SEVERITY_WEIGHTS = {
    "Critical": 5,
    "High": 4,
    "Medium": 2,
    "Low": 1
}


def calculate_risk(checks):

    applicable_checks = [
        check for check in checks
        if check.get("status") != "Not Observed"
    ]

    if not applicable_checks:
        return 0, "Unknown"

    total_weight = 0
    earned_weight = 0

    for check in applicable_checks:

        severity = check.get("severity", "Medium")
        weight = SEVERITY_WEIGHTS.get(severity, 2)

        total_weight += weight

        if check.get("status") == "Passed":
            earned_weight += weight

    if total_weight == 0:
        return 0, "Unknown"

    security_score = round(
        (earned_weight / total_weight) * 100
    )

    if security_score >= 80:
        risk_level = "Low"

    elif security_score >= 50:
        risk_level = "Medium"

    else:
        risk_level = "High"

    return security_score, risk_level


def get_risk_summary(checks):

    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Passed": 0,
        "Missing": 0,
        "Failed": 0,
        "Not Observed": 0
    }

    for check in checks:

        status = check.get("status", "Not Observed")
        severity = check.get("severity", "Medium")

        if status in summary:
            summary[status] += 1

        if status in ("Missing", "Failed"):
            if severity in summary:
                summary[severity] += 1

    return summary
