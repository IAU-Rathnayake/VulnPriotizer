def cvss_baseline(row):
    if row["cvss_score"] >= 9:
        return "High"
    elif row["cvss_score"] >= 7:
        return "Medium"
    else:
        return "Low"


def exploitability_baseline(row):
    if row["has_cisa_kev"] == 1:
        return "High"
    elif row["reference_count"] >= 10:
        return "Medium"
    else:
        return "Low"


def age_baseline(row):
    if row["vulnerability_age_days"] > 365:
        return "High"
    elif row["vulnerability_age_days"] > 90:
        return "Medium"
    else:
        return "Low"


def combined_rule_baseline(row):
    score = 0

    if row["cvss_score"] >= 9:
        score = score + 3
    elif row["cvss_score"] >= 7:
        score = score + 2
    elif row["cvss_score"] >= 4:
        score = score + 1

    if row["has_cisa_kev"] == 1:
        score = score + 3

    if row["reference_count"] >= 10:
        score = score + 1

    if row["vulnerability_age_days"] > 90:
        score = score + 1

    if score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    else:
        return "Low"


def create_baseline_predictions(df):
    results = {}

    results["CVSS Baseline"] = df.apply(cvss_baseline, axis=1)
    results["Exploitability Baseline"] = df.apply(exploitability_baseline, axis=1)
    results["Age Baseline"] = df.apply(age_baseline, axis=1)
    results["Combined Rule Baseline"] = df.apply(combined_rule_baseline, axis=1)

    return results