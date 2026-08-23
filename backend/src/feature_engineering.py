import pandas as pd


def calculate_vulnerability_age(published_date):
    """
    Calculate how many days old a vulnerability is.
    """

    published = pd.to_datetime(
        published_date,
        errors="coerce",
        utc=True
    )

    if pd.isna(published):
        return 0

    today = pd.Timestamp.now(tz="UTC")
    age_days = (today - published).days

    return max(age_days, 0)


def calculate_priority_score(row):
    """
    Create a transparent priority score.

    Factors:
    1. CVSS score
    2. CISA KEV status
    3. Network attack vector
    4. Low attack complexity
    5. No privileges required
    6. No user interaction required
    7. Number of references
    8. Number of weaknesses
    """

    score = 0

    # CVSS contribution
    if row["cvss_score"] >= 9.0:
        score += 4
    elif row["cvss_score"] >= 7.0:
        score += 3
    elif row["cvss_score"] >= 4.0:
        score += 1

    # Known exploited vulnerability
    if row["has_cisa_kev"] == 1:
        score += 5

    # Easily reachable over a network
    if row["attack_vector"] == "NETWORK":
        score += 2

    # Easier exploitation
    if row["attack_complexity"] == "LOW":
        score += 1

    # Attacker does not require privileges
    if row["privileges_required"] == "NONE":
        score += 1

    # Victim interaction is unnecessary
    if row["user_interaction"] == "NONE":
        score += 1

    # More references may indicate greater public exposure
    if row["reference_count"] >= 10:
        score += 1

    # Multiple recorded weakness entries
    if row["weakness_count"] >= 2:
        score += 1

    return score


def assign_priority(priority_score):
    """
    Convert the numeric score into a priority class.

    These thresholds are project-defined proxy rules.
    """

    if priority_score >= 8:
        return "High"

    if priority_score >= 5:
        return "Medium"

    return "Low"


def prepare_features(df):
    print("Creating machine learning features...")

    df = df.copy()

    # Create additional useful columns
    df["vulnerability_age_days"] = df["published_date"].apply(
        calculate_vulnerability_age
    )

    df["description_length"] = df["description"].fillna("").apply(len)

    # Create transparent training labels
    df["priority_score"] = df.apply(
        calculate_priority_score,
        axis=1
    )

    df["priority"] = df["priority_score"].apply(assign_priority)

    print("\nPriority distribution:")
    print(df["priority"].value_counts())

    print("\nPriority score statistics:")
    print(df["priority_score"].describe())

    # Do not include priority_score here.
    # It directly creates the label and would cause target leakage.
    feature_columns = [
        "cvss_score",
        "reference_count",
        "weakness_count",
        "has_cisa_kev",
        "vulnerability_age_days",
        "description_length",
        "severity",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction"
    ]

    X = df[feature_columns]
    y = df["priority"]

    # Convert text columns into numeric one-hot columns
    X = pd.get_dummies(X, dtype=int)

    print("Number of ML features:", len(X.columns))
    print("Feature engineering completed.")

    return X, y, df