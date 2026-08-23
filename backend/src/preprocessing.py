import pandas as pd


def clean_data(df):
    print("Cleaning dataset...")

    df = df.copy()

    df = df.drop_duplicates(subset=["cve_id"])

    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["cvss_score"] = df["cvss_score"].fillna(0)

    df["description"] = df["description"].fillna("")
    df["severity"] = df["severity"].fillna("UNKNOWN")
    df["attack_vector"] = df["attack_vector"].fillna("UNKNOWN")
    df["attack_complexity"] = df["attack_complexity"].fillna("UNKNOWN")
    df["privileges_required"] = df["privileges_required"].fillna("UNKNOWN")
    df["user_interaction"] = df["user_interaction"].fillna("UNKNOWN")

    df["reference_count"] = df["reference_count"].fillna(0)
    df["weakness_count"] = df["weakness_count"].fillna(0)
    df["has_cisa_kev"] = df["has_cisa_kev"].fillna(0)

    df = df[df["cvss_score"] > 0]
    df = df[df["severity"] != "UNKNOWN"]

    df = df[df["cvss_score"] >= 0]
    df = df[df["cvss_score"] <= 10]

    print("Cleaning completed.")
    print("Remaining records after cleaning:", len(df))

    return df