import requests
import pandas as pd
import time
import os
from dotenv import load_dotenv
load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_english_description(cve):
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    return ""


def get_cvss_details(cve):
    metrics = cve.get("metrics", {})

    if "cvssMetricV40" in metrics:
        cvss = metrics["cvssMetricV40"][0]["cvssData"]
        return {
            "cvss_score": cvss.get("baseScore", 0),
            "severity": cvss.get("baseSeverity", "UNKNOWN"),
            "attack_vector": cvss.get("attackVector", "UNKNOWN"),
            "attack_complexity": cvss.get("attackComplexity", "UNKNOWN"),
            "privileges_required": cvss.get("privilegesRequired", "UNKNOWN"),
            "user_interaction": cvss.get("userInteraction", "UNKNOWN")
        }

    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        return {
            "cvss_score": cvss.get("baseScore", 0),
            "severity": cvss.get("baseSeverity", "UNKNOWN"),
            "attack_vector": cvss.get("attackVector", "UNKNOWN"),
            "attack_complexity": cvss.get("attackComplexity", "UNKNOWN"),
            "privileges_required": cvss.get("privilegesRequired", "UNKNOWN"),
            "user_interaction": cvss.get("userInteraction", "UNKNOWN")
        }

    if "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0]["cvssData"]
        return {
            "cvss_score": cvss.get("baseScore", 0),
            "severity": cvss.get("baseSeverity", "UNKNOWN"),
            "attack_vector": cvss.get("attackVector", "UNKNOWN"),
            "attack_complexity": cvss.get("attackComplexity", "UNKNOWN"),
            "privileges_required": cvss.get("privilegesRequired", "UNKNOWN"),
            "user_interaction": cvss.get("userInteraction", "UNKNOWN")
        }

    if "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"]
        return {
            "cvss_score": cvss.get("baseScore", 0),
            "severity": metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN"),
            "attack_vector": "UNKNOWN",
            "attack_complexity": "UNKNOWN",
            "privileges_required": "UNKNOWN",
            "user_interaction": "UNKNOWN"
        }

    return {
        "cvss_score": 0,
        "severity": "UNKNOWN",
        "attack_vector": "UNKNOWN",
        "attack_complexity": "UNKNOWN",
        "privileges_required": "UNKNOWN",
        "user_interaction": "UNKNOWN"
    }


def fetch_nvd_data(
    keyword="linux",
    total_records=1000,
    api_key=None,
    start_date="2024-01-01T00:00:00.000",
    end_date="2024-04-29T23:59:59.999"
):
    all_rows = []
    start_index = 0
    results_per_page = 100

    headers = {}

    if api_key:
        headers["apiKey"] = api_key
    elif NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    print("Fetching real data from NVD API...")

    while len(all_rows) < total_records:
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }

        response = requests.get(NVD_API_URL, params=params, headers=headers)

        print("Request URL:", response.url)
        print("NVD message:", response.headers.get("message"))

        if response.status_code != 200:
            print("NVD API request failed.")
            print("Status code:", response.status_code)
            print("Response:", response.text)
            break

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if len(vulnerabilities) == 0:
            print("No more records found.")
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cvss_details = get_cvss_details(cve)

            references = cve.get("references", [])
            weaknesses = cve.get("weaknesses", [])

            row = {
                "cve_id": cve.get("id", ""),
                "published_date": cve.get("published", ""),
                "last_modified_date": cve.get("lastModified", ""),
                "vuln_status": cve.get("vulnStatus", ""),
                "description": get_english_description(cve),

                "cvss_score": cvss_details["cvss_score"],
                "severity": cvss_details["severity"],
                "attack_vector": cvss_details["attack_vector"],
                "attack_complexity": cvss_details["attack_complexity"],
                "privileges_required": cvss_details["privileges_required"],
                "user_interaction": cvss_details["user_interaction"],

                "reference_count": len(references),
                "weakness_count": len(weaknesses),
                "has_cisa_kev": 1 if cve.get("cisaExploitAdd") else 0
            }

            all_rows.append(row)

            if len(all_rows) >= total_records:
                break

        start_index = start_index + results_per_page
        time.sleep(6)

    df = pd.DataFrame(all_rows)

    print("Fetched records:", len(df))

    return df
