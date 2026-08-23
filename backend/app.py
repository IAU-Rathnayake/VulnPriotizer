import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.data_acquisition import fetch_nvd_data
from src.preprocessing import clean_data
from src.feature_engineering import prepare_features
from src.model import load_model


MODEL_PATH = "models/vulnprioritizer_model.joblib"
FEATURE_IMAGE = "reports/feature_importance.png"
CONFUSION_IMAGE = "reports/confusion_matrix.png"
REPORT_PATH = "reports/evaluation_report.txt"


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="VULNPRIORITIZER",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# PROFESSIONAL DARK STYLE
# =========================================================

st.markdown(
    """
    <style>
    .stApp {
        background-color: #07111f;
        color: #e5edf7;
    }

    [data-testid="stSidebar"] {
        background-color: #0b1728;
        border-right: 1px solid #24364d;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #101f33, #0b1728);
        border: 1px solid #24364d;
        border-radius: 12px;
        padding: 18px;
    }

    [data-testid="stMetricLabel"] {
        color: #9fb2c8;
    }

    [data-testid="stMetricValue"] {
        color: #f5f8fc;
    }

    .hero {
        padding: 24px;
        border: 1px solid #24364d;
        border-radius: 14px;
        background: linear-gradient(135deg, #10243d, #091523);
        margin-bottom: 24px;
    }

    .hero-title {
        font-size: 32px;
        font-weight: 700;
        color: #f5f8fc;
    }

    .hero-subtitle {
        color: #9fb2c8;
        margin-top: 4px;
    }

    .status-online {
        color: #35d399;
        font-weight: 600;
    }

    .risk-high {
        color: #ff5d6c;
        font-weight: 700;
    }

    .risk-medium {
        color: #ffbc42;
        font-weight: 700;
    }

    .risk-low {
        color: #35d399;
        font-weight: 700;
    }

    .reason-card {
        background-color: #101f33;
        border: 1px solid #24364d;
        border-radius: 10px;
        padding: 14px;
        margin-bottom: 8px;
    }

    div.stButton > button {
        width: 100%;
        border-radius: 8px;
        background-color: #1677ff;
        color: white;
        border: none;
        font-weight: 600;
    }

    div.stButton > button:hover {
        background-color: #4096ff;
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def align_features(features, model):
    """
    Make new NVD features match the columns used during training.
    """

    aligned_features = features.copy()

    for column in model.feature_names_in_:
        if column not in aligned_features.columns:
            aligned_features[column] = 0

    return aligned_features[model.feature_names_in_]


def calculate_ml_risk_scores(model, features):
    """
    Convert Random Forest class probabilities into scores from 0 to 100.

    Low probability contributes 20 points.
    Medium probability contributes 60 points.
    High probability contributes 100 points.
    """

    probabilities = model.predict_proba(features)
    class_names = list(model.classes_)

    risk_scores = []
    confidence_scores = []

    class_weights = {
        "Low": 20,
        "Medium": 60,
        "High": 100
    }

    for probability_row in probabilities:
        score = 0

        for class_name, probability in zip(
            class_names,
            probability_row
        ):
            score += probability * class_weights.get(
                class_name,
                0
            )

        risk_scores.append(round(score))
        confidence_scores.append(
            round(max(probability_row) * 100, 1)
        )

    return risk_scores, confidence_scores


def create_risk_explanation(row):
    """
    Explain the main vulnerability properties affecting risk.
    """

    reasons = []

    if row["cvss_score"] >= 9:
        reasons.append(
            f"Critical CVSS score of {row['cvss_score']}"
        )
    elif row["cvss_score"] >= 7:
        reasons.append(
            f"High CVSS score of {row['cvss_score']}"
        )

    if row.get("has_cisa_kev", 0) == 1:
        reasons.append(
            "Listed in CISA Known Exploited Vulnerabilities"
        )

    if row.get("attack_vector") == "NETWORK":
        reasons.append(
            "Potentially exploitable across a network"
        )

    if row.get("attack_complexity") == "LOW":
        reasons.append(
            "Low attack complexity"
        )

    if row.get("privileges_required") == "NONE":
        reasons.append(
            "No existing privileges required"
        )

    if row.get("user_interaction") == "NONE":
        reasons.append(
            "No user interaction required"
        )

    if row.get("reference_count", 0) >= 10:
        reasons.append(
            "Large number of public references"
        )

    if not reasons:
        reasons.append(
            "No major high-risk indicators were identified"
        )

    return reasons


def create_risk_gauge(score):
    """
    Create a risk-score gauge.
    """

    if score >= 75:
        bar_color = "#ff5d6c"
    elif score >= 45:
        bar_color = "#ffbc42"
    else:
        bar_color = "#35d399"

    figure = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            title={"text": "ML Risk Score"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": bar_color},
                "bgcolor": "#101f33",
                "bordercolor": "#24364d",
                "steps": [
                    {
                        "range": [0, 45],
                        "color": "#163b34"
                    },
                    {
                        "range": [45, 75],
                        "color": "#4a3b18"
                    },
                    {
                        "range": [75, 100],
                        "color": "#4b2028"
                    }
                ]
            }
        )
    )

    figure.update_layout(
        height=280,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="#07111f",
        font_color="#e5edf7"
    )

    return figure


def run_live_analysis(keyword, records):
    """
    Fetch current NVD records and score them immediately.
    """

    if not os.path.exists(MODEL_PATH):
        st.error(
            "The trained model was not found. "
            "Run 'python main.py train' first."
        )
        return

    with st.spinner(
        "Fetching NVD data and calculating priorities..."
    ):
        raw_df = fetch_nvd_data(
            keyword=keyword,
            total_records=records
        )

        if raw_df.empty:
            st.error(
                "No vulnerabilities were returned for this search."
            )
            return

        clean_df = clean_data(raw_df)

        if clean_df.empty:
            st.error(
                "No usable vulnerabilities remained after cleaning."
            )
            return

        features, _, complete_df = prepare_features(
            clean_df
        )

        model = load_model(MODEL_PATH)

        aligned_features = align_features(
            features,
            model
        )

        predictions = model.predict(aligned_features)

        risk_scores, confidence_scores = (
            calculate_ml_risk_scores(
                model,
                aligned_features
            )
        )

        complete_df["predicted_priority"] = predictions
        complete_df["risk_score"] = risk_scores
        complete_df["model_confidence"] = confidence_scores

        complete_df = complete_df.sort_values(
            by=["risk_score", "cvss_score"],
            ascending=False
        ).reset_index(drop=True)

        st.session_state["results"] = complete_df
        st.session_state["last_updated"] = (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        st.session_state["last_keyword"] = keyword


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.markdown("## 🛡️ VULNPRIORITIZER")
st.sidebar.caption("Vulnerability Intelligence Console")

keyword = st.sidebar.text_input(
    "Product or technology",
    value="windows",
    help="Examples: windows, linux, apache or openssl"
)

records = st.sidebar.slider(
    "Maximum CVEs",
    min_value=100,
    max_value=1000,
    value=500,
    step=100
)

analyze_button = st.sidebar.button(
    "Run Live Analysis",
    type="primary"
)

refresh_button = st.sidebar.button(
    "Refresh Current Search"
)

if analyze_button:
    run_live_analysis(keyword, records)

if refresh_button:
    current_keyword = st.session_state.get(
        "last_keyword",
        keyword
    )

    run_live_analysis(current_keyword, records)

st.sidebar.markdown("---")

st.sidebar.markdown(
    """
    **Data source**

    NVD CVE API

    **Scoring**

    Random Forest probability-based risk score

    **Notice**

    This product uses data from the NVD API but is not
    endorsed or certified by the NVD.
    """
)


# =========================================================
# HERO HEADER
# =========================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-title">
            VULNPRIORITIZER
        </div>
        <div class="hero-subtitle">
            Machine Learning-Based Vulnerability
            Intelligence and Prioritization Platform
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# =========================================================
# EMPTY STATE
# =========================================================

if "results" not in st.session_state:
    st.info(
        "Enter a technology in the sidebar and select "
        "'Run Live Analysis' to begin."
    )

    st.markdown(
        """
        ### Platform capabilities

        - Fetch current vulnerability records from NVD
        - Score vulnerabilities using the trained Random Forest
        - Rank vulnerabilities using probability-based risk scores
        - Explain important risk indicators
        - Search and filter CVEs
        - Export prioritized results
        """
    )

    st.stop()


# =========================================================
# PREPARE RESULTS
# =========================================================

results = st.session_state["results"].copy()

# Permanent protection against old Streamlit session data
if "risk_score" not in results.columns:
    model = load_model(MODEL_PATH)
    features, _, results = prepare_features(results)
    aligned_features = align_features(features, model)

    results["predicted_priority"] = model.predict(
        aligned_features
    )

    risk_scores, confidence_scores = (
        calculate_ml_risk_scores(
            model,
            aligned_features
        )
    )

    results["risk_score"] = risk_scores
    results["model_confidence"] = confidence_scores

    st.session_state["results"] = results

last_updated = st.session_state.get(
    "last_updated",
    "Not available"
)

st.markdown(
    f"""
    <span class="status-online">● LIVE</span>
    &nbsp;&nbsp; Last refreshed: {last_updated}
    """,
    unsafe_allow_html=True
)


# =========================================================
# MAIN NAVIGATION
# =========================================================

dashboard_tab, threat_tab, explorer_tab, ml_tab = st.tabs(
    [
        "Security Overview",
        "Threat Center",
        "Vulnerability Explorer",
        "ML Intelligence"
    ]
)


# =========================================================
# SECURITY OVERVIEW
# =========================================================

with dashboard_tab:
    total_count = len(results)

    high_count = (
        results["predicted_priority"] == "High"
    ).sum()

    medium_count = (
        results["predicted_priority"] == "Medium"
    ).sum()

    low_count = (
        results["predicted_priority"] == "Low"
    ).sum()

    average_risk = round(
        results["risk_score"].mean(),
        1
    )

    metric1, metric2, metric3, metric4, metric5 = (
        st.columns(5)
    )

    metric1.metric("Total CVEs", total_count)
    metric2.metric("High Priority", high_count)
    metric3.metric("Medium Priority", medium_count)
    metric4.metric("Low Priority", low_count)
    metric5.metric("Average Risk", average_risk)

    st.markdown("---")

    chart1, chart2 = st.columns(2)

    priority_colors = {
        "High": "#ff5d6c",
        "Medium": "#ffbc42",
        "Low": "#35d399"
    }

    with chart1:
        priority_counts = (
            results["predicted_priority"]
            .value_counts()
            .reset_index()
        )

        priority_counts.columns = [
            "Priority",
            "Count"
        ]

        priority_chart = px.pie(
            priority_counts,
            names="Priority",
            values="Count",
            title="Priority Distribution",
            color="Priority",
            color_discrete_map=priority_colors,
            hole=0.62
        )

        priority_chart.update_layout(
            paper_bgcolor="#07111f",
            plot_bgcolor="#07111f",
            font_color="#e5edf7"
        )

        st.plotly_chart(
            priority_chart,
            use_container_width=True
        )

    with chart2:
        severity_counts = (
            results["severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        severity_chart = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            color="Severity",
            title="Severity Distribution",
            color_discrete_map={
                "CRITICAL": "#ff3b4d",
                "HIGH": "#ff7a45",
                "MEDIUM": "#ffbc42",
                "LOW": "#35d399",
                "UNKNOWN": "#718096"
            }
        )

        severity_chart.update_layout(
            paper_bgcolor="#07111f",
            plot_bgcolor="#07111f",
            font_color="#e5edf7",
            showlegend=False
        )

        st.plotly_chart(
            severity_chart,
            use_container_width=True
        )

    st.subheader("Highest-Risk Vulnerabilities")

    overview_columns = [
        "cve_id",
        "risk_score",
        "model_confidence",
        "predicted_priority",
        "cvss_score",
        "severity",
        "attack_vector"
    ]

    st.dataframe(
        results[overview_columns].head(10),
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# THREAT CENTER
# =========================================================

with threat_tab:
    st.subheader("Threat Prioritization Center")

    filter1, filter2, filter3 = st.columns(3)

    with filter1:
        selected_priority = st.multiselect(
            "Priority",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"]
        )

    with filter2:
        available_severities = sorted(
            results["severity"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_severity = st.multiselect(
            "Severity",
            options=available_severities,
            default=available_severities
        )

    with filter3:
        minimum_risk = st.slider(
            "Minimum risk score",
            min_value=0,
            max_value=100,
            value=0
        )

    threat_results = results[
        results["predicted_priority"].isin(
            selected_priority
        )
        & results["severity"].isin(
            selected_severity
        )
        & (results["risk_score"] >= minimum_risk)
    ]

    st.caption(
        f"{len(threat_results)} vulnerabilities match "
        "the selected filters."
    )

    threat_columns = [
        "cve_id",
        "risk_score",
        "model_confidence",
        "predicted_priority",
        "cvss_score",
        "severity",
        "attack_vector",
        "privileges_required",
        "published_date"
    ]

    st.dataframe(
        threat_results[threat_columns],
        use_container_width=True,
        hide_index=True
    )

    threat_csv = threat_results.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        "Download Filtered Threat Report",
        data=threat_csv,
        file_name="vulnprioritizer_threat_report.csv",
        mime="text/csv"
    )


# =========================================================
# VULNERABILITY EXPLORER
# =========================================================

with explorer_tab:
    st.subheader("Vulnerability Explorer")

    search_value = st.text_input(
        "Search by CVE ID or description",
        placeholder="Example: CVE-2024 or remote code execution"
    )

    explorer_results = results.copy()

    if search_value:
        search_mask = (
            explorer_results["cve_id"]
            .astype(str)
            .str.contains(
                search_value,
                case=False,
                na=False
            )
            |
            explorer_results["description"]
            .astype(str)
            .str.contains(
                search_value,
                case=False,
                na=False
            )
        )

        explorer_results = explorer_results[
            search_mask
        ]

    if explorer_results.empty:
        st.warning(
            "No vulnerabilities matched the search."
        )
    else:
        selected_cve = st.selectbox(
            "Select vulnerability",
            explorer_results["cve_id"].tolist()
        )

        selected_row = explorer_results[
            explorer_results["cve_id"] == selected_cve
        ].iloc[0]

        detail1, detail2 = st.columns(
            [1, 2]
        )

        with detail1:
            st.plotly_chart(
                create_risk_gauge(
                    selected_row["risk_score"]
                ),
                use_container_width=True
            )

            st.metric(
                "Predicted Priority",
                selected_row["predicted_priority"]
            )

            st.metric(
                "Model Confidence",
                f"{selected_row['model_confidence']}%"
            )

        with detail2:
            st.markdown(
                f"## {selected_row['cve_id']}"
            )

            st.write(selected_row["description"])

            info1, info2, info3 = st.columns(3)

            info1.metric(
                "CVSS",
                selected_row["cvss_score"]
            )

            info2.metric(
                "Severity",
                selected_row["severity"]
            )

            info3.metric(
                "Attack Vector",
                selected_row["attack_vector"]
            )

            st.markdown("### Technical characteristics")

            technical_details = {
                "Attack complexity":
                    selected_row["attack_complexity"],

                "Privileges required":
                    selected_row["privileges_required"],

                "User interaction":
                    selected_row["user_interaction"],

                "Reference count":
                    int(selected_row["reference_count"]),

                "Weakness count":
                    int(selected_row["weakness_count"]),

                "Published":
                    selected_row["published_date"]
            }

            st.json(technical_details)

        st.markdown("### Risk explanation")

        explanations = create_risk_explanation(
            selected_row
        )

        for reason in explanations:
            st.markdown(
                f"""
                <div class="reason-card">
                    ✓ {reason}
                </div>
                """,
                unsafe_allow_html=True
            )


# =========================================================
# ML INTELLIGENCE
# =========================================================

with ml_tab:
    st.subheader("Machine Learning Intelligence")

    st.info(
        "Risk scores are calculated from the Random Forest "
        "class probabilities. The displayed confidence is "
        "the model's highest predicted-class probability."
    )

    image1, image2 = st.columns(2)

    with image1:
        if os.path.exists(FEATURE_IMAGE):
            st.image(
                FEATURE_IMAGE,
                caption="Random Forest Feature Importance",
                use_container_width=True
            )
        else:
            st.warning(
                "Feature-importance image was not found."
            )

    with image2:
        if os.path.exists(CONFUSION_IMAGE):
            st.image(
                CONFUSION_IMAGE,
                caption="Model Confusion Matrix",
                use_container_width=True
            )
        else:
            st.warning(
                "Confusion-matrix image was not found."
            )

    if os.path.exists(REPORT_PATH):
        with open(
            REPORT_PATH,
            "r",
            encoding="utf-8"
        ) as report_file:
            report_text = report_file.read()

        with st.expander(
            "View complete evaluation report"
        ):
            st.code(report_text)

    all_results_csv = results.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        "Download Complete Prioritized Dataset",
        data=all_results_csv,
        file_name="vulnprioritizer_complete_results.csv",
        mime="text/csv"
    )