import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


LABELS = ["High", "Medium", "Low"]


def evaluate_model(y_true, y_pred):
    """
    Calculate common classification measurements.
    """

    return {
        "accuracy": accuracy_score(y_true, y_pred),

        "precision": precision_score(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0
        ),

        "recall": recall_score(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0
        ),

        "f1_score": f1_score(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0
        ),

        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=LABELS,
            zero_division=0
        )
    }


def compare_methods(y_true, predictions_dict):
    """
    Compare Random Forest with baseline approaches.
    """

    rows = []

    for method_name, predictions in predictions_dict.items():
        rows.append({
            "Method": method_name,

            "Accuracy": accuracy_score(
                y_true,
                predictions
            ),

            "Precision": precision_score(
                y_true,
                predictions,
                average="weighted",
                zero_division=0
            ),

            "Recall": recall_score(
                y_true,
                predictions,
                average="weighted",
                zero_division=0
            ),

            "F1 Score": f1_score(
                y_true,
                predictions,
                average="weighted",
                zero_division=0
            )
        })

    return pd.DataFrame(rows)


def save_confusion_matrix(y_true, y_pred, output_path):
    """
    Save the confusion matrix as an image.
    """

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=LABELS
    )

    plt.figure(figsize=(7, 5))

    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=LABELS,
        yticklabels=LABELS
    )

    plt.title("Random Forest Confusion Matrix")
    plt.xlabel("Predicted Priority")
    plt.ylabel("Actual Priority")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def save_feature_importance_chart(
    feature_importance,
    output_path,
    top_n=10
):
    """
    Save the ten most important model features.
    """

    top_features = feature_importance[:top_n]

    feature_names = [
        item["feature"] for item in top_features
    ]

    importance_values = [
        item["importance"] for item in top_features
    ]

    # Reverse order so the most important appears at the top
    feature_names.reverse()
    importance_values.reverse()

    plt.figure(figsize=(9, 6))

    plt.barh(
        feature_names,
        importance_values,
        color="steelblue"
    )

    plt.title("Top 10 Random Forest Feature Importances")
    plt.xlabel("Importance")
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()