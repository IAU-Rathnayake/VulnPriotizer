import pandas as pd


def save_text_report(
    report_path,
    comparison_df,
    model_results,
    feature_importance
):
    """
    Save all evaluation measurements in a text file.
    """

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("VULNPRIORITIZER EVALUATION REPORT\n")
        file.write("=================================\n\n")

        file.write("RANDOM FOREST RESULTS\n")
        file.write("---------------------\n")
        file.write(
            f"Accuracy: {model_results['accuracy']:.4f}\n"
        )
        file.write(
            f"Precision: {model_results['precision']:.4f}\n"
        )
        file.write(
            f"Recall: {model_results['recall']:.4f}\n"
        )
        file.write(
            f"F1 Score: {model_results['f1_score']:.4f}\n\n"
        )

        file.write("CLASSIFICATION REPORT\n")
        file.write("---------------------\n")
        file.write(model_results["classification_report"])
        file.write("\n\n")

        file.write("METHOD COMPARISON\n")
        file.write("-----------------\n")
        file.write(
            comparison_df.to_string(index=False)
        )
        file.write("\n\n")

        file.write("TOP FEATURE IMPORTANCES\n")
        file.write("-----------------------\n")

        for position, item in enumerate(
            feature_importance[:10],
            start=1
        ):
            file.write(
                f"{position}. {item['feature']}: "
                f"{item['importance']:.6f}\n"
            )

        file.write("\nINTERPRETATION NOTE\n")
        file.write("-------------------\n")
        file.write(
            "These feature importance values show which inputs "
            "the fitted Random Forest used most when splitting "
            "the training data. They do not prove causation.\n"
        )


def save_feature_importance_csv(
    feature_importance,
    output_path
):
    """
    Save every feature importance value as CSV.
    """

    importance_df = pd.DataFrame(feature_importance)
    importance_df.to_csv(output_path, index=False)


def save_predictions(df, predictions, output_path):
    """
    Save actual and predicted priorities.
    """

    output_df = df.copy()
    output_df["predicted_priority"] = predictions
    output_df.to_csv(output_path, index=False)