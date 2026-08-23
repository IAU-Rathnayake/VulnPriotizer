import argparse
import os
import pandas as pd

from src.data_acquisition import fetch_nvd_data
from src.preprocessing import clean_data
from src.feature_engineering import prepare_features
from src.model import split_data, train_random_forest, save_model, load_model, get_feature_importance
from src.baselines import create_baseline_predictions
from src.evaluation import (
    evaluate_model,
    compare_methods,
    save_confusion_matrix,
    save_feature_importance_chart
)
from src.reporting import (
    save_text_report,
    save_feature_importance_csv,
    save_predictions
)


DATA_DIR = "data"
MODEL_DIR = "models"
REPORT_DIR = "reports"

RAW_DATA_PATH = os.path.join(DATA_DIR, "nvd_data.csv")
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_nvd_data.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "vulnprioritizer_model.joblib")


def create_folders():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)


def command_fetch(args):
    create_folders()

    df = fetch_nvd_data(
        keyword=args.keyword,
        total_records=args.records,
        api_key=args.api_key,
        start_date=args.start_date,
        end_date=args.end_date
    )
    if len(df) == 0:
        print("\nNo data was fetched. CSV file was not saved.")
        return
    df.to_csv(RAW_DATA_PATH, index=False)

    print("\nReal NVD data saved successfully.")
    print("Saved file:", RAW_DATA_PATH)
    print("Total records:", len(df))


def command_train(args):
    create_folders()

    if not os.path.exists(RAW_DATA_PATH):
        print("No NVD dataset found.")
        print("Run the fetch-nvd command first.")
        return

    # Load and clean data
    df = pd.read_csv(RAW_DATA_PATH)
    df = clean_data(df)

    if len(df) < 100:
        print("Warning: fewer than 100 usable records remain.")

    # Create features and labels
    X, y, full_df = prepare_features(df)

    full_df.to_csv(
        PROCESSED_DATA_PATH,
        index=False
    )

    # Split into training and testing datasets
    X_train, X_test, y_train, y_test = split_data(X, y)

    print("\nTraining records:", len(X_train))
    print("Testing records:", len(X_test))

    # Train Random Forest
    print("\nTraining Random Forest model...")

    model = train_random_forest(
        X_train,
        y_train
    )

    save_model(model, MODEL_PATH)

    # Test model
    y_pred = model.predict(X_test)

    model_results = evaluate_model(
        y_test,
        y_pred
    )

    # Use only test rows for a fair baseline comparison
    test_df = full_df.loc[X_test.index].copy()

    baseline_predictions = create_baseline_predictions(
        test_df
    )

    all_predictions = {
        "Random Forest": y_pred
    }

    for name, prediction in baseline_predictions.items():
        all_predictions[name] = prediction

    comparison_df = compare_methods(
        y_test,
        all_predictions
    )

    # Calculate feature importance
    feature_importance = get_feature_importance(
        model,
        X.columns
    )

    print("\nTop 10 Important Features:")

    for position, item in enumerate(
        feature_importance[:10],
        start=1
    ):
        print(
            f"{position}. {item['feature']}: "
            f"{item['importance']:.4f}"
        )

    # Save evaluation outputs
    save_confusion_matrix(
        y_test,
        y_pred,
        os.path.join(
            REPORT_DIR,
            "confusion_matrix.png"
        )
    )

    save_feature_importance_chart(
        feature_importance,
        os.path.join(
            REPORT_DIR,
            "feature_importance.png"
        )
    )

    save_feature_importance_csv(
        feature_importance,
        os.path.join(
            REPORT_DIR,
            "feature_importance.csv"
        )
    )

    save_text_report(
        os.path.join(
            REPORT_DIR,
            "evaluation_report.txt"
        ),
        comparison_df,
        model_results,
        feature_importance
    )

    save_predictions(
        test_df,
        y_pred,
        os.path.join(
            REPORT_DIR,
            "test_predictions.csv"
        )
    )

    print("\nTraining completed.")
    print("Model:", MODEL_PATH)
    print("Processed data:", PROCESSED_DATA_PATH)
    print("Report: reports/evaluation_report.txt")
    print("Confusion matrix: reports/confusion_matrix.png")
    print("Feature chart: reports/feature_importance.png")
    print("Feature table: reports/feature_importance.csv")

    print("\nComparison Results:")
    print(comparison_df)

    


def command_predict(args):
    create_folders()

    if not os.path.exists(MODEL_PATH):
        print("No trained model found. Please run train first.")
        return

    model = load_model(MODEL_PATH)

    df = pd.read_csv(args.input)

    df = clean_data(df)
    print("\nCVSS Statistics:")
    print(df["cvss_score"].describe())

    X, y, full_df = prepare_features(df)

    for col in model.feature_names_in_:
        if col not in X.columns:
            X[col] = 0

    X = X[model.feature_names_in_]

    predictions = model.predict(X)

    output_path = args.output

    if output_path is None:
        output_path = os.path.join(REPORT_DIR, "new_predictions.csv")

    save_predictions(full_df, predictions, output_path)

    print("Predictions saved:", output_path)


def main():
    parser = argparse.ArgumentParser(
        description="VULNPRIORITIZER: Simple ML-Based Vulnerability Prioritization Tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch-nvd")
    fetch_parser.add_argument("--keyword", default="microsoft")
    fetch_parser.add_argument("--records", type=int, default=1000)
    fetch_parser.add_argument("--api-key",default=None,help="Optional. If omitted, .env file key is used.")
    fetch_parser.add_argument("--start-date", default="2024-01-01T00:00:00.000")
    fetch_parser.add_argument("--end-date", default="2024-04-29T23:59:59.999")
    fetch_parser.set_defaults(func=command_fetch)

    train_parser = subparsers.add_parser("train")
    train_parser.set_defaults(func=command_train)

    predict_parser = subparsers.add_parser("predict")
    predict_parser.add_argument("--input", required=True)
    predict_parser.add_argument("--output", default=None)
    predict_parser.set_defaults(func=command_predict)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
