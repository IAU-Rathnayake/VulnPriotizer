import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier


def split_data(X, y):
    """
    Split data into 80% training and 20% testing data.
    """

    class_counts = y.value_counts()

    print("\nClass distribution:")
    print(class_counts)

    if len(class_counts) < 2:
        raise ValueError(
            "Training requires at least two priority classes."
        )

    if class_counts.min() < 2:
        raise ValueError(
            "Every priority class must contain at least two records."
        )

    return train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )


def train_random_forest(X_train, y_train):
    """
    Train a Random Forest classifier.
    """

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    return model


def save_model(model, path):
    joblib.dump(model, path)


def load_model(path):
    return joblib.load(path)


def get_feature_importance(model, feature_names):
    """
    Return feature names and their importance values.
    """

    importance_rows = []

    for feature, importance in zip(
        feature_names,
        model.feature_importances_
    ):
        importance_rows.append({
            "feature": feature,
            "importance": importance
        })

    importance_rows.sort(
        key=lambda item: item["importance"],
        reverse=True
    )

    return importance_rows