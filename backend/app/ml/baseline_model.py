"""Baseline URL + HTML Machine Learning Classifier (Experiment 1).

Implements the standard industry benchmark classifier using scikit-learn
to establish the empirical control baseline against which CRCE and SLM
advancements will be rigorously measured.
"""
import os
import joblib
import numpy as np
from typing import Dict, List, Optional, Tuple, Union
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from backend.app.core.logging import logger
from backend.app.ml.baseline_features import extract_baseline_features, get_feature_names
from backend.app.models.schemas import (
    BaselinePrediction,
    EvaluationMetrics,
    HTMLFeatures,
    URLFeatures,
)


class BaselineClassifier:
    """Baseline supervised classifier operating exclusively on URL + HTML features.
    
    Provides training, prediction, evaluation metric generation, and model serialization.
    """

    def __init__(
        self,
        model_type: str = "random_forest",
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.model_type = model_type.lower()
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.is_fitted = False

        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=random_state,
                class_weight="balanced",
                n_jobs=-1,
            )
        elif self.model_type == "logistic_regression":
            self.model = LogisticRegression(
                random_state=random_state,
                class_weight="balanced",
                max_iter=1000,
            )
        else:
            raise ValueError(f"Unsupported model type '{model_type}'. Choose 'random_forest' or 'logistic_regression'.")

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BaselineClassifier":
        """Trains the baseline model and fits the feature scaler."""
        if len(X) == 0 or len(y) == 0:
            raise ValueError("Training dataset must not be empty.")

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        logger.info(f"Baseline {self.model_type} trained on {len(X)} samples.")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Generates binary class predictions (0=Legitimate, 1=Phishing)."""
        if not self.is_fitted:
            raise RuntimeError("Model must be trained before calling predict().")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Generates class probabilities [P(legit), P(phish)]."""
        if not self.is_fitted:
            raise RuntimeError("Model must be trained before calling predict_proba().")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def predict_sample(
        self,
        url_features: URLFeatures,
        html_features: HTMLFeatures,
    ) -> BaselinePrediction:
        """Predicts phishing status and probability for a single URL + HTML sample."""
        if not self.is_fitted:
            # Fallback heuristic prediction if untrained model is queried
            logger.warning("Baseline model not yet trained; returning heuristic fallback prediction.")
            prob = round(url_features.url_risk_score, 4)
            return BaselinePrediction(
                is_phishing=prob >= 0.5,
                probability=prob,
                model_name=f"{self.model_type}_untrained_fallback",
            )

        feat_vector = extract_baseline_features(url_features, html_features).reshape(1, -1)
        prob = float(self.predict_proba(feat_vector)[0][1])
        is_phish = prob >= 0.5

        # Feature contributions from Random Forest importances
        feature_contributions: Dict[str, float] = {}
        if hasattr(self.model, "feature_importances_"):
            feature_names = get_feature_names()
            importances = self.model.feature_importances_
            top_indices = np.argsort(importances)[::-1][:5]
            for idx in top_indices:
                feature_contributions[feature_names[idx]] = round(float(importances[idx]), 4)

        return BaselinePrediction(
            is_phishing=is_phish,
            probability=round(prob, 4),
            model_name=self.model_type,
            feature_contributions=feature_contributions,
        )

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> EvaluationMetrics:
        """Evaluates model performance against ground-truth labels.
        
        Calculates Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR,
        and Confusion Matrix with complete academic rigor.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be trained before calling evaluate().")

        preds = self.predict(X_test)
        probas = self.predict_proba(X_test)[:, 1]

        # Calculate standard academic metrics
        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))

        # ROC-AUC requires both classes present in y_test
        roc_auc: Optional[float] = None
        if len(np.unique(y_test)) > 1:
            roc_auc = float(roc_auc_score(y_test, probas))

        # Confusion Matrix [[TN, FP], [FN, TP]]
        cm = confusion_matrix(y_test, preds)
        tn, fp, fn, tp = (0, 0, 0, 0)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        elif len(cm) == 1:
            if y_test[0] == 0:
                tn = cm[0][0]
            else:
                tp = cm[0][0]

        # FPR = FP / (FP + TN)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        # FNR = FN / (FN + TP)
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        return EvaluationMetrics(
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            roc_auc=round(roc_auc, 4) if roc_auc is not None else None,
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]],
            total_samples=len(y_test),
        )

    def save(self, filepath: str) -> None:
        """Persists trained model and scaler to disk via joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "model_type": self.model_type,
                "is_fitted": self.is_fitted,
            },
            filepath,
        )
        logger.info(f"Model saved to '{filepath}'.")

    @classmethod
    def load(cls, filepath: str) -> "BaselineClassifier":
        """Loads serialized model and scaler from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model artifact not found at '{filepath}'.")

        data = joblib.load(filepath)
        instance = cls(model_type=data["model_type"])
        instance.model = data["model"]
        instance.scaler = data["scaler"]
        instance.is_fitted = data["is_fitted"]
        logger.info(f"Model loaded from '{filepath}'.")
        return instance
