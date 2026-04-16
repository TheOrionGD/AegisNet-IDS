import argparse
import json
import logging
from pathlib import Path

import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_predictions(prediction_path: Path):
    with prediction_path.open('r', encoding='utf-8') as f:
        content = json.load(f)
    return pd.DataFrame(content.get('results', []) if isinstance(content, dict) else content)


def load_truth(truth_path: Path):
    if truth_path.suffix in ['.json', '.jsonl']:
        with truth_path.open('r', encoding='utf-8') as f:
            data = [json.loads(line) for line in f] if truth_path.suffix == '.jsonl' else json.load(f)
        return pd.DataFrame(data)
    return pd.read_csv(truth_path)


def main():
    parser = argparse.ArgumentParser(description='Evaluate anomaly detection metrics against labeled data.')
    parser.add_argument('--truth', required=True, help='Path to the labeled ground truth file.')
    parser.add_argument('--predictions', required=True, help='Path to the detection results JSON file.')
    args = parser.parse_args()

    truth_path = Path(args.truth)
    prediction_path = Path(args.predictions)
    if not truth_path.exists() or not prediction_path.exists():
        logger.error('Both truth and prediction files must exist.')
        return

    truth_df = load_truth(truth_path)
    pred_df = load_predictions(prediction_path)

    if 'label' not in truth_df.columns:
        logger.error('Truth file must contain a "label" column with values normal/anomaly.')
        return
    if 'label' not in pred_df.columns:
        logger.error('Prediction file must contain a "label" field in each result entry.')
        return

    y_true = truth_df['label'].astype(str).str.lower().map({'normal': 0, 'anomaly': 1}).fillna(0)
    y_pred = pred_df['label'].astype(str).str.lower().map({'normal': 0, 'anomaly': 1}).fillna(0)

    if len(y_true) != len(y_pred):
        logger.warning('Truth and prediction lengths differ; truncating to shortest length.')
        n = min(len(y_true), len(y_pred))
        y_true = y_true.iloc[:n]
        y_pred = y_pred.iloc[:n]

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print('Evaluation results:')
    print(f'  Precision: {precision:.3f}')
    print(f'  Recall:    {recall:.3f}')
    print(f'  F1-score:  {f1:.3f}')


if __name__ == '__main__':
    main()
