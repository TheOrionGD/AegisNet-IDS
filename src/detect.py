import json
import logging
import joblib
from datetime import datetime
from pathlib import Path
from config_loader import load_config
from data_loader import DataLoader
from feature_engineering import FeatureEngineer
from model import AnomalyModel
from rule_generator import RuleGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    config = load_config()

    model = AnomalyModel()
    model.load_model(config['paths']['model_path'])

    scaler = joblib.load(config['paths']['scaler_path'])
    engineer = FeatureEngineer(window_size=config['feature']['window_size'])
    engineer.scaler = scaler

    loader = DataLoader(config['paths']['log_dir'], config['paths']['alert_file'])
    df = loader.load_logs()
    if df.empty:
        logger.info('No alerts available for detection.')
        return

    features = engineer.extract_features(df)
    if features.empty:
        logger.info('No feature windows extracted for detection.')
        return

    normalized_features, _ = engineer.normalize_features(features, fit=False)
    scores, labels = model.predict(normalized_features)

    results = []
    for window, score, label in zip(features.index, scores, labels):
        label_text = 'anomaly' if label == -1 else 'normal'
        results.append({
            'window_start': window.isoformat(),
            'anomaly_score': float(score),
            'label': label_text,
            'threshold': config['threshold']['anomaly_score']
        })

    detection_output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_windows': len(results),
        'anomalies_detected': sum(1 for item in results if item['label'] == 'anomaly'),
        'results': results
    }

    with open(config['paths']['detection_results_output'], 'w', encoding='utf-8') as f:
        json.dump(detection_output, f, indent=2)

    anomalies = [item for item in results if item['label'] == 'anomaly' or item['anomaly_score'] < config['threshold']['anomaly_score']]
    with open(config['paths']['anomalies_output'], 'w', encoding='utf-8') as f:
        json.dump(anomalies, f, indent=2)

    logger.info(f'Detection completed. {len(anomalies)} anomalies written to {config["paths"]["anomalies_output"]}.')

    # Generate candidate Snort rules from detected anomalies
    if anomalies:
        try:
            rule_generator = RuleGenerator('generated_rules.rules')
            generated_rules = rule_generator.analyze_anomalies(df, anomalies)
            if generated_rules:
                rule_generator.save_rules(generated_rules, append=True)
                rule_generator.save_rules_metadata('generated_rules_metadata.json', generated_rules, anomalies)
                logger.info(f'Generated {len(generated_rules)} candidate Snort rules')
        except Exception as e:
            logger.warning(f'Rule generation failed: {e}')


if __name__ == '__main__':
    main()