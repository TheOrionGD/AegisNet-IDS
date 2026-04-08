#!/usr/bin/env python3
"""
Standalone demo: Generate sample Snort logs, train ML model, detect anomalies.
This works on Windows/macOS without requiring Snort or Linux sudo.
"""
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import random
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def generate_sample_snort_logs(output_dir: Path) -> None:
    """Generate realistic Snort JSON alert samples matching the data_loader expectations."""
    
    output_dir.mkdir(parents=True, exist_ok=True)
    train_file = output_dir / 'train_alerts.json'
    test_file = output_dir / 'test_alerts.json'
    
    base_time = datetime.now()
    alerts = []
    
    # Normal traffic
    for i in range(200):
        timestamp = (base_time + timedelta(seconds=i * 5)).isoformat() + '+0000'
        src_ip = f'192.168.1.{random.randint(10, 200)}'
        dst_ip = f'10.0.0.{random.randint(1, 250)}'
        alert = {
            'timestamp': timestamp,
            'event': {
                'source': {'ip': src_ip, 'port': random.randint(1024, 65535)},
                'destination': {'ip': dst_ip, 'port': random.choice([80, 443, 22, 8080])},
                'protocol': random.choice(['TCP', 'UDP']),
                'packet': {'length': random.randint(64, 1500)}
            }
        }
        alerts.append(alert)
    
    # Anomaly: DoS burst (many packets in short time)
    for i in range(500):
        timestamp = (base_time + timedelta(seconds=1000 + i * 0.05)).isoformat() + '+0000'
        alert = {
            'timestamp': timestamp,
            'event': {
                'source': {'ip': '192.168.1.50', 'port': random.randint(1024, 65535)},
                'destination': {'ip': '10.0.0.1', 'port': 80},
                'protocol': 'TCP',
                'packet': {'length': 64}
            }
        }
        alerts.append(alert)
    
    # Anomaly: Port scan
    for i in range(100):
        timestamp = (base_time + timedelta(seconds=2000 + i)).isoformat() + '+0000'
        alert = {
            'timestamp': timestamp,
            'event': {
                'source': {'ip': '192.168.1.99', 'port': random.randint(1024, 65535)},
                'destination': {'ip': '10.0.0.1', 'port': 1000 + i},
                'protocol': 'TCP',
                'packet': {'length': 64}
            }
        }
        alerts.append(alert)
    
    # Normal traffic for training
    train_alerts = alerts[:150] # Subset of normal for training
    
    # Write as JSONL (one per line)
    with train_file.open('w', encoding='utf-8') as f:
        for alert in sorted(train_alerts, key=lambda x: x['timestamp']):
            f.write(json.dumps(alert) + '\n')
            
    with test_file.open('w', encoding='utf-8') as f:
        for alert in sorted(alerts, key=lambda x: x['timestamp']):
            f.write(json.dumps(alert) + '\n')
    
    logger.info(f'Generated {len(train_alerts)} training alerts to {train_file}')
    logger.info(f'Generated {len(alerts)} testing alerts to {test_file}')


def main():
    try:
        from config_loader import load_config
        from data_loader import DataLoader
        from feature_engineering import FeatureEngineer
        from model import AnomalyModel
        import joblib
    except ImportError as e:
        logger.error(f'Missing required Python packages: {e}')
        logger.info('Run: pip install -r requirements.txt')
        sys.exit(1)
    
    # Step 1: Generate sample alerts
    logger.info('=== Step 1: Generating sample Snort alerts ===')
    data_dir = Path('demo_data')
    generate_sample_snort_logs(data_dir)
    
    # Step 2: Load config
    logger.info('=== Step 2: Loading configuration ===')
    try:
        config = load_config('config/config.yaml')
    except FileNotFoundError:
        logger.error('config/config.yaml not found')
        sys.exit(1)
    
    # Override paths for demo
    config['paths']['log_dir'] = str(data_dir)
    config['paths']['train_file'] = str(data_dir / 'train_alerts.json')
    config['paths']['alert_file'] = str(data_dir / 'test_alerts.json')
    demo_output = Path('demo_output')
    demo_output.mkdir(exist_ok=True)
    config['paths']['processed_data'] = str(demo_output / 'processed.csv')
    config['paths']['model_path'] = str(demo_output / 'model.joblib')
    config['paths']['scaler_path'] = str(demo_output / 'scaler.joblib')
    config['paths']['anomalies_output'] = str(demo_output / 'anomalies.json')
    config['paths']['detection_results_output'] = str(demo_output / 'results.json')
    
    # Step 3: Load and parse training alerts
    logger.info('=== Step 3: Loading training alerts ===')
    train_loader = DataLoader(None, config['paths']['train_file'])
    train_df = train_loader.load_logs()
    
    # Step 4: Extract and Normalize Training features
    logger.info('=== Step 4: Extracting Training features ===')
    engineer = FeatureEngineer(window_size=config['feature']['window_size'])
    train_features = engineer.extract_features(train_df)
    train_normalized, scaler = engineer.normalize_features(train_features, fit=True)
    joblib.dump(scaler, config['paths']['scaler_path'])
    
    # Step 5: Train model
    logger.info('=== Step 5: Training Isolation Forest on Normal Data ===')
    model = AnomalyModel(
        contamination=config['model']['contamination'],
        random_state=config['model']['random_state']
    )
    model.train(train_normalized)
    model.save_model(config['paths']['model_path'])
    logger.info(f'Model saved to {config["paths"]["model_path"]}')
    
    # Step 6: Process Testing Alerts
    logger.info('=== Step 6: Evaluating Testing Alerts ===')
    test_loader = DataLoader(None, config['paths']['alert_file'])
    df = test_loader.load_logs()
    features = engineer.extract_features(df)
    normalized_features, _ = engineer.normalize_features(features, fit=False)
    normalized_features.to_csv(config['paths']['processed_data'])
    
    # Step 7: Detect anomalies
    logger.info('=== Step 7: Detecting anomalies ===')
    scores, labels = model.predict(normalized_features)
    
    results = []
    anomaly_count = 0
    for window, score, label in zip(features.index, scores, labels):
        label_text = 'anomaly' if label == -1 else 'normal'
        is_anomaly = label == -1 or score < config['threshold']['anomaly_score']
        if is_anomaly:
            anomaly_count += 1
        results.append({
            'window_start': window.isoformat(),
            'anomaly_score': float(score),
            'label': label_text,
            'threshold': config['threshold']['anomaly_score']
        })
    
    detection_output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_windows': len(results),
        'anomalies_detected': anomaly_count,
        'results': results
    }
    
    with open(config['paths']['detection_results_output'], 'w', encoding='utf-8') as f:
        json.dump(detection_output, f, indent=2)
    
    logger.info(f'Detected {anomaly_count} anomalies from {len(results)} windows')
    logger.info(f'Results saved to {config["paths"]["detection_results_output"]}')
    
    # Step 8: Generate candidate Snort rules from anomalies
    logger.info('=== Step 8: Generating candidate Snort rules ===')
    try:
        from rule_generator import RuleGenerator
        anomalies = [r for r in results if r['label'] == 'anomaly' or r['anomaly_score'] < config['threshold']['anomaly_score']]
        if anomalies:
            rule_generator = RuleGenerator(str(demo_output / 'generated_rules.rules'))
            generated_rules = rule_generator.analyze_anomalies(df, anomalies)
            if generated_rules:
                rule_generator.save_rules(generated_rules, append=False)
                rule_generator.save_rules_metadata(str(demo_output / 'generated_rules_metadata.json'), generated_rules, anomalies)
                logger.info(f'Generated {len(generated_rules)} candidate Snort rules')
            else:
                logger.info('No rules generated from anomaly analysis')
    except Exception as e:
        logger.warning(f'Rule generation failed: {e}')
    
    # Summary
    logger.info('=== Demo Complete ===')
    logger.info(f'Sample alerts: {data_dir / "alerts.json"}')
    logger.info(f'Processed data: {config["paths"]["processed_data"]}')
    logger.info(f'Model: {config["paths"]["model_path"]}')
    logger.info(f'Results: {config["paths"]["detection_results_output"]}')
    try:
        logger.info(f'Generated rules: {demo_output / "generated_rules.rules"}')
    except:
        pass


if __name__ == '__main__':
    main()
