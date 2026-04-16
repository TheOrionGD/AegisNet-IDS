import json
import logging
import time
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import joblib
import pandas as pd
from config_loader import load_config
from ml_services.data_loader import DataLoader
from ml_services.feature_engineering import FeatureEngineer
from ml_services.model import AnomalyModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncrementalLogHandler(FileSystemEventHandler):
    def __init__(self, config: dict):
        self.config = config
        self.alert_file = Path(config['paths']['alert_file'])
        self.log_dir = Path(config['paths']['log_dir'])
        self.state_file = Path(config['paths'].get('monitor_state', 'logs/monitor_state.json'))
        self.offsets = self._load_state()

        self.model = AnomalyModel(
            contamination=config['model']['contamination'],
            random_state=config['model']['random_state']
        )
        self.model.load_model(config['paths']['model_path'])

        self.engineer = FeatureEngineer(window_size=config['feature']['window_size'])
        self.engineer.scaler = joblib.load(config['paths']['scaler_path'])
        self.anomalies_path = Path(config['paths']['anomalies_output'])
        self.anomalies_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> dict:
        if self.state_file.exists():
            try:
                with self.state_file.open('r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.warning('Monitor state file is invalid; starting fresh state.')
        return {}

    def _save_state(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with self.state_file.open('w', encoding='utf-8') as f:
            json.dump(self.offsets, f, indent=2)

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith('.json'):
            return
        self.process_file(Path(event.src_path))

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith('.json'):
            return
        self.process_file(Path(event.src_path))

    def process_file(self, path: Path) -> None:
        if not path.exists():
            return

        if self.alert_file.exists() and path != self.alert_file and path.parent != self.log_dir:
            return

        offset = self.offsets.get(str(path), 0)
        new_entries = []
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as f:
                f.seek(offset)
                for line in f:
                    payload = line.strip()
                    if not payload:
                        continue
                    try:
                        entry = json.loads(payload)
                        loader = DataLoader()
                        parsed = loader._extract_fields(entry)
                        if parsed:
                            new_entries.append(parsed)
                    except json.JSONDecodeError:
                        logger.warning(f'Skipping malformed JSON line in {path}')
                self.offsets[str(path)] = f.tell()
                self._save_state()
        except Exception as exc:
            logger.error(f'Failed to read incremental entries from {path}: {exc}')
            return

        if not new_entries:
            return

        df = pd.DataFrame(new_entries)
        if df.empty:
            return

        features = self.engineer.extract_features(df)
        if features.empty:
            return

        normalized_features, _ = self.engineer.normalize_features(features, fit=False)
        scores, labels = self.model.predict(normalized_features)

        anomalies = []
        for window, score, label in zip(features.index, scores, labels):
            if label == -1 or score < self.config['threshold']['anomaly_score']:
                anomalies.append({
                    'window_start': window.isoformat(),
                    'anomaly_score': float(score),
                    'label': 'anomaly',
                    'source_file': str(path)
                })

        if anomalies:
            with self.anomalies_path.open('a', encoding='utf-8') as f:
                for anomaly in anomalies:
                    f.write(json.dumps(anomaly) + '\n')
            logger.info(f'Appended {len(anomalies)} anomaly records to {self.anomalies_path}')


def main():
    config = load_config()
    event_handler = IncrementalLogHandler(config)
    observer = Observer()
    observer.schedule(event_handler, path=config['paths']['log_dir'], recursive=False)
    observer.start()

    logger.info('Started incremental Snort monitor.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == '__main__':
    main()