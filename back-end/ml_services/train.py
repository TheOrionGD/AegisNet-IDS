import joblib
import logging
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_PATH = ROOT_DIR / "back-end"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from config_loader import load_config
from ml_services.data_loader import DataLoader
from ml_services.feature_engineering import FeatureEngineer
from ml_services.model import AnomalyModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    config = load_config()

    train_file = config['paths'].get('train_file', config['paths']['alert_file'])
    loader = DataLoader(config['paths']['log_dir'], train_file)
    df = loader.load_logs()
    if df.empty:
        logger.error('No log entries loaded. Check Snort JSON output in config.paths.log_dir or config.paths.alert_file.')
        return

    engineer = FeatureEngineer(window_size=config['feature']['window_size'])
    features = engineer.extract_features(df)
    if features.empty:
        logger.error('Feature extraction produced no windows. Inspect log timestamps and feature settings.')
        return

    normalized_features, scaler = engineer.normalize_features(features, fit=True)
    normalized_features.to_csv(config['paths']['processed_data'])
    logger.info('Saved processed feature data.')

    model = AnomalyModel(
        contamination=config['model']['contamination'],
        random_state=config['model']['random_state']
    )
    model.train(normalized_features)
    model.save_model(config['paths']['model_path'])
    joblib.dump(scaler, config['paths']['scaler_path'])
    logger.info('Training complete and model/scaler saved.')


if __name__ == '__main__':
    main()