import logging
from pathlib import Path
import yaml

logger = logging.getLogger(__name__)


def load_config(config_path: str = 'config/config.yaml') -> dict:
    """Load and validate the YAML configuration file."""
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_file}")

    with config_file.open('r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}

    _validate_config(config)
    _ensure_paths(config)
    return config


def _validate_config(config: dict) -> None:
    required_sections = ['paths', 'model', 'threshold', 'feature']
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required config section: {section}")

    paths = config['paths']
    for key in ['log_dir', 'alert_file', 'processed_data', 'model_path', 'scaler_path', 'anomalies_output']:
        if key not in paths:
            raise ValueError(f"Missing required config path: {key}")

    if 'window_size' not in config['feature']:
        raise ValueError("Missing required feature.window_size setting")


def _ensure_paths(config: dict) -> None:
    paths = config['paths']
    safe_mkdir(paths.get('raw_log_dir', 'data/raw_logs'))
    safe_mkdir(Path(paths['processed_data']).parent)
    safe_mkdir(Path(paths['model_path']).parent)
    safe_mkdir(Path(paths['scaler_path']).parent)
    safe_mkdir(Path(paths['anomalies_output']).parent)
    if 'detection_results_output' in paths:
        safe_mkdir(Path(paths['detection_results_output']).parent)


def safe_mkdir(path) -> None:
    directory = Path(path)
    if not directory.exists():
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"Unable to create path {directory} due to permissions. Please create it manually.")
