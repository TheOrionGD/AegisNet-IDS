import logging
import os
from pathlib import Path
import yaml
from dotenv import load_dotenv

# ── Root .env resolution ───────────────────────────────────────────────────────
# This file lives at  <project-root>/back-end/config_loader.py
#   parents[0] = back-end/
#   parents[1] = project root  (E:\PROJECTS\CNS)
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_ENV_FILE = _PROJECT_ROOT / ".env"

# override=False: any variable already set in the shell/OS environment
# takes precedence over the .env file (12-factor principle).
load_dotenv(dotenv_path=_ENV_FILE, override=False)
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


def _resolve_repo_path(path_value: str, repo_root: Path) -> str:
    if not isinstance(path_value, str):
        return path_value
    if Path(path_value).is_absolute() or path_value.startswith(('http://', 'https://')):
        return path_value
    return str(repo_root / path_value)


def _normalize_config_paths(config: dict, repo_root: Path) -> None:
    if 'paths' in config and isinstance(config['paths'], dict):
        for key, value in config['paths'].items():
            if isinstance(value, str):
                config['paths'][key] = _resolve_repo_path(value, repo_root)

    if 'siem' in config and isinstance(config['siem'], dict):
        index_schema = config['siem'].get('index_schema')
        if isinstance(index_schema, str):
            config['siem']['index_schema'] = _resolve_repo_path(index_schema, repo_root)


def _merge_env_config(config: dict) -> None:
    """Merge environment variables into configuration."""
    # Database
    if 'DATABASE_URL' in os.environ:
        config.setdefault('database', {})['url'] = os.environ['DATABASE_URL']

    # Redis
    if 'REDIS_URL' in os.environ:
        config.setdefault('bus', {})['redis_url'] = os.environ['REDIS_URL']

    # Security
    if 'SECRET_KEY' in os.environ:
        config['secret_key'] = os.environ['SECRET_KEY']

    if 'JWT_SECRET_KEY' in os.environ:
        config['jwt_secret_key'] = os.environ['JWT_SECRET_KEY']

    # Environment
    if 'ENVIRONMENT' in os.environ:
        config['environment'] = os.environ['ENVIRONMENT']

    # Elasticsearch
    if 'ELASTICSEARCH_URL' in os.environ:
        config.setdefault('elasticsearch', {})['url'] = os.environ['ELASTICSEARCH_URL']

    # Threat Intel
    if 'NVD_API_KEY' in os.environ:
        config.setdefault('threat_intel', {})['api_key'] = os.environ['NVD_API_KEY']


def load_config(config_path: str = 'config/config.yaml') -> dict:
    """Load and validate the YAML configuration file."""
    repo_root = Path(__file__).resolve().parents[1]
    config_file = Path(config_path)
    if not config_file.is_absolute():
        candidate = repo_root / config_path
        if candidate.exists():
            config_file = candidate

    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_file}")

    with config_file.open('r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}

    # Merge environment variables
    _merge_env_config(config)

    _validate_config(config)
    _normalize_config_paths(config, repo_root)
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
