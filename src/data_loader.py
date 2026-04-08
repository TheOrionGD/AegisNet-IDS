import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)

_PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


class DataLoader:
    """Load and parse Snort JSON alert files into a pandas DataFrame."""

    def __init__(self, log_dir: str = None, alert_file: str = None):
        self.log_dir = Path(log_dir) if log_dir else None
        self.alert_file = Path(alert_file) if alert_file else None

    def load_logs(self) -> pd.DataFrame:
        paths = set()
        if self.alert_file and self.alert_file.exists():
            paths.add(self.alert_file)
        if self.log_dir and self.log_dir.exists():
            for json_file in self.log_dir.glob('*.json'):
                paths.add(json_file)

        if not paths:
            logger.warning('No JSON logs found in log directory or alert file path.')
            return pd.DataFrame()

        rows = []
        for path in sorted(paths):
            logger.info(f'Loading JSON alerts from {path}')
            rows.extend(self._parse_log_file(path))

        df = pd.DataFrame(rows)
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df.dropna(subset=['timestamp'], inplace=True)
            df.sort_values(by='timestamp', inplace=True)
        logger.info(f'Loaded {len(df)} parsed log entries.')
        return df

    def _parse_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        entries = []
        try:
            with file_path.open('r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        json_entry = json.loads(raw)
                    except json.JSONDecodeError:
                        logger.warning(f'Skipping malformed JSON at {file_path}:{line_number}')
                        continue
                    parsed = self._extract_fields(json_entry)
                    if parsed is not None:
                        entries.append(parsed)
        except FileNotFoundError:
            logger.warning(f'Alert file not found: {file_path}')
        return entries

    def _normalize_protocol(self, protocol: Any) -> str:
        if isinstance(protocol, str):
            return protocol.strip().upper()
        if isinstance(protocol, int):
            return _PROTOCOL_MAP.get(protocol, f'PROTO_{protocol}')
        return 'UNKNOWN'

    def _extract_fields(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event = entry.get('event', {}) if isinstance(entry.get('event', {}), dict) else {}
        source = event.get('source', {}) if isinstance(event.get('source', {}), dict) else {}
        destination = event.get('destination', {}) if isinstance(event.get('destination', {}), dict) else {}

        timestamp = (
            entry.get('timestamp')
            or entry.get('time')
            or event.get('timestamp')
            or entry.get('ts')
        )

        src_ip = (
            source.get('ip')
            or entry.get('src_ip')
            or entry.get('source_ip')
            or entry.get('src_addr')
        )
        dst_ip = (
            destination.get('ip')
            or entry.get('dst_ip')
            or entry.get('destination_ip')
            or entry.get('dst_addr')
        )

        src_port = (
            source.get('port')
            or entry.get('src_port')
            or entry.get('source_port')
        )
        dst_port = (
            destination.get('port')
            or entry.get('dst_port')
            or entry.get('destination_port')
        )

        protocol = (
            event.get('protocol')
            or entry.get('protocol')
            or entry.get('proto')
            or entry.get('ip_proto')
        )
        protocol = self._normalize_protocol(protocol)

        pkt_len = (
            event.get('packet', {}).get('length')
            or event.get('packet', {}).get('pkt_len')
            or entry.get('packet_len')
            or entry.get('payload_len')
            or entry.get('pkt_len')
            or 0
        )

        if not timestamp or not src_ip or not dst_ip:
            logger.debug('Skipping record with missing essential fields.')
            return None

        try:
            pkt_len = int(pkt_len)
        except (TypeError, ValueError):
            pkt_len = 0

        alert = entry.get('alert', {}) if isinstance(entry.get('alert', {}), dict) else {}
        rule = entry.get('rule', {}) if isinstance(entry.get('rule', {}), dict) else {}
        rule_sid = alert.get('sid') or alert.get('signature_id') or rule.get('sid')
        alert_msg = alert.get('msg') or alert.get('message') or entry.get('msg')

        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': int(src_port) if src_port else 0,
            'dst_port': int(dst_port) if dst_port else 0,
            'protocol': protocol,
            'pkt_len': pkt_len,
            'rule_sid': rule_sid,
            'alert_msg': alert_msg,
        }
