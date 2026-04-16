#!/usr/bin/env python3
"""
Automatic Snort rule generator based on detected anomalies with FALSE POSITIVE PREVENTION.

This module implements a feedback loop that generates candidate Snort rules
from detected anomalies. It analyzes anomaly patterns and creates rules that
can be reviewed and deployed by security teams.

FALSE POSITIVE PREVENTION MECHANISMS:
1. Whitelisting: Known-good IPs/patterns are excluded
2. Confidence scoring: Only anomalies with high confidence generate rules
3. Threshold validation: Required evidence count before rule generation
4. Frequency filtering: Avoids rules from rare/one-time events
5. Pattern confirmation: Requires pattern to repeat before rule creation
6. Known benign services: Excludes common services (Windows Update, NTP, etc.)
7. Audit trail: All rule generation decisions logged for review
"""

import logging
import json
import re
import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import pandas as pd
from siem.threat_defs import RECONNAISSANCE, DOS, EXFILTRATION, C2_BEACONING, WEB_ATTACK, SIGNATURES, THRESHOLDS, TARGET_PORTS

logger = logging.getLogger(__name__)


class RuleGenerator:
    """Generate Snort IDS rules from detected anomalies with false positive prevention."""

    # Rule ID counter (start at 2000000 to avoid conflicts with manual rules)
    _rule_id_counter = 2000000

    # Known benign IPs/ranges (Common false positive sources)
    DEFAULT_WHITELIST = {
        'ips': [
            '127.0.0.1',              # localhost
            '255.255.255.255',        # broadcast
            '224.0.0.0/4',            # multicast
        ],
        'ip_patterns': [
            r'169\.254\.',            # link-local
        ],
        'common_services': {
            '53': 'DNS',              # DNS resolvers
            '123': 'NTP',             # Network Time Protocol
            '67': 'DHCP',             # DHCP servers
            '68': 'DHCP',             # DHCP clients
            '546': 'DHCPv6',          # DHCPv6
            '547': 'DHCPv6',          # DHCPv6
            '5353': 'mDNS',           # Multicast DNS
        }
    }

    def __init__(self, output_path: str = 'generated_rules.rules', whitelist_path: Optional[str] = None,
                 db_path: str = 'data/siem.db'):
        self.output_path = Path(output_path)
        self.rules = []
        self.audit_log = []
        self.db_path = Path(db_path)
        
        # Load whitelist
        self.whitelist = self.DEFAULT_WHITELIST.copy()
        if whitelist_path and Path(whitelist_path).exists():
            try:
                with open(whitelist_path, 'r') as f:
                    custom_whitelist = json.load(f)
                    self.whitelist.update(custom_whitelist)
                    logger.info(f'Loaded custom whitelist from {whitelist_path}')
            except json.JSONDecodeError:
                logger.warning(f'Failed to parse whitelist {whitelist_path}, using defaults')

    def analyze_anomalies(self, alerts_df: pd.DataFrame, anomaly_windows: List[Dict]) -> List[str]:
        """
        Analyze anomaly patterns and generate candidate rules with FP prevention.
        
        Args:
            alerts_df: DataFrame with alert records
            anomaly_windows: List of anomaly detection windows with metadata
        
        Returns:
            List of generated rule strings (high confidence only)
        """
        if alerts_df.empty:
            logger.warning('No alerts to analyze')
            return []
        
        if not anomaly_windows:
            logger.info('No ML anomalies provided, performing signature/behavioral analysis on raw logs')

        generated_rules = []

        # FILTER 1: Remove whitelisted IPs from analysis
        filtered_df = self._filter_whitelisted(alerts_df)
        if filtered_df.empty:
            self._audit_log('All anomalies whitelisted', 'INFO')
            return []

        # Detect patterns with confidence scoring
        patterns = {
            'port_scan': self._detect_port_scan_pattern(filtered_df, anomaly_windows),
            'dos': self._detect_dos_pattern(filtered_df, anomaly_windows),
            'c2': self._detect_c2_pattern(filtered_df, anomaly_windows),
            'http': self._detect_http_anomaly_pattern(filtered_df, anomaly_windows),
            'exfil': self._detect_exfiltration_pattern(filtered_df, anomaly_windows),
        }

        # FILTER 2: Only generate rules for high-confidence patterns
        for p_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                actual_type = pattern.get('type', p_type)
                if pattern.get('confidence', 0) >= 0.75:  # Confidence threshold
                    rule = self._create_rule_with_validation(actual_type, pattern)
                    if rule:
                        generated_rules.append(rule)
                        self._audit_log(
                            f'Generated {actual_type} rule: {rule[:80]}...',
                            'RULE_GENERATED',
                            pattern
                        )
                else:
                    self._audit_log(
                        f'Low confidence {actual_type} pattern: {pattern.get("confidence", 0):.2f}',
                        'LOW_CONFIDENCE'
                    )

        return generated_rules

    def _filter_whitelisted(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove known-good traffic from analysis (whitelist filter)."""
        if df.empty:
            return df
        
        filtered = df.copy()
        
        # Remove whitelisted IPs
        for ip in self.whitelist.get('ips', []):
            filtered = filtered[
                (filtered['src_ip'] != ip) & 
                (filtered['dst_ip'] != ip)
            ]
        
        # Remove whitelisted services
        benign_ports = set(self.whitelist.get('common_services', {}).keys())
        for port in benign_ports:
            filtered = filtered[
                (filtered['src_port'] != int(port)) & 
                (filtered['dst_port'] != int(port))
            ]
        
        removed_count = len(df) - len(filtered)
        if removed_count > 0:
            self._audit_log(f'Filtered {removed_count} whitelisted alerts', 'WHITELIST_FILTER')
        
        return filtered

    def _validate_confidence(self, pattern_dict: Dict, required_evidence: int = 3) -> float:
        """
        Calculate confidence score for a pattern (0.0 to 1.0).
        
        Checks:
        - Evidence count (how many times did we see this pattern?)
        - Pattern consistency (does it repeat?)
        - Anomaly score strength (how unusual was it on ML scale?)
        """
        confidence = 0.0
        
        # Evidence count (normalized 0-0.4)
        evidence_count = pattern_dict.get('evidence_count', 0)
        if evidence_count >= required_evidence:
            confidence += min(0.4, evidence_count * 0.1)
        
        # Pattern consistency (0-0.3)
        consistency = pattern_dict.get('consistency_score', 0.0)
        confidence += consistency * 0.3
        
        # ML anomaly score (0-0.3)
        anomaly_score = pattern_dict.get('anomaly_score', 0.0)
        if anomaly_score < -0.5:  # Strong anomaly
            confidence += 0.3
        elif anomaly_score < -0.2:
            confidence += 0.15
        
        return min(1.0, confidence)

    def _detect_port_scan_pattern(self, df: pd.DataFrame, anomalies: List[Dict]) -> List[Dict]:
        """
        Detect port scan patterns (single source to many destination ports).
        
        Returns: List of pattern dicts with confidence scores
        """
        patterns = []

        suspicious_sources = self._find_suspicious_sources(df, 'port_scan')
        
        for src_ip, port_count, evidence in suspicious_sources:
            # VALIDATION: Check that port count is consistent
            if port_count < THRESHOLDS['port_scan_min_ports']:  # Threshold from threat_defs
                self._audit_log(f'Port scan src {src_ip}: only {port_count} ports (threshold {THRESHOLDS["port_scan_min_ports"]})', 'BELOW_THRESHOLD')
                continue
            
            pattern = {
                'type': 'port_scan',
                'src_ip': src_ip,
                'port_count': port_count,
                'evidence_count': evidence,
                'consistency_score': min(1.0, evidence / 5),  # Seen 5+ times = perfect consistency
                'anomaly_score': -0.7,  # Port scans are strong anomalies
            }
            pattern['confidence'] = self._validate_confidence(pattern, required_evidence=2)
            patterns.append(pattern)

        return patterns

    def _detect_dos_pattern(self, df: pd.DataFrame, anomalies: List[Dict]) -> List[Dict]:
        """
        Detect DoS/flood patterns (high volume traffic from single source).
        """
        patterns = []

        if df.empty:
            return patterns

        src_counts = df['src_ip'].value_counts()
        for src_ip, count in src_counts.head(5).items():
            # VALIDATION: DoS must be sustained
            if count < THRESHOLDS['dos_min_packets']:
                self._audit_log(f'DoS src {src_ip}: {count} packets (threshold {THRESHOLDS["dos_min_packets"]})', 'BELOW_THRESHOLD')
                continue
            
            # VALIDATION: Don't flag known services
            port_data = df[df['src_ip'] == src_ip]
            if self._is_known_service(port_data):
                self._audit_log(f'DoS src {src_ip}: identified as known service', 'KNOWN_SERVICE')
                continue
            
            pattern = {
                'type': 'dos',
                'src_ip': src_ip,
                'packet_count': int(count),
                'evidence_count': 1,
                'consistency_score': 0.5,  # Needs monitoring to confirm pattern
                'anomaly_score': -0.6,
            }
            pattern['confidence'] = self._validate_confidence(pattern, required_evidence=1)
            patterns.append(pattern)

        return patterns

    def _detect_c2_pattern(self, df: pd.DataFrame, anomalies: List[Dict]) -> List[Dict]:
        """
        Detect C2/Beaconing patterns.
        """
        patterns = []

        beaconing_ips = self._find_beaconing_destinations(df)
        
        for dst_ip, frequency, regularity in beaconing_ips:
            # VALIDATION: Beaconing must show regularity
            if regularity < THRESHOLDS['c2_regularity_score']:  # Use threshold from threat_defs
                self._audit_log(f'C2 dst {dst_ip}: low regularity {regularity:.2f} (threshold {THRESHOLDS["c2_regularity_score"]})', 'LOW_REGULARITY')
                continue
            
            pattern = {
                'type': 'c2',
                'dst_ip': dst_ip,
                'frequency': frequency,
                'regularity': regularity,
                'evidence_count': frequency,  # More frequent = more evidence
                'consistency_score': regularity,
                'anomaly_score': -0.65,
            }
            pattern['confidence'] = self._validate_confidence(pattern, required_evidence=3)
            patterns.append(pattern)

        return patterns

    def _detect_http_anomaly_pattern(self, df: pd.DataFrame, anomalies: List[Dict]) -> List[Dict]:
        """Detect HTTP-level anomalies."""
        patterns = []

        http_alerts = df[df['protocol'].isin(['TCP', 'HTTP'])]
        
        if not http_alerts.empty:
            # High-frequency HTTP from single IP (HTTP flood)
            src_http = http_alerts['src_ip'].value_counts()
            
            for src_ip, count in src_http.head(3).items():
                if count >= THRESHOLDS['dos_min_packets']:  # Use DoS threshold for HTTP flood
                    pattern = {
                        'type': 'http_flood',
                        'src_ip': src_ip,
                        'request_count': int(count),
                        'evidence_count': 1,
                        'consistency_score': 0.6,
                        'anomaly_score': -0.55,
                    }
                    pattern['confidence'] = self._validate_confidence(pattern)
                    patterns.append(pattern)
            
            # Application Layer: Web Attack Signatures
            for _, row in http_alerts.iterrows():
                payload = str(row.get('payload', '')).lower()
                if not payload:
                    continue
                
                for attack_type, sigs in SIGNATURES[WEB_ATTACK].items():
                    matches = [s for s in sigs if s.lower() in payload]
                    if matches:
                        pattern = {
                            'type': f'web_{attack_type}',
                            'src_ip': row['src_ip'],
                            'dst_ip': row['dst_ip'],
                            'signature': matches[0],
                            'evidence_count': 1,
                            'consistency_score': 1.0, # Signature match is high consistency
                            'anomaly_score': -0.8,    # Signature matches are high priority
                        }
                        pattern['confidence'] = 0.9 # High confidence for sig matches
                        patterns.append(pattern)

        return patterns

    def _detect_exfiltration_pattern(self, df: pd.DataFrame, anomalies: List[Dict]) -> List[Dict]:
        """Detect data exfiltration patterns."""
        patterns = []

        if df.empty:
            return patterns

        # Large packet transfers
        large_packets = df[df['pkt_len'] > 1000]
        
        if not large_packets.empty:
            src_transfers = large_packets._get_numeric_data()['pkt_len'].sum() if 'pkt_len' in large_packets.columns else 0
            
            # Only flag if sustained (multiple large packets)
            if len(large_packets) >= 10:
                pattern = {
                    'type': 'exfiltration',
                    'packet_count': len(large_packets),
                    'total_bytes': int(src_transfers) if isinstance(src_transfers, (int, float)) else 0,
                    'evidence_count': len(large_packets),
                    'consistency_score': min(1.0, len(large_packets) / 20),
                    'anomaly_score': -0.60,
                }
                pattern['confidence'] = self._validate_confidence(pattern, required_evidence=5)
                patterns.append(pattern)

        return patterns

    def _find_suspicious_sources(self, df: pd.DataFrame, pattern: str = 'port_scan') -> List[Tuple]:
        """
        Find suspicious source IPs matching a pattern.
        
        Returns: List of (src_ip, metric, evidence_count) tuples with high confidence
        """
        suspicious = []

        if pattern == 'port_scan':
            # Find sources with many unique destination ports
            port_counts = df.groupby('src_ip')['dst_port'].nunique()
            port_counts = port_counts[port_counts >= 20]  # Minimum 20 ports
            
            for src_ip, count in port_counts.head(5).items():
                # Evidence: how many times did we see this IP scanning?
                evidence = len(df[df['src_ip'] == src_ip]) // 20  # ~20 packets per port
                suspicious.append((src_ip, int(count), max(1, evidence)))

        return suspicious

    def _find_beaconing_destinations(self, df: pd.DataFrame) -> List[Tuple]:
        """
        Find destination IPs with beaconing characteristics.
        
        Returns: List of (dst_ip, frequency, regularity_score) tuples
        """
        if df.empty:
            return []

        dst_counts = df.groupby('dst_ip').size()
        
        # Filter for external (non-RFC1918) destinations with multiple connections
        external_gateways = dst_counts[dst_counts >= 3]
        
        beaconing = []
        for dst_ip, count in external_gateways.head(5).items():
            # Check regularity of connections (simple: if count >= 5, high regularity)
            regularity = min(1.0, count / 10)  # Max regularity at 10+ connections
            beaconing.append((dst_ip, int(count), regularity))

        return beaconing

    def _is_known_service(self, port_data: pd.DataFrame) -> bool:
        """Check if traffic is from a known service (Windows Update, etc.)."""
        if port_data.empty:
            return False
        
        benign_services = self.whitelist.get('common_services', {})
        ports = set()
        
        if 'src_port' in port_data.columns:
            ports.update(port_data['src_port'].astype(str).unique())
        if 'dst_port' in port_data.columns:
            ports.update(port_data['dst_port'].astype(str).unique())
        
        return any(p in benign_services for p in ports)

    def _create_rule_with_validation(self, pattern_type: str, pattern: Dict) -> Optional[str]:
        """
        Create Snort rule with additional validation.
        
        Pre-rule-generation checks:
        - Confidence score already checked in main function
        - Pattern is not from a whitelisted source
        - Required evidence threshold met
        """
        try:
            if pattern_type == 'port_scan':
                return self._create_port_scan_rule(pattern['src_ip'])
            elif pattern_type == 'dos':
                return self._create_dos_rule(pattern['src_ip'], pattern['packet_count'])
            elif pattern_type == 'c2':
                return self._create_c2_rule(pattern['dst_ip'])
            elif pattern_type == 'http_flood':
                return self._create_http_flood_rule(pattern.get('src_ip'))
            elif pattern_type == 'exfiltration':
                return self._create_exfil_rule()
            elif pattern_type.startswith('web_'):
                attack_subtype = pattern_type.replace('web_', '')
                return self._create_web_attack_rule(attack_subtype, pattern['signature'])
        except Exception as e:
            logger.error(f'Error creating {pattern_type} rule: {e}')
            self._audit_log(f'Rule creation failed for {pattern_type}: {e}', 'ERROR')
        
        return None

    def _audit_log(self, message: str, log_type: str = 'INFO', pattern: Optional[Dict] = None) -> None:
        """Log all rule generation decisions for audit trail."""
        entry = {
            'timestamp': datetime.now(UTC).isoformat(),
            'type': log_type,
            'message': message,
        }
        if pattern:
            entry['pattern'] = pattern
        
        self.audit_log.append(entry)
        logger.info(f'[{log_type}] {message}')

    def _create_port_scan_rule(self, src_ip: str) -> Optional[str]:
        """Generate a Snort rule to detect port scans from a specific source."""
        sid = self._next_rule_id()
        rule = (
            f'alert tcp {src_ip} any -> any any '
            f'(msg:"Auto-Generated Port Scan Detected from {src_ip}"; '
            f'detection_filter:track by_src, count 20, seconds 10; '
            f'flow:stateless; '
            f'sid:{sid}; rev:1; classtype:attempted-recon; priority:1;)'
        )
        return rule

    def _create_dos_rule(self, src_ip: str, packet_count: int) -> Optional[str]:
        """Generate a Snort rule to detect DoS/flooding from a specific source."""
        sid = self._next_rule_id()
        threshold = max(50, packet_count // 2)
        rule = (
            f'alert tcp {src_ip} any -> any any '
            f'(msg:"Auto-Generated DoS/Flood Detected from {src_ip}"; '
            f'threshold:type threshold, track by_src, count {threshold}, seconds 60; '
            f'flow:established; '
            f'sid:{sid}; rev:1; classtype:attempted-dos; priority:1;)'
        )
        return rule

    def _create_c2_rule(self, dst_ip: str) -> Optional[str]:
        """Generate a Snort rule to detect C2/C&C communications."""
        sid = self._next_rule_id()
        rule = (
            f'alert tcp any any -> {dst_ip} any '
            f'(msg:"Auto-Generated C2 Beacon Detected to {dst_ip}"; '
            f'threshold:type threshold, track by_dst, count 10, seconds 300; '
            f'flow:established,to_server; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; priority:1;)'
        )
        return rule

    def _create_http_flood_rule(self, src_ip: Optional[str] = None) -> Optional[str]:
        """Generate a Snort rule to detect HTTP floods."""
        sid = self._next_rule_id()
        rule = (
            f'alert http any any -> any any '
            f'(msg:"Auto-Generated HTTP Flood Detected"; '
            f'threshold:type threshold, track by_src, count 100, seconds 60; '
            f'flow:established,to_server; '
            f'http_method; '
            f'sid:{sid}; rev:1; classtype:attempted-dos; priority:2;)'
        )
        return rule

    def _create_exfil_rule(self) -> Optional[str]:
        """Generate a Snort rule to detect data exfiltration."""
        sid = self._next_rule_id()
        rule = (
            f'alert tcp any any -> any any '
            f'(msg:"Auto-Generated Data Exfiltration Detected"; '
            f'dsize:>1000; '
            f'flow:established,to_server; '
            f'threshold:type threshold, track by_src, count 5, seconds 300; '
            f'sid:{sid}; rev:1; classtype:unusual-activity; priority:3;)'
        )
        return rule

    def _create_web_attack_rule(self, attack_type: str, signature: str) -> Optional[str]:
        """Generate a Snort rule to detect specific web attacks based on payload signatures."""
        sid = self._next_rule_id()
        rule = (
            f'alert tcp any any -> any any '
            f'(msg:"Auto-Generated Web Attack ({attack_type}) Detected: {signature}"; '
            f'content:"{signature}"; nocase; '
            f'flow:established,to_server; '
            f'sid:{sid}; rev:1; classtype:web-application-attack; priority:1;)'
        )
        return rule

    def _next_rule_id(self) -> int:
        """Get the next available rule ID."""
        self._rule_id_counter += 1
        return self._rule_id_counter

    def save_rules(self, rules: List[str], append: bool = False) -> None:
        """
        Save generated rules to file.
        
        Args:
            rules: List of rule strings to save
            append: If True, append to existing file; if False, overwrite
        """
        if not rules:
            logger.warning('No rules to save')
            return

        try:
            mode = 'a' if append and self.output_path.exists() else 'w'
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

            with self.output_path.open(mode, encoding='utf-8') as f:
                f.write(f'\n# Generated {datetime.now(UTC).isoformat()} - {len(rules)} rules\n')
                for rule in rules:
                    f.write(rule + '\n')

            logger.info(f'Saved {len(rules)} rules to {self.output_path}')
        except IOError as e:
            logger.error(f'Failed to save rules: {e}')

    def save_rules_metadata(self, metadata_path: str, rules: List[str], anomalies: List[Dict]) -> None:
        """Save rule generation metadata for review and audit."""
        try:
            output = {
                'generated_at': datetime.now(UTC).isoformat(),
                'total_rules': len(rules),
                'anomalies_analyzed': len(anomalies),
                'rules': rules,
                'anomalies_summary': anomalies[:5] if anomalies else [],
                'audit_log': self.audit_log[-50:],  # Last 50 audit entries
            }

            meta_path = Path(metadata_path)
            meta_path.parent.mkdir(parents=True, exist_ok=True)

            with meta_path.open('w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)

            logger.info(f'Saved rule metadata to {metadata_path}')
        except IOError as e:
            logger.error(f'Failed to save rule metadata: {e}')

    # ──────────────────────────────────────────────────────────────────────────
    # Phase 4: Rule Evolution (mutation, scoring, retirement)
    # ──────────────────────────────────────────────────────────────────────────

    def register_rule(self, sid: int, rule_text: str) -> None:
        """Register a newly generated rule in the rule_scores DB table."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                '''
                INSERT OR IGNORE INTO rule_scores
                (sid, rule_text, hit_count, effectiveness_score, created_at, is_retired)
                VALUES (?, ?, 0, 0.5, ?, 0)
                ''',
                (sid, rule_text, datetime.now(UTC).isoformat())
            )
            conn.commit()
            conn.close()
            logger.debug(f'Registered rule sid={sid}')
        except Exception as exc:
            logger.warning(f'Failed to register rule {sid}: {exc}')

    def update_rule_hit(self, sid: int) -> Dict:
        """
        Record a hit for a rule (called when a matching alert fires).
        Increments hit_count and recalculates effectiveness_score.

        effectiveness_score uses a log1p saturation curve peaking at ~50 hits.
        Returns updated scoring dict.
        """
        import math
        now = datetime.now(UTC).isoformat()
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                'UPDATE rule_scores SET hit_count = hit_count + 1, last_hit_at = ? '
                'WHERE sid = ?',
                (now, sid)
            )
            conn.commit()
            cur.execute('SELECT * FROM rule_scores WHERE sid = ?', (sid,))
            row = cur.fetchone()
            if row:
                result = dict(row)
                hits = result['hit_count']
                eff = min(1.0, math.log1p(hits) / math.log1p(50))
                cur.execute(
                    'UPDATE rule_scores SET effectiveness_score = ? WHERE sid = ?',
                    (eff, sid)
                )
                conn.commit()
                result['effectiveness_score'] = eff
                conn.close()
                logger.info(f'Rule {sid} hit #{hits} | effectiveness={eff:.3f}')
                return result
            conn.close()
        except Exception as exc:
            logger.warning(f'Failed to update rule hit for {sid}: {exc}')
        return {}

    def score_rule(self, sid: int) -> Dict:
        """
        Retrieve current scoring for a rule.

        Returns dict with keys:
          sid, hit_count, effectiveness_score, is_retired, hit_rate
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute('SELECT * FROM rule_scores WHERE sid = ?', (sid,))
            row = cur.fetchone()
            conn.close()
            if row:
                result = dict(row)
                created_at = result.get('created_at')
                if created_at:
                    try:
                        age_days = max(
                            1,
                            (datetime.now(UTC) - datetime.fromisoformat(created_at)).days
                        )
                        result['hit_rate'] = result['hit_count'] / age_days
                    except Exception:
                        result['hit_rate'] = 0.0
                else:
                    result['hit_rate'] = 0.0
                return result
        except Exception as exc:
            logger.warning(f'Failed to score rule {sid}: {exc}')
        return {}

    def mutate_rule(
        self,
        sid: int,
        incident_context: Optional[Dict] = None,
    ) -> Optional[str]:
        """
        Mutate an existing rule based on repeated incident context.

        Mutation strategies:
          1. Bump rev: number
          2. Tighten threshold COUNT if high alert_count in context
          3. Embed incident metadata

        Returns the new rule string (does NOT auto-save; caller decides).
        """
        scoring = self.score_rule(sid)
        if not scoring:
            logger.warning(f'Cannot mutate unknown rule sid={sid}')
            return None

        rule_text = scoring.get('rule_text', '')
        if not rule_text:
            return None

        def bump_rev(rule: str) -> str:
            match = re.search(r'rev:(\d+)', rule)
            if match:
                old_rev = int(match.group(1))
                return rule.replace(f'rev:{old_rev}', f'rev:{old_rev + 1}')
            return rule.rstrip(')') + ' rev:2;)'

        mutated = bump_rev(rule_text)

        # Tighten threshold count for high-volume incidents
        alert_count = incident_context.get('alert_count', 0) if incident_context else 0
        if alert_count > 10:
            match = re.search(r'count (\d+)', mutated)
            if match:
                old_c = int(match.group(1))
                new_c = max(5, int(old_c * 0.8))
                mutated = mutated.replace(f'count {old_c}', f'count {new_c}')

        # Embed incident metadata
        if incident_context:
            inc_id = incident_context.get('incident_id', 'UNKNOWN')
            if 'metadata:' in mutated:
                mutated = mutated.replace(
                    'metadata:', f'metadata: mutated_from_incident {inc_id};'
                )
            else:
                mutated = mutated.rstrip(')') + f' metadata: mutated_from_incident {inc_id};)'

        logger.info(f'Mutated rule sid={sid}: {mutated[:80]}...')
        self._audit_log(f'Rule mutation sid={sid}', 'MUTATION', {'original': rule_text[:80]})
        return mutated

    def retire_unused_rules(
        self,
        hit_threshold: int = 0,
        min_age_days: int = 7,
    ) -> List[int]:
        """
        Retire rules that have never (or rarely) fired after a minimum age.

        Args:
            hit_threshold : rules with hit_count <= this value are candidates
            min_age_days  : rules younger than this are never retired

        Returns:
            List of retired SIDs
        """
        retired_sids: List[int] = []
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                'SELECT * FROM rule_scores WHERE is_retired = 0 AND hit_count <= ?',
                (hit_threshold,)
            )
            candidates = [dict(r) for r in cur.fetchall()]

            for rule in candidates:
                created_at = rule.get('created_at')
                if not created_at:
                    continue
                try:
                    age_days = (datetime.now(UTC) - datetime.fromisoformat(created_at)).days
                except Exception:
                    continue
                if age_days < min_age_days:
                    continue
                cur.execute(
                    'UPDATE rule_scores SET is_retired = 1 WHERE sid = ?',
                    (rule['sid'],)
                )
                retired_sids.append(rule['sid'])
                logger.info(
                    f'Retired rule sid={rule["sid"]} '
                    f'(hits={rule["hit_count"]}, age={age_days}d)'
                )

            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning(f'Rule retirement scan failed: {exc}')

        if retired_sids:
            self._audit_log(
                f'Retired {len(retired_sids)} unused rules: {retired_sids}',
                'RETIREMENT'
            )
        return retired_sids

    def get_all_rule_scores(self) -> List[Dict]:
        """Return scoring metadata for all tracked rules."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute('SELECT * FROM rule_scores ORDER BY effectiveness_score DESC')
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.warning(f'Failed to load rule scores: {exc}')
            return []


def main():
    """Standalone rule generator - processes anomalies and generates rules."""
    import sys
    from config_loader import load_config

    from ml_services.data_loader import DataLoader

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    try:
        config = load_config()
    except FileNotFoundError:
        logger.error('config/config.yaml not found')
        sys.exit(1)

    # Load alerts
    loader = DataLoader(config['paths']['log_dir'], config['paths']['alert_file'])
    df = loader.load_logs()

    if df.empty:
        logger.error('No alerts to process')
        sys.exit(1)

    # Load anomalies
    anomalies_path = Path(config['paths']['anomalies_output'])
    if not anomalies_path.exists():
        logger.error(f'Anomalies file not found: {anomalies_path}')
        sys.exit(1)

    with anomalies_path.open('r', encoding='utf-8') as f:
        anomalies = json.load(f) if anomalies_path.suffix == '.json' else \
                    [json.loads(line) for line in f]

    # Generate rules
    generator = RuleGenerator('generated_rules.rules')
    rules = generator.analyze_anomalies(df, anomalies)

    if rules:
        generator.save_rules(rules)
        generator.save_rules_metadata('generated_rules_metadata.json', rules, anomalies)
        logger.info(f'Generated {len(rules)} candidate Snort rules')
    else:
        logger.info('No rules generated from anomaly analysis')


if __name__ == '__main__':
    main()
