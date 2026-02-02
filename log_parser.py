#!/usr/bin/env python3
"""
SIEM Log Parser
Extracts security-relevant information from network device logs
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Optional


class LogParser:
    """
    Parse network device logs and extract security events
    """

    def __init__(self):
        self.patterns = {
            'firewall_block': {
                'pattern': re.compile(r'(DENY|BLOCK|DROP|REJECT).*?src[=:]?\s*(\d+\.\d+\.\d+\.\d+).*?dst[=:]?\s*(\d+\.\d+\.\d+\.\d+).*?port[=:]?\s*(\d+)', re.IGNORECASE),
                'fields': ['action', 'src_ip', 'dst_ip', 'dst_port'],
                'severity': 'medium',
                'category': 'firewall_block'
            },
            'firewall_allow': {
                'pattern': re.compile(r'(ALLOW|PERMIT|ACCEPT).*?src[=:]?\s*(\d+\.\d+\.\d+\.\d+).*?dst[=:]?\s*(\d+\.\d+\.\d+\.\d+).*?port[=:]?\s*(\d+)', re.IGNORECASE),
                'fields': ['action', 'src_ip', 'dst_ip', 'dst_port'],
                'severity': 'low',
                'category': 'firewall_allow'
            },
            'authentication_success': {
                'pattern': re.compile(r'(login|authentication|auth).*?(success|succeeded|accepted).*?(?:user|username)[=:]?\s*(\S+)', re.IGNORECASE),
                'fields': ['event_type', 'result', 'username'],
                'severity': 'low',
                'category': 'auth_success'
            },
            'authentication_failure': {
                'pattern': re.compile(r'(login|authentication|auth).*?(fail|failed|denied|invalid).*?(?:user|username)[=:]?\s*(\S+)', re.IGNORECASE),
                'fields': ['event_type', 'result', 'username'],
                'severity': 'medium',
                'category': 'auth_failure'
            },
            'port_scan': {
                'pattern': re.compile(r'(port scan|portscan|scan detected).*?(?:from|src)[=:]?\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
                'fields': ['attack_type', 'src_ip'],
                'severity': 'high',
                'category': 'port_scan'
            },
            'ddos_attack': {
                'pattern': re.compile(r'(ddos|dos attack|flooding).*?(?:from|src)[=:]?\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
                'fields': ['attack_type', 'src_ip'],
                'severity': 'critical',
                'category': 'ddos'
            },
            'vpn_connection': {
                'pattern': re.compile(r'(vpn|ipsec|ssl-vpn).*?(connect|connected|established).*?(?:user|username)[=:]?\s*(\S+).*?(?:from|ip)[=:]?\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
                'fields': ['connection_type', 'action', 'username', 'src_ip'],
                'severity': 'low',
                'category': 'vpn_connect'
            },
            'configuration_change': {
                'pattern': re.compile(r'(config|configuration).*?(change|changed|modified|update)', re.IGNORECASE),
                'fields': ['change_type', 'action'],
                'severity': 'medium',
                'category': 'config_change'
            }
        }

    def parse(self, log_entry: Dict) -> Optional[Dict]:
        """
        Parse a log entry and extract security events

        Args:
            log_entry: Dictionary containing parsed syslog data

        Returns:
            Enhanced log entry with extracted security information, or None
        """
        message = log_entry.get('message', '')

        for event_name, pattern_config in self.patterns.items():
            match = pattern_config['pattern'].search(message)
            if match:
                extracted_fields = {}
                for i, field_name in enumerate(pattern_config['fields'], start=1):
                    extracted_fields[field_name] = match.group(i)

                enhanced_entry = log_entry.copy()
                enhanced_entry.update({
                    'event_type': event_name,
                    'event_category': pattern_config['category'],
                    'event_severity': pattern_config['severity'],
                    'extracted_fields': extracted_fields,
                    'parsed_timestamp': datetime.now().isoformat()
                })

                return enhanced_entry

        return log_entry

    def extract_ip_addresses(self, text: str) -> List[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)

    def extract_ports(self, text: str) -> List[int]:
        port_pattern = r'(?:port|dport|sport)[=:]?\s*(\d{1,5})'
        matches = re.findall(port_pattern, text, re.IGNORECASE)
        return [int(p) for p in matches if 0 <= int(p) <= 65535]


class LogAnalyzer:
    """
    Analyze parsed logs for security threats
    """

    def __init__(self):
        self.auth_failure_threshold = 5  # Failed attempts before alert
        self.port_scan_threshold = 10     # Unique ports before alert
        self.failure_counts = {}
        self.port_access_counts = {}

    def analyze(self, log_entry: Dict) -> List[Dict]:
        """
        Analyze log entry and return any alerts

        Returns:
            List of alert dictionaries
        """
        alerts = []
        event_category = log_entry.get('event_category', '')

        if event_category == 'auth_failure':
            alerts.extend(self._check_brute_force(log_entry))

        if event_category == 'firewall_block':
            alerts.extend(self._check_port_scan(log_entry))

        if log_entry.get('event_severity') == 'critical':
            alerts.append(self._create_alert(
                'Critical Event Detected',
                log_entry,
                'critical'
            ))

        return alerts

    def _check_brute_force(self, log_entry: Dict) -> List[Dict]:
        """Check for brute force authentication attempts"""
        alerts = []
        extracted = log_entry.get('extracted_fields', {})
        username = extracted.get('username', 'unknown')
        src_ip = log_entry.get('source_ip', 'unknown')

        key = f"{src_ip}:{username}"
        self.failure_counts[key] = self.failure_counts.get(key, 0) + 1

        if self.failure_counts[key] >= self.auth_failure_threshold:
            alerts.append(self._create_alert(
                f'Brute Force Attack: {self.failure_counts[key]} failed login attempts',
                log_entry,
                'high',
                {
                    'username': username,
                    'source_ip': src_ip,
                    'failure_count': self.failure_counts[key]
                }
            ))
            self.failure_counts[key] = 0

        return alerts

    def _check_port_scan(self, log_entry: Dict) -> List[Dict]:
        alerts = []
        extracted = log_entry.get('extracted_fields', {})
        src_ip = extracted.get('src_ip', 'unknown')
        dst_port = extracted.get('dst_port', '')

        if src_ip not in self.port_access_counts:
            self.port_access_counts[src_ip] = set()

        self.port_access_counts[src_ip].add(dst_port)

        if len(self.port_access_counts[src_ip]) >= self.port_scan_threshold:
            alerts.append(self._create_alert(
                f'Port Scan Detected: {len(self.port_access_counts[src_ip])} unique ports accessed',
                log_entry,
                'high',
                {
                    'source_ip': src_ip,
                    'ports_accessed': len(self.port_access_counts[src_ip])
                }
            ))
            self.port_access_counts[src_ip] = set()

        return alerts

    def _create_alert(self, title: str, log_entry: Dict, severity: str, extra_data: Dict = None) -> Dict:
        """Create an alert dictionary"""
        alert = {
            'alert_id': f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'title': title,
            'severity': severity,
            'source_log': log_entry,
            'extra_data': extra_data or {}
        }
        return alert


if __name__ == "__main__":
    parser = LogParser()
    analyzer = LogAnalyzer()

    sample_logs = [
        {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'hostname': 'firewall01',
            'message': 'DENY src=10.0.0.5 dst=192.168.1.100 port=22 proto=tcp'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'hostname': 'firewall01',
            'message': 'Authentication failed for user admin from 203.0.113.50'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'hostname': 'firewall01',
            'message': 'Port scan detected from 198.51.100.25'
        }
    ]

    print("=== Log Parser Test ===\n")
    for log in sample_logs:
        parsed = parser.parse(log)
        print(f"Original: {log['message']}")
        print(f"Parsed: {json.dumps(parsed, indent=2)}\n")

        alerts = analyzer.analyze(parsed)
        if alerts:
            print(f"ALERTS GENERATED: {len(alerts)}")
            for alert in alerts:
                print(json.dumps(alert, indent=2))
        print("-" * 80)
