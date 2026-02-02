#!/usr/bin/env python3
"""
SIEM Database Storage Module
Handles storage and retrieval of logs and alerts
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional


class SIEMDatabase:
    """
    SQLite database for SIEM data storage
    In production, you'd use PostgreSQL, Elasticsearch, or similar
    """

    def __init__(self, db_path: str = "siem.db"):
        self.db_path = db_path
        self.conn = None
        self.init_database()

    def init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                hostname TEXT,
                facility TEXT,
                severity TEXT,
                severity_level INTEGER,
                message TEXT,
                raw_message TEXT,
                event_type TEXT,
                event_category TEXT,
                event_severity TEXT,
                extracted_fields TEXT,  -- JSON
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_log_id INTEGER,
                extra_data TEXT,  -- JSON
                status TEXT DEFAULT 'new',  -- new, investigating, resolved, false_positive
                assigned_to TEXT,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_log_id) REFERENCES logs(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reputation TEXT,  -- malicious, suspicious, whitelisted
                first_seen TEXT,
                last_seen TEXT,
                threat_count INTEGER DEFAULT 0,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_event_category ON logs(event_category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')

        self.conn.commit()

    def store_log(self, log_entry: Dict) -> int:
        """
        Store a log entry in the database

        Returns:
            Log ID
        """
        cursor = self.conn.cursor()

        extracted_fields_json = json.dumps(log_entry.get('extracted_fields', {}))

        cursor.execute('''
            INSERT INTO logs (
                timestamp, source_ip, hostname, facility, severity,
                severity_level, message, raw_message, event_type,
                event_category, event_severity, extracted_fields
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry.get('timestamp'),
            log_entry.get('source_ip'),
            log_entry.get('hostname'),
            log_entry.get('facility'),
            log_entry.get('severity'),
            log_entry.get('severity_level'),
            log_entry.get('message'),
            log_entry.get('raw_message'),
            log_entry.get('event_type'),
            log_entry.get('event_category'),
            log_entry.get('event_severity'),
            extracted_fields_json
        ))

        self.conn.commit()
        return cursor.lastrowid

    def store_alert(self, alert: Dict, source_log_id: int = None) -> int:
        """
        Store an alert in the database

        Returns:
            Alert ID
        """
        cursor = self.conn.cursor()

        extra_data_json = json.dumps(alert.get('extra_data', {}))

        cursor.execute('''
            INSERT INTO alerts (
                alert_id, timestamp, title, severity,
                source_log_id, extra_data
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert.get('alert_id'),
            alert.get('timestamp'),
            alert.get('title'),
            alert.get('severity'),
            source_log_id,
            extra_data_json
        ))

        self.conn.commit()
        return cursor.lastrowid

    def get_recent_logs(self, limit: int = 100, event_category: str = None) -> List[Dict]:
        """Get recent logs, optionally filtered by event category"""
        cursor = self.conn.cursor()

        if event_category:
            cursor.execute('''
                SELECT * FROM logs
                WHERE event_category = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (event_category, limit))
        else:
            cursor.execute('''
                SELECT * FROM logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_alerts(self, status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get alerts, optionally filtered by status and severity"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def update_alert_status(self, alert_id: str, status: str, notes: str = None):
        """Update alert status"""
        cursor = self.conn.cursor()

        cursor.execute('''
            UPDATE alerts
            SET status = ?, notes = ?, updated_at = ?
            WHERE alert_id = ?
        ''', (status, notes, datetime.now().isoformat(), alert_id))

        self.conn.commit()

    def get_statistics(self, hours: int = 24) -> Dict:
        """
        Get statistics for the dashboard

        Args:
            hours: Number of hours to look back

        Returns:
            Dictionary with various statistics
        """
        cursor = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()

        cursor.execute('SELECT COUNT(*) as count FROM logs WHERE timestamp > ?', (cutoff,))
        total_logs = cursor.fetchone()['count']

        cursor.execute('''
            SELECT event_severity, COUNT(*) as count
            FROM logs
            WHERE timestamp > ? AND event_severity IS NOT NULL
            GROUP BY event_severity
        ''', (cutoff,))
        logs_by_severity = {row['event_severity']: row['count'] for row in cursor.fetchall()}

        cursor.execute('''
            SELECT event_category, COUNT(*) as count
            FROM logs
            WHERE timestamp > ? AND event_category IS NOT NULL
            GROUP BY event_category
        ''', (cutoff,))
        logs_by_category = {row['event_category']: row['count'] for row in cursor.fetchall()}

        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM logs
            WHERE timestamp > ?
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''', (cutoff,))
        top_source_ips = [dict(row) for row in cursor.fetchall()]

        cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE status = "new"')
        new_alerts = cursor.fetchone()['count']

        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp > ?
            GROUP BY severity
        ''', (cutoff,))
        alerts_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        return {
            'time_period_hours': hours,
            'total_logs': total_logs,
            'logs_by_severity': logs_by_severity,
            'logs_by_category': logs_by_category,
            'top_source_ips': top_source_ips,
            'new_alerts': new_alerts,
            'alerts_by_severity': alerts_by_severity,
            'generated_at': datetime.now().isoformat()
        }

    def search_logs(self, query: str, limit: int = 100) -> List[Dict]:
        """
        Simple text search in logs

        Args:
            query: Search string
            limit: Maximum results

        Returns:
            List of matching log entries
        """
        cursor = self.conn.cursor()

        search_pattern = f"%{query}%"
        cursor.execute('''
            SELECT * FROM logs
            WHERE message LIKE ? OR raw_message LIKE ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (search_pattern, search_pattern, limit))

        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    # Example usage
    db = SIEMDatabase()

    sample_log = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.1',
        'hostname': 'firewall01',
        'facility': 'local4',
        'severity': 'Warning',
        'severity_level': 4,
        'message': 'DENY src=10.0.0.5 dst=192.168.1.100 port=22',
        'raw_message': '<20>Jan 1 12:00:00 firewall01 DENY src=10.0.0.5 dst=192.168.1.100 port=22',
        'event_type': 'firewall_block',
        'event_category': 'firewall_block',
        'event_severity': 'medium',
        'extracted_fields': {
            'action': 'DENY',
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.1.100',
            'dst_port': '22'
        }
    }

    log_id = db.store_log(sample_log)
    print(f"Stored log with ID: {log_id}")

    stats = db.get_statistics(hours=24)
    print(f"\nStatistics:\n{json.dumps(stats, indent=2)}")

    db.close()
