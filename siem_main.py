#!/usr/bin/env python3
"""
SIEM Main Application
Integrates log collection, parsing, analysis, and storage
"""

import socketserver
import threading
import json
from datetime import datetime
from pathlib import Path

from log_parser import LogParser, LogAnalyzer
from siem_database import SIEMDatabase


class IntegratedSyslogHandler(socketserver.BaseRequestHandler):
    """
    Enhanced syslog handler with integrated parsing and analysis
    """

    parser = LogParser()
    analyzer = LogAnalyzer()
    db = SIEMDatabase()

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        client_ip = self.client_address[0]

        try:
            message = data.decode('utf-8')
        except UnicodeDecodeError:
            message = data.decode('latin-1')

        parsed_log = self.parse_syslog(message, client_ip)

        enhanced_log = self.parser.parse(parsed_log)

        log_id = self.db.store_log(enhanced_log)

        alerts = self.analyzer.analyze(enhanced_log)

        for alert in alerts:
            alert_id = self.db.store_alert(alert, source_log_id=log_id)
            print(f"\n🚨 ALERT GENERATED: {alert['title']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Alert ID: {alert['alert_id']}\n")

        event_type = enhanced_log.get('event_type', 'unknown')
        severity = enhanced_log.get('event_severity', 'low')

        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }

        print(f"{severity_emoji.get(severity, '⚪')} [{enhanced_log['timestamp']}] "
              f"{client_ip} | {event_type} | {enhanced_log['message'][:80]}")

    def parse_syslog(self, raw_message, source_ip):
        """Parse syslog message (same as before)"""
        import re

        syslog_pattern = r'^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$'
        match = re.match(syslog_pattern, raw_message)

        if match:
            priority = int(match.group(1))
            timestamp_str = match.group(2)
            hostname = match.group(3)
            message = match.group(4)

            facility = priority >> 3
            severity = priority & 0x07
        else:
            facility = 0
            severity = 6
            timestamp_str = None
            hostname = source_ip
            message = raw_message

        if timestamp_str:
            try:
                current_year = datetime.now().year
                timestamp_str_with_year = f"{timestamp_str} {current_year}"
                timestamp = datetime.strptime(timestamp_str_with_year, "%b %d %H:%M:%S %Y")
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()

        severity_map = {
            0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
            4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug"
        }

        facility_map = {
            0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
            16: "local0", 17: "local1", 18: "local2", 19: "local3",
            20: "local4", 21: "local5", 22: "local6", 23: "local7"
        }

        return {
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "hostname": hostname,
            "facility": facility_map.get(facility, f"unknown({facility})"),
            "severity": severity_map.get(severity, "Unknown"),
            "severity_level": severity,
            "message": message,
            "raw_message": raw_message
        }


class SIEMApplication:
    """
    Main SIEM application
    """

    def __init__(self, syslog_host='0.0.0.0', syslog_port=5140,
                 web_host='0.0.0.0', web_port=5000):
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.web_host = web_host
        self.web_port = web_port
        self.syslog_server = None
        self.web_thread = None

    def start_syslog_server(self):
        """Start the syslog collection server"""
        print(f"Starting Syslog Collector on {self.syslog_host}:{self.syslog_port}")
        try:
            self.syslog_server = socketserver.UDPServer(
                (self.syslog_host, self.syslog_port),
                IntegratedSyslogHandler
            )
            self.syslog_server.serve_forever()
        except Exception as e:
            print(f"Error starting syslog server: {e}")

    def start_web_dashboard(self):
        """Start the web dashboard in a separate thread"""
        from dashboard import app

        print(f"Starting Web Dashboard on http://{self.web_host}:{self.web_port}")
        app.run(host=self.web_host, port=self.web_port, debug=False, use_reloader=False)

    def start(self):
        """Start both syslog server and web dashboard"""
        print("=" * 60)
        print("SIEM System Starting")
        print("=" * 60)
        print()

        self.web_thread = threading.Thread(target=self.start_web_dashboard, daemon=True)
        self.web_thread.start()

        print()
        print("=" * 60)
        print("System Ready!")
        print(f"Dashboard: http://localhost:{self.web_port}")
        print(f"Syslog Receiver: {self.syslog_host}:{self.syslog_port}")
        print()
        print("Configure your network devices to send syslog to this server")
        print("Press Ctrl+C to stop")
        print("=" * 60)
        print()

        try:
            self.start_syslog_server()
        except KeyboardInterrupt:
            print("\n\nShutting down SIEM system...")
            if self.syslog_server:
                self.syslog_server.shutdown()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='SIEM System')
    parser.add_argument('--syslog-host', default='0.0.0.0', help='Syslog bind address')
    parser.add_argument('--syslog-port', type=int, default=5140, help='Syslog port')
    parser.add_argument('--web-host', default='0.0.0.0', help='Web dashboard bind address')
    parser.add_argument('--web-port', type=int, default=5000, help='Web dashboard port')

    args = parser.parse_args()

    app = SIEMApplication(
        syslog_host=args.syslog_host,
        syslog_port=args.syslog_port,
        web_host=args.web_host,
        web_port=args.web_port
    )

    app.start()
