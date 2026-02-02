#!/usr/bin/env python3
"""
SIEM Log Collector - Syslog Server
Receives syslog messages from network devices and firewalls
"""

import socketserver
import json
import re
from datetime import datetime
from pathlib import Path


class SyslogHandler(socketserver.BaseRequestHandler):
    """
    Handler for incoming syslog messages (UDP)
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        client_ip = self.client_address[0]

        # Decode the syslog message
        try:
            message = data.decode('utf-8')
        except UnicodeDecodeError:
            message = data.decode('latin-1')

        parsed_log = self.parse_syslog(message, client_ip)
        self.store_log(parsed_log)

        # Print to console for monitoring
        print(f"[{parsed_log['timestamp']}] {client_ip}: {parsed_log['message']}")

    def parse_syslog(self, raw_message, source_ip):
        """
        Parse syslog message following RFC 3164/5424
        """
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
            severity = 6  # Informational
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
            0: "Emergency",
            1: "Alert",
            2: "Critical",
            3: "Error",
            4: "Warning",
            5: "Notice",
            6: "Informational",
            7: "Debug"
        }

        # Facility mapping (common ones)
        facility_map = {
            0: "kernel",
            1: "user",
            2: "mail",
            3: "daemon",
            4: "auth",
            16: "local0",
            17: "local1",
            18: "local2",
            19: "local3",
            20: "local4",
            21: "local5",
            22: "local6",
            23: "local7"
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

    def store_log(self, parsed_log):
        """
        Store parsed log to JSON file (one log per line)
        In production, this would go to a database
        """
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        date_str = datetime.now().strftime("%Y-%m-%d")
        log_file = log_dir / f"syslog_{date_str}.jsonl"

        with open(log_file, 'a') as f:
            f.write(json.dumps(parsed_log) + '\n')


class SyslogServer:
    """
    Main syslog server class
    """

    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        """
        Start the syslog server
        Note: Port 514 requires root/admin privileges
        Use port 5140 or higher for testing without sudo
        """
        print(f"Starting SIEM Syslog Collector on {self.host}:{self.port}")
        print("Press Ctrl+C to stop\n")

        try:
            self.server = socketserver.UDPServer((self.host, self.port), SyslogHandler)
            self.server.serve_forever()
        except PermissionError:
            print(f"\nERROR: Permission denied for port {self.port}")
            print("Solutions:")
            print("  1. Run with sudo: sudo python3 syslog_collector.py")
            print("  2. Use a higher port (>1024): python3 syslog_collector.py --port 5140")
            print("     Then configure your devices to send logs to port 5140")
        except KeyboardInterrupt:
            print("\n\nShutting down syslog server...")
            if self.server:
                self.server.shutdown()
        except Exception as e:
            print(f"Error starting server: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='SIEM Syslog Collector')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5140, help='Port number (default: 5140)')

    args = parser.parse_args()

    server = SyslogServer(host=args.host, port=args.port)
    server.start()
