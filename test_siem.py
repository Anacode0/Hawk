#!/usr/bin/env python3
"""
SIEM Test Script
Generates sample security events for testing
"""

import socket
import time
import random
from datetime import datetime


class SyslogTestGenerator:
    """
    Generate test syslog messages for SIEM testing
    """

    def __init__(self, siem_host='localhost', siem_port=5140):
        self.siem_host = siem_host
        self.siem_port = siem_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_log(self, message, priority=133):
        """
        Send a syslog message

        Args:
            message: Log message
            priority: Syslog priority (default: 133 = local4.notice)
        """
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        syslog_msg = f"<{priority}>{timestamp} testdevice {message}"

        try:
            self.sock.sendto(syslog_msg.encode(), (self.siem_host, self.siem_port))
            print(f"✓ Sent: {message[:80]}")
        except Exception as e:
            print(f"✗ Error sending: {e}")

    def generate_firewall_blocks(self, count=5):
        """Generate firewall block events"""
        print(f"\nGenerating {count} firewall block events...")

        src_ips = ['10.0.0.5', '10.0.0.10', '192.168.50.25', '172.16.0.100']
        dst_ips = ['192.168.1.100', '192.168.1.200', '10.1.1.50']
        ports = [22, 23, 3389, 445, 1433, 3306, 5432]

        for i in range(count):
            src = random.choice(src_ips)
            dst = random.choice(dst_ips)
            port = random.choice(ports)
            proto = random.choice(['tcp', 'udp'])

            message = f"DENY src={src} dst={dst} port={port} proto={proto} action=blocked"
            self.send_log(message)
            time.sleep(0.2)

    def generate_auth_failures(self, count=5, same_user=True):
        """Generate authentication failure events"""
        print(f"\nGenerating {count} authentication failure events...")

        usernames = ['admin', 'root', 'administrator', 'user', 'backup']
        src_ips = ['203.0.113.50', '198.51.100.25', '192.0.2.100']

        if same_user:
            # Simulate brute force - same user, same IP
            user = 'admin'
            ip = random.choice(src_ips)
            for i in range(count):
                message = f"Authentication failed for user {user} from {ip} - invalid password"
                self.send_log(message, priority=132)  # auth.warning
                time.sleep(0.3)
        else:
            # Random failures
            for i in range(count):
                user = random.choice(usernames)
                ip = random.choice(src_ips)
                message = f"Authentication failed for user {user} from {ip} - invalid password"
                self.send_log(message, priority=132)
                time.sleep(0.2)

    def generate_port_scan(self, src_ip='198.51.100.25'):
        """Generate port scan event"""
        print(f"\nGenerating port scan events from {src_ip}...")

        # Multiple connections to different ports (simulating port scan)
        for port in [21, 22, 23, 25, 80, 110, 143, 443, 3389, 8080, 3306, 5432]:
            message = f"DENY src={src_ip} dst=192.168.1.100 port={port} proto=tcp"
            self.send_log(message)
            time.sleep(0.1)

    def generate_vpn_connections(self, count=3):
        """Generate VPN connection events"""
        print(f"\nGenerating {count} VPN connection events...")

        users = ['john.doe', 'jane.smith', 'bob.wilson']
        ips = ['203.0.113.75', '198.51.100.100', '192.0.2.250']

        for i in range(count):
            user = random.choice(users)
            ip = random.choice(ips)
            message = f"SSL-VPN connection established for user {user} from {ip}"
            self.send_log(message, priority=134)  # local4.info
            time.sleep(0.3)

    def generate_ddos_event(self):
        """Generate DDoS attack event"""
        print(f"\n⚠Generating DDoS attack event...")

        message = "DDoS attack detected: SYN flooding from 198.51.100.50 - 50000 packets/sec"
        self.send_log(message, priority=130)  # local4.critical

    def generate_config_changes(self, count=2):
        """Generate configuration change events"""
        print(f"\n⚙Generating {count} configuration change events...")

        changes = [
            "Configuration changed by admin - firewall rule added",
            "Configuration updated - access list modified",
            "System configuration saved by user administrator"
        ]

        for i in range(count):
            message = random.choice(changes)
            self.send_log(message, priority=133)
            time.sleep(0.3)

    def generate_successful_auth(self, count=3):
        """Generate successful authentication events"""
        print(f"\nGenerating {count} successful authentication events...")

        users = ['admin', 'operator', 'monitor']
        ips = ['192.168.1.50', '192.168.1.51', '10.0.0.100']

        for i in range(count):
            user = random.choice(users)
            ip = random.choice(ips)
            message = f"Authentication successful for user {user} from {ip}"
            self.send_log(message, priority=134)
            time.sleep(0.2)

    def run_full_test(self):
        """Run complete test suite"""
        print("=" * 60)
        print("SIEM Test Suite")
        print(f"Target: {self.siem_host}:{self.siem_port}")
        print("=" * 60)

        # Test 1: Normal traffic
        self.generate_successful_auth(3)
        time.sleep(1)

        # Test 2: Firewall blocks
        self.generate_firewall_blocks(5)
        time.sleep(1)

        # Test 3: Brute force attack (should trigger alert)
        self.generate_auth_failures(6, same_user=True)
        time.sleep(1)

        # Test 4: Port scan (should trigger alert)
        self.generate_port_scan()
        time.sleep(1)

        # Test 5: VPN connections
        self.generate_vpn_connections(3)
        time.sleep(1)

        # Test 6: Configuration changes
        self.generate_config_changes(2)
        time.sleep(1)

        # Test 7: Critical event
        self.generate_ddos_event()

        print("\n" + "=" * 60)
        print("✓ Test suite completed!")
        print("Check the SIEM dashboard for alerts and statistics")
        print("=" * 60)

    def close(self):
        """Close socket"""
        self.sock.close()


def interactive_menu():
    """Interactive menu for testing"""
    generator = SyslogTestGenerator()

    while True:
        print("\n" + "=" * 60)
        print("SIEM Test Menu")
        print("=" * 60)
        print("1. Run full test suite")
        print("2. Generate firewall blocks")
        print("3. Generate authentication failures (brute force)")
        print("4. Generate port scan")
        print("5. Generate VPN connections")
        print("6. Generate DDoS event")
        print("7. Generate configuration changes")
        print("8. Custom message")
        print("0. Exit")
        print("=" * 60)

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            generator.run_full_test()
        elif choice == '2':
            count = int(input("How many? [5]: ") or "5")
            generator.generate_firewall_blocks(count)
        elif choice == '3':
            count = int(input("How many failures? [6]: ") or "6")
            generator.generate_auth_failures(count, same_user=True)
        elif choice == '4':
            generator.generate_port_scan()
        elif choice == '5':
            count = int(input("How many? [3]: ") or "3")
            generator.generate_vpn_connections(count)
        elif choice == '6':
            generator.generate_ddos_event()
        elif choice == '7':
            count = int(input("How many? [2]: ") or "2")
            generator.generate_config_changes(count)
        elif choice == '8':
            message = input("Enter message: ")
            generator.send_log(message)
        elif choice == '0':
            print("\nExiting...")
            break
        else:
            print("Invalid option!")

    generator.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--auto':
        # Run full test automatically
        generator = SyslogTestGenerator()
        generator.run_full_test()
        generator.close()
    else:
        # Interactive mode
        interactive_menu()
