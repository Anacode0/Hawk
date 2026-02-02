# Custom SIEM System - Setup Guide

## Overview

This is a custom-built Security Information and Event Management (SIEM) system designed for learning and lab environments. It collects logs from network devices and firewalls, parses them for security events, analyzes threats, and provides a web-based dashboard for monitoring.

## Architecture

```
Network Devices/Firewalls
         ↓
    Syslog (UDP)
         ↓
   Log Collector
         ↓
    Log Parser (Pattern Matching)
         ↓
   Threat Analyzer
         ↓
   SQLite Database
         ↓
   Web Dashboard
```

## Components

1. **syslog_collector.py** - Receives syslog messages via UDP
2. **log_parser.py** - Parses logs and identifies security events
3. **siem_database.py** - Stores logs and alerts in SQLite
4. **dashboard.py** - Flask web application for visualization
5. **siem_main.py** - Integrates all components

## Installation

### Prerequisites

```bash
# Python 3.8 or higher
python3 --version

# Install required packages
pip3 install flask
```

### Quick Start

```bash
# Make scripts executable
chmod +x *.py

# Start the SIEM system
python3 siem_main.py
```

The system will start:
- Syslog receiver on port 5140 (UDP)
- Web dashboard on http://localhost:5000

## Configuration

### Configure Network Devices

Point your network devices to send syslog messages to your SIEM server:

**Example: Cisco Router/Switch**
```
configure terminal
logging host <SIEM_IP> transport udp port 5140
logging trap informational
logging facility local4
end
```

**Example: pfSense Firewall**
1. Go to Status > System Logs > Settings
2. Enable "Send log messages to remote syslog server"
3. Add remote log server: `<SIEM_IP>:5140`
4. Select log levels to send

**Example: Linux iptables**
```bash
# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4

# Configure rsyslog to forward
echo "*.* @<SIEM_IP>:5140" >> /etc/rsyslog.d/50-default.conf
systemctl restart rsyslog
```

### Custom Port Configuration

```bash
# Use different ports
python3 siem_main.py --syslog-port 514 --web-port 8080

# Note: Port 514 requires root/sudo
sudo python3 siem_main.py --syslog-port 514
```

## Testing

### Generate Test Logs

Use the included test script to generate sample security events:

```bash
python3 test_siem.py
```

Or manually send test syslog messages:

```bash
# Install logger (if not available)
# apt-get install bsdutils  # Debian/Ubuntu
# yum install util-linux    # RHEL/CentOS

# Send test messages
logger -n localhost -P 5140 "DENY src=10.0.0.5 dst=192.168.1.100 port=22 proto=tcp"
logger -n localhost -P 5140 "Authentication failed for user admin from 203.0.113.50"
logger -n localhost -P 5140 "Port scan detected from 198.51.100.25"
```

### Python Test Script

```python
import socket
import time

def send_test_log(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), ('localhost', 5140))
    sock.close()

# Test firewall block
send_test_log('<133>Jan 1 12:00:00 firewall01 DENY src=10.0.0.5 dst=192.168.1.100 port=22')
time.sleep(1)

# Test auth failure
send_test_log('<133>Jan 1 12:01:00 server01 Authentication failed for user admin from 203.0.113.50')
time.sleep(1)

# Test port scan
send_test_log('<133>Jan 1 12:02:00 firewall01 Port scan detected from 198.51.100.25')

print("Test logs sent!")
```

## Dashboard Features

Access the dashboard at http://localhost:5000

### Statistics Cards
- Total events in last 24 hours
- New alerts requiring attention
- High priority alerts
- Top event categories

### Alerts Table
- View all active security alerts
- Filter by severity (critical, high, medium, low)
- Filter by status (new, investigating, resolved)
- Update alert status

### Logs Table
- View recent security events
- Search logs by keyword
- Filter by event category
- Real-time updates (30-second refresh)

## Detected Security Events

The SIEM can detect the following event types:

| Event Type | Pattern | Severity | Example |
|------------|---------|----------|---------|
| Firewall Block | DENY/BLOCK/DROP traffic | Medium | `DENY src=X dst=Y port=Z` |
| Auth Failure | Failed login attempts | Medium | `Authentication failed for user X` |
| Brute Force | Multiple auth failures | High | 5+ failures from same IP |
| Port Scan | Multiple port accesses | High | 10+ unique ports from same IP |
| DDoS Attack | Flood/DDoS patterns | Critical | `DDoS detected from X` |
| VPN Connection | VPN login events | Low | `VPN connected user X` |
| Config Change | Configuration modifications | Medium | `Configuration changed` |

## Alert Rules

### Brute Force Detection
- Threshold: 5 failed authentication attempts
- Window: Per unique IP + username combination
- Action: Generate high-severity alert

### Port Scan Detection
- Threshold: 10 unique destination ports
- Window: Per source IP
- Action: Generate high-severity alert

### Custom Rules

Add custom detection rules by editing `log_parser.py`:

```python
# Add new pattern in LogParser.__init__()
self.patterns['custom_event'] = {
    'pattern': re.compile(r'YOUR_REGEX_PATTERN', re.IGNORECASE),
    'fields': ['field1', 'field2'],
    'severity': 'high',
    'category': 'custom_category'
}
```

## Database Schema

### Logs Table
- Stores all incoming log entries
- Fields: timestamp, source_ip, hostname, message, event_type, severity
- Indexed on: timestamp, source_ip, event_category

### Alerts Table
- Stores generated security alerts
- Fields: alert_id, title, severity, status, timestamp
- Statuses: new, investigating, resolved, false_positive

### IP Reputation Table
- Tracks known malicious/suspicious IPs
- Fields: ip_address, reputation, threat_count

## API Endpoints

The dashboard exposes REST API endpoints:

```
GET /api/statistics           - Dashboard statistics
GET /api/logs                 - Recent logs
GET /api/alerts               - Security alerts
GET /api/search?q=keyword     - Search logs
POST /api/alerts/:id/status   - Update alert status
```

Example API usage:

```bash
# Get statistics
curl http://localhost:5000/api/statistics

# Search logs
curl http://localhost:5000/api/search?q=denied

# Get high severity alerts
curl http://localhost:5000/api/alerts?severity=high
```

## Next Steps for Learning

### Phase 2 Enhancements
1. **Threat Intelligence Integration**
   - Add IP reputation lookups (AbuseIPDB, VirusTotal)
   - Integrate threat feeds
   
2. **Advanced Analytics**
   - Machine learning for anomaly detection
   - Baseline behavior analysis
   - Statistical correlation

3. **Improved Storage**
   - Migrate to PostgreSQL or Elasticsearch
   - Implement log rotation
   - Add data retention policies

4. **Alerting Mechanisms**
   - Email notifications (SMTP)
   - Slack/Discord webhooks
   - SMS alerts (Twilio)
   - PagerDuty integration

5. **Compliance Reporting**
   - Generate compliance reports
   - Export logs in standard formats
   - Audit trail functionality

### Phase 3 Advanced Features
1. **Multi-tenant Support**
2. **User Authentication & RBAC**
3. **Custom Dashboard Widgets**
4. **Playbook Automation (SOAR)**
5. **Network Traffic Analysis (NetFlow)**

## Troubleshooting

### No logs appearing?

1. Check if syslog server is running:
```bash
netstat -ulnp | grep 5140
```

2. Test connectivity:
```bash
nc -u localhost 5140
# Type a test message and press Enter
```

3. Check firewall rules:
```bash
# Allow UDP port 5140
sudo ufw allow 5140/udp
```

### Database locked errors?

SQLite has limited concurrency. For production use, migrate to PostgreSQL:
```python
# In siem_database.py, replace SQLite with PostgreSQL
import psycopg2
```

### Dashboard not loading?

1. Check Flask is running: `ps aux | grep dashboard.py`
2. Check port availability: `netstat -tlnp | grep 5000`
3. Try accessing: `curl http://localhost:5000`

## Security Considerations

### For Lab Use
- This SIEM is designed for learning environments
- SQLite is not suitable for production
- No authentication on web dashboard
- No encryption for log transmission

### For Production Use
Consider:
- Add HTTPS/TLS for web dashboard
- Implement user authentication (OAuth, SAML)
- Use enterprise database (PostgreSQL, Elasticsearch)
- Enable TLS for syslog (port 6514)
- Implement log signing/integrity checks
- Add backup and disaster recovery
- Deploy in high-availability configuration

## Contributing

This is a learning project! Enhance it by:
- Adding more detection patterns
- Implementing new alert rules
- Creating custom dashboard widgets
- Improving parsing accuracy
- Adding support for more log formats

## Resources

### Learn More
- RFC 5424: Syslog Protocol
- MITRE ATT&CK Framework
- OWASP Top 10
- CIS Critical Security Controls

### Similar Projects
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Wazuh (Open-source SIEM)
- Graylog (Log management)
- AlienVault OSSIM

## License

Educational use only. Use at your own risk.

---

**Happy Learning! 🛡️🔍**
