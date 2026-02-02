# SIEM Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Devices Layer                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Firewall │  │  Router  │  │  Switch  │  │   IDS    │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
└───────┼─────────────┼─────────────┼─────────────┼──────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                      │
                      ▼ Syslog (UDP Port 5140)
        ┌─────────────────────────────────────┐
        │   Log Collector (syslog_collector)  │
        │   - Receives UDP syslog messages    │
        │   - Parses RFC 3164/5424 format     │
        │   - Extracts timestamp, source, etc │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │     Log Parser (log_parser)         │
        │   - Pattern matching                │
        │   - Event classification            │
        │   - Field extraction                │
        │   Detects:                          │
        │   • Firewall blocks                 │
        │   • Auth failures                   │
        │   • Port scans                      │
        │   • DDoS attacks                    │
        │   • VPN connections                 │
        │   • Config changes                  │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │   Threat Analyzer (LogAnalyzer)     │
        │   - Brute force detection           │
        │   - Port scan detection             │
        │   - Threshold-based alerting        │
        │   - Stateful analysis               │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │    Database (siem_database)         │
        │    SQLite Storage                   │
        │   ┌───────────────────────────┐     │
        │   │  Logs Table               │     │
        │   │  - All events             │     │
        │   │  - Full metadata          │     │
        │   └───────────────────────────┘     │
        │   ┌───────────────────────────┐     │
        │   │  Alerts Table             │     │
        │   │  - Security alerts        │     │
        │   │  - Status tracking        │     │
        │   └───────────────────────────┘     │
        │   ┌───────────────────────────┐     │
        │   │  IP Reputation            │     │
        │   └───────────────────────────┘     │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │   Web Dashboard (Flask)             │
        │   http://localhost:5000             │
        │   ┌───────────────────────────┐     │
        │   │  Statistics View          │     │
        │   │  - Event counts           │     │
        │   │  - Alert summary          │     │
        │   │  - Severity breakdown     │     │
        │   └───────────────────────────┘     │
        │   ┌───────────────────────────┐     │
        │   │  Alerts View              │     │
        │   │  - Real-time alerts       │     │
        │   │  - Status management      │     │
        │   └───────────────────────────┘     │
        │   ┌───────────────────────────┐     │
        │   │  Logs View                │     │
        │   │  - Recent events          │     │
        │   │  - Search capability      │     │
        │   └───────────────────────────┘     │
        └─────────────────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │         Security Analyst            │
        │   - Monitor dashboard               │
        │   - Investigate alerts              │
        │   - Update status                   │
        │   - Search logs                     │
        └─────────────────────────────────────┘

═══════════════════════════════════════════════════════════════

Data Flow:
──────────
1. Network devices send syslog messages (UDP)
2. Collector receives and parses raw syslog
3. Parser identifies security events and extracts fields
4. Analyzer applies detection rules and generates alerts
5. Database stores logs and alerts
6. Dashboard displays real-time security status
7. Analyst reviews and responds to alerts

Key Features:
─────────────
✓ Real-time log collection
✓ Pattern-based event detection
✓ Automated threat analysis
✓ Alert generation
✓ Web-based dashboard
✓ Log search capability
✓ Statistics and metrics
✓ Alert status tracking

Alert Generation Rules:
──────────────────────
• Brute Force: 5+ auth failures (same IP + user)
• Port Scan: 10+ unique ports (same source IP)
• Critical Events: Immediate alert on detection
• DDoS: Pattern match on attack indicators
```
