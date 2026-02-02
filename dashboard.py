#!/usr/bin/env python3
"""
SIEM Web Dashboard
Simple web interface for viewing logs, alerts, and statistics
"""

from flask import Flask, render_template, jsonify, request
from siem_database import SIEMDatabase
from datetime import datetime
import json

app = Flask(__name__)
db = SIEMDatabase()


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/statistics')
def get_statistics():
    """Get dashboard statistics"""
    hours = request.args.get('hours', default=24, type=int)
    stats = db.get_statistics(hours=hours)
    return jsonify(stats)


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    limit = request.args.get('limit', default=100, type=int)
    category = request.args.get('category', default=None, type=str)

    logs = db.get_recent_logs(limit=limit, event_category=category)

    for log in logs:
        if log.get('extracted_fields'):
            log['extracted_fields'] = json.loads(log['extracted_fields'])

    return jsonify(logs)


@app.route('/api/alerts')
def get_alerts():
    """Get alerts"""
    limit = request.args.get('limit', default=100, type=int)
    status = request.args.get('status', default=None, type=str)
    severity = request.args.get('severity', default=None, type=str)

    alerts = db.get_alerts(status=status, severity=severity, limit=limit)

    for alert in alerts:
        if alert.get('extra_data'):
            alert['extra_data'] = json.loads(alert['extra_data'])

    return jsonify(alerts)


@app.route('/api/alerts/<alert_id>/status', methods=['POST'])
def update_alert_status(alert_id):
    """Update alert status"""
    data = request.get_json()
    status = data.get('status')
    notes = data.get('notes')

    db.update_alert_status(alert_id, status, notes)
    return jsonify({'success': True})


@app.route('/api/search')
def search_logs():
    """Search logs"""
    query = request.args.get('q', default='', type=str)
    limit = request.args.get('limit', default=100, type=int)

    if not query:
        return jsonify([])

    results = db.search_logs(query, limit=limit)

    for result in results:
        if result.get('extracted_fields'):
            result['extracted_fields'] = json.loads(result['extracted_fields'])

    return jsonify(results)


if __name__ == '__main__':
    print("Starting SIEM Dashboard on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
