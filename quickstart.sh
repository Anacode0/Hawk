#!/bin/bash
# Quick Start Script for Custom SIEM

echo "   Custom SIEM System - Quick Start"
echo

# Check Python version
echo "Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "ERROR: Python 3 is required but not found"
    exit 1
fi
echo "✓ Python 3 found"
echo

# Check/install Flask
echo "Checking Flask installation..."
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Flask not found. Installing..."
    pip3 install flask
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install Flask"
        echo "Try: pip3 install --user flask"
        exit 1
    fi
fi
echo "✓ Flask installed"
echo

# Make scripts executable
echo "Setting permissions..."
chmod +x *.py
echo "✓ Scripts are executable"
echo

# Create necessary directories
echo "Creating directories..."
mkdir -p logs
mkdir -p templates
echo "✓ Directories created"
echo

# Initialize database
echo "Initializing database..."
python3 -c "from siem_database import SIEMDatabase; db = Database(); db.close()"
if [ $? -eq 0 ]; then
    echo "Database initialized"
else
    echo "WARNING: Database initialization may have failed"
fi
echo

echo "   Setup Complete!"
echo
echo "To start the SIEM system:"
echo "  python3 siem_main.py"
echo
echo "To test with sample data:"
echo "  python3 test_siem.py --auto"
echo
echo "Dashboard will be available at:"
echo "  http://localhost:5000"
echo
echo "Syslog receiver will listen on:"
echo "  UDP port 5140"
