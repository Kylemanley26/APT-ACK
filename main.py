#!/usr/bin/env python3
"""
APT-ACK Web Application Entry Point
"""
import os
import sys

# Add project to path
sys.path.insert(0, os.path.dirname(__file__))

# Import and run the Flask app
from web.app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)