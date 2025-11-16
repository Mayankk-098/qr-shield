#!/bin/bash
# Production startup script for Render

echo "Starting QR Shield application..."

# Set default port if not provided
export PORT=${PORT:-10000}

echo "Using port: $PORT"

# Start the application with gunicorn
echo "Starting Flask application with gunicorn..."
exec gunicorn -k eventlet -w 1 --bind 0.0.0.0:$PORT app:app