#!/bin/sh
set -e

echo "============================================="
echo "   ProxmoxVED Telemetry Service"
echo "============================================="

echo "🚀 Starting telemetry service..."
exec /app/telemetry-service
