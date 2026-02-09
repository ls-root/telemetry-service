#!/bin/sh
set -e

echo "============================================="
echo "   ProxmoxVED Telemetry Service"
echo "============================================="

# Map Coolify ENV names to migration script names
# Coolify uses PB_URL, PB_TARGET_COLLECTION
export POCKETBASE_URL="${POCKETBASE_URL:-$PB_URL}"
export POCKETBASE_COLLECTION="${POCKETBASE_COLLECTION:-$PB_TARGET_COLLECTION}"

# Run migration if enabled
if [ "$RUN_MIGRATION" = "true" ]; then
    echo ""
    echo "🔄 Migration mode enabled"
    echo "   Source: $MIGRATION_SOURCE_URL"
    echo "   Target: $POCKETBASE_URL"
    echo "   Collection: $POCKETBASE_COLLECTION"
    echo ""
    
    # Wait for PocketBase to be ready
    echo "⏳ Waiting for PocketBase to be ready..."
    RETRIES=30
    until wget -q --spider "$POCKETBASE_URL/api/health" 2>/dev/null; do
        RETRIES=$((RETRIES - 1))
        if [ $RETRIES -le 0 ]; then
            echo "❌ PocketBase not reachable after 30 attempts"
            if [ "$MIGRATION_REQUIRED" = "true" ]; then
                exit 1
            fi
            echo "⚠️  Continuing without migration..."
            break
        fi
        echo "   Waiting... ($RETRIES attempts left)"
        sleep 2
    done
    
    if wget -q --spider "$POCKETBASE_URL/api/health" 2>/dev/null; then
        echo "✅ PocketBase is ready"
        echo ""
        echo "🚀 Starting migration..."
        /app/migrate || {
            if [ "$MIGRATION_REQUIRED" = "true" ]; then
                echo "❌ Migration failed!"
                exit 1
            fi
            echo "⚠️  Migration failed, but continuing..."
        }
        echo ""
    fi
fi

echo "🚀 Starting telemetry service..."
exec /app/telemetry-service
