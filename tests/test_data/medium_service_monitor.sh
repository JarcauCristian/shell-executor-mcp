#!/usr/bin/env bash
# Medium risk script - Service health checker and restarter
# Monitors services and restarts them if they're down
# Note: Can restart system services which may affect system stability

SERVICES=("nginx" "mysql" "postgresql" "redis" "docker")
LOG_FILE="/var/log/service_monitor.log"
EMAIL_ALERT="${ALERT_EMAIL:-admin@example.com}"

log_message() {
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $msg" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$timestamp] $msg"
}

check_and_restart_service() {
    local service="$1"
    
    # Check if service exists
    if ! systemctl list-unit-files | grep -q "^${service}.service"; then
        return 0
    fi
    
    # Check service status
    if systemctl is-active --quiet "$service"; then
        log_message "OK: $service is running"
        return 0
    else
        log_message "WARNING: $service is not running. Attempting restart..."
        
        # Try to restart the service
        if systemctl restart "$service" 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet "$service"; then
                log_message "SUCCESS: $service restarted successfully"
                return 0
            fi
        fi
        
        log_message "ERROR: Failed to restart $service"
        return 1
    fi
}

echo "========================================="
echo "        SERVICE HEALTH MONITOR           "
echo "========================================="
echo ""

log_message "Starting service health check..."

FAILED_SERVICES=()

for service in "${SERVICES[@]}"; do
    if ! check_and_restart_service "$service"; then
        FAILED_SERVICES+=("$service")
    fi
done

echo ""
if [ ${#FAILED_SERVICES[@]} -eq 0 ]; then
    log_message "All monitored services are healthy"
else
    log_message "ALERT: ${#FAILED_SERVICES[@]} service(s) failed: ${FAILED_SERVICES[*]}"
fi

echo ""
echo "Health check completed."
