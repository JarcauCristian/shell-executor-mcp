#!/usr/bin/env bash
# Medium risk script - System cleanup utility
# Removes temporary files and caches to free disk space
# Note: Deletes files, but only from safe temporary locations

echo "========================================="
echo "        SYSTEM CLEANUP UTILITY           "
echo "========================================="
echo ""

DRY_RUN=false
if [ "$1" == "--dry-run" ]; then
    DRY_RUN=true
    echo "Running in DRY RUN mode - no files will be deleted"
    echo ""
fi

SPACE_BEFORE=$(df -h / | tail -1 | awk '{print $4}')
echo "Free space before cleanup: $SPACE_BEFORE"
echo ""

# Function to safely remove files
safe_remove() {
    local path="$1"
    local desc="$2"
    
    if [ -e "$path" ]; then
        if [ "$DRY_RUN" = true ]; then
            echo "[DRY RUN] Would clean: $desc"
            du -sh "$path" 2>/dev/null | awk '{print "  Size: " $1}'
        else
            echo "Cleaning: $desc"
            rm -rf "$path" 2>/dev/null
        fi
    fi
}

echo "--- Cleaning temporary files ---"
safe_remove "/tmp/*" "System temp files"
safe_remove "$HOME/.cache/thumbnails/*" "Thumbnail cache"
safe_remove "$HOME/.local/share/Trash/*" "Trash bin"

echo ""
echo "--- Cleaning package manager caches ---"
if command -v apt-get &> /dev/null; then
    if [ "$DRY_RUN" = false ]; then
        apt-get clean 2>/dev/null
    fi
    echo "Cleaned apt cache"
fi

echo ""
echo "--- Cleaning log files (older than 7 days) ---"
if [ "$DRY_RUN" = false ]; then
    find /var/log -type f -name "*.log" -mtime +7 -delete 2>/dev/null
    find /var/log -type f -name "*.gz" -mtime +7 -delete 2>/dev/null
fi
echo "Old log files cleaned"

echo ""
SPACE_AFTER=$(df -h / | tail -1 | awk '{print $4}')
echo "Free space after cleanup: $SPACE_AFTER"
echo ""
echo "Cleanup completed!"
