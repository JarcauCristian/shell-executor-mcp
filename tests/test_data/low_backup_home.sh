#!/usr/bin/env bash
# Low risk script - Backup user's home directory
# Standard backup utility

BACKUP_DIR="${1:-/tmp/backups}"
SOURCE_DIR="$HOME"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="home_backup_${DATE}.tar.gz"

echo "Starting backup process..."
echo "Source: $SOURCE_DIR"
echo "Destination: $BACKUP_DIR/$BACKUP_NAME"
echo ""

# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    echo "Created backup directory: $BACKUP_DIR"
fi

# Exclude common cache and temporary directories
EXCLUDES="--exclude=.cache --exclude=.local/share/Trash --exclude=node_modules --exclude=.npm --exclude=__pycache__"

# Create the backup
echo "Creating backup archive..."
tar czf "$BACKUP_DIR/$BACKUP_NAME" $EXCLUDES -C "$(dirname $SOURCE_DIR)" "$(basename $SOURCE_DIR)" 2>/dev/null

if [ $? -eq 0 ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_NAME" | cut -f1)
    echo ""
    echo "Backup completed successfully!"
    echo "File: $BACKUP_DIR/$BACKUP_NAME"
    echo "Size: $BACKUP_SIZE"
else
    echo "Backup failed!"
    exit 1
fi

# Optional: Remove backups older than 7 days
find "$BACKUP_DIR" -name "home_backup_*.tar.gz" -mtime +7 -delete 2>/dev/null

echo ""
echo "Backup process finished."
