#!/bin/bash
# Example script that logs session information to a file

# Define log file path
LOG_FILE="$HOME/.local/share/taskbeep/session.log"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Log session information
echo "$(date '+%Y-%m-%d %H:%M:%S') | Topic: $TASKBEEP_TOPIC | Duration: ${TASKBEEP_DURATION}s | Session: #$TASKBEEP_SESSION_COUNT" >>"$LOG_FILE"

# Also show a notification
notify-send "TaskBeep" "Timer finished for: $TASKBEEP_TOPIC (logged)" --urgency=normal
