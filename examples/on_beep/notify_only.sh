#!/bin/bash
# Example script that only shows a notification

# Show detailed notification
notify-send "TaskBeep Timer Finished" \
    "Task: $TASKBEEP_TOPIC\nDuration: ${TASKBEEP_DURATION}s\nSession: #$TASKBEEP_SESSION_COUNT\n\nRespond with:\ntaskbeep working\ntaskbeep wasting" \
    --urgency=critical \
    --icon=alarm-symbolic
