#!/bin/bash
# Example script using wofi to prompt for productivity response
# Show notification about timer completion
notify-send "TaskBeep Timer Finished" \
    "Task: $TASKBEEP_TOPIC\nDuration: ${TASKBEEP_DURATION}s\nSession: #$TASKBEEP_SESSION_COUNT" \
    --urgency=critical

# Use wofi to ask if time was productive
RESPONSE=$(echo -e "working\nwasting\nstop (working)\nstop (wasting)" | wofi --dmenu --prompt="Was the time productive? ")

if [ "$RESPONSE" = "working" ]; then
    taskbeep working
elif [ "$RESPONSE" = "wasting" ]; then
    taskbeep wasting
elif [ "$RESPONSE" = "stop (working)" ]; then
    taskbeep stop --working
elif [ "$RESPONSE" = "stop (wasting)" ]; then
    taskbeep stop --wasting
fi
