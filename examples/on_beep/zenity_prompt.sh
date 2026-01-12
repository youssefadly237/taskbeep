#!/bin/bash
# Example script using zenity (GTK dialog) to prompt for productivity response

# Use zenity to show a list dialog with all options
RESPONSE=$(zenity --list \
    --title="TaskBeep Timer Finished" \
    --text="Task: $TASKBEEP_TOPIC\nDuration: ${TASKBEEP_DURATION}s\nSession: #$TASKBEEP_SESSION_COUNT\n\nWhat would you like to do?" \
    --column="Action" \
    "working" \
    "wasting" \
    "stop (working)" \
    "stop (wasting)" \
    --width=350 --height=300)

if [ "$RESPONSE" = "working" ]; then
    taskbeep working
elif [ "$RESPONSE" = "wasting" ]; then
    taskbeep wasting
elif [ "$RESPONSE" = "stop (working)" ]; then
    taskbeep stop --working
elif [ "$RESPONSE" = "stop (wasting)" ]; then
    taskbeep stop --wasting
fi
