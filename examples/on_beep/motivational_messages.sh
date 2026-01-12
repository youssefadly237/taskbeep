#!/bin/bash
# This example shows how to display random motivational messages when a timer completes

# Array of motivational messages
messages=(
    "Great job! You're crushing it!"
    "Another task completed! You're unstoppable!"
    "Excellent work! Keep the momentum going!"
    "Task done! You're on fire today!"
    "Well done! Success is yours!"
    "Achievement unlocked! You're amazing!"
    "Target hit! You're a rockstar!"
    "Fantastic! You're making great progress!"
    "Perfect! You're doing awesome!"
    "Boom! Another win in the books!"
    "Superb! You're a productivity champion!"
    "Bravo! Keep up the fantastic work!"
    "Wonderful! You're creating magic!"
    "Lightning fast! You're incredible!"
    "Success! You're living your best life!"
)

# Get a random message
random_index=$((RANDOM % ${#messages[@]}))
message="${messages[$random_index]}"

# Display the motivational message using notify-send
# You can customize this to use any notification system you prefer
notify-send "TaskBeep" "$message" -u normal -t 5000

# Optional: Also print to terminal
# echo "$message"
