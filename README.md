# TaskBeep - Pomodoro Timer

A Pomodoro timer with productivity tracking that plays a beep sound at the end
of each interval.

## Features

- Start timer with a custom topic and interval
- Receive beep notification when timer completes
- Signal whether you were working or wasting time
- Track productivity statistics by topic
- Integration-friendly (designed for use with Waybar or other status bars)

## Usage

### Start a Pomodoro Session

```bash
# Default 25-minute (1500s) session
taskbeep start "Writing documentation"

# Custom interval (e.g., 45 minutes)
taskbeep start "Deep work coding" 2700
```

The timer will:

1. Run in the background for the specified interval
2. Play a beep sound when the interval completes
3. Wait for your response about how productive you were

### Respond to Timer

When the timer beeps, signal whether you were productive:

```bash
# Signal that you were working on the task
taskbeep working

# Signal that you were wasting time
taskbeep wasting
```

### Check Status

```bash
taskbeep status
```

Shows:

- Current topic
- Interval length
- Sessions completed
- Time remaining
- Whether waiting for working/wasting response

### View Statistics

```bash
taskbeep stats
```

Shows:

- Total sessions (working vs wasting)
- Overall productivity percentage
- Breakdown by topic with individual productivity rates

### Stop Timer

```bash
taskbeep stop
```

## Integration with Waybar

You can integrate this with Waybar to create a visual Pomodoro timer. Here's an
example configuration:

### Waybar Config (`~/.config/waybar/config`)

```json
{
    "custom/pomodoro": {
        "exec": "~/.config/waybar/scripts/pomodoro.sh",
        "return-type": "json",
        "interval": 1,
        "format": "󰔛 {text}",
        "escape": false,
        "tooltip": false,
        "on-click": "~/.config/waybar/scripts/pomodoro.sh working",
        "on-click-middle": "~/.config/waybar/scripts/pomodoro.sh toggle",
        "on-click-right": "~/.config/waybar/scripts/pomodoro.sh wasting",
    }
}
```

### Pomodoro script (`~/.config/waybar/scripts/pomodoro.sh`)

```bash
#!/usr/bin/env bash
export PATH="$HOME/.cargo/bin:$PATH"

cmd="$1"

if [[ -n "$cmd" ]]; then
    case "$cmd" in
        working)
            taskbeep working
            exit 0
            ;;
        toggle)
            taskbeep toggle
            exit 0
            ;;
        wasting)
            taskbeep wasting
            exit 0
            ;;
        *)
            echo "Unknown command"
            exit 1
            ;;
    esac
fi

raw=$(taskbeep status 2>/dev/null)

if echo "$raw" | grep -q "Timer not running"; then
    echo '{"text":"Idle", "class":"idle"}'
    exit 0
fi

if echo "$raw" | grep -q "Error"; then
    echo '{"text":"error", "class":"error"}'
    exit 0
fi

status=$(echo "$raw" | head -n1)
remaining=$(echo "$raw" | grep 'Time remaining:' | cut -d: -f2- | sed 's/^ *//')

case "$status" in
Running)
    h=0 m=0 s=0
    [[ "$remaining" =~ ([0-9]+)h ]] && h=${BASH_REMATCH[1]}
    [[ "$remaining" =~ ([0-9]+)m ]] && m=${BASH_REMATCH[1]}
    [[ "$remaining" =~ ([0-9]+)s ]] && s=${BASH_REMATCH[1]}

    total=$((h * 3600 + m * 60 + s))
    text=$(printf "%02d:%02d" $((total / 60)) $((total % 60)))
    class="running"
    ;;
Paused)
    text="Paused "
    class="paused"
    ;;
"Waiting for response")
    text="Waiting"
    class="waiting"
    ;;
*)
    text="Idle"
    class="idle"
    ;;
esac

echo "{\"text\":\"$text\", \"class\":\"$class\"}"
```

### Waybar Style (`~/.config/waybar/style.css`)

```css
#custom-pomodoro {
    padding: 0 10px;
    background-color: #22223b;
}
#custom-pomodoro.running { color: #38b000; }
#custom-pomodoro.paused  { color: #ffd60a; }
#custom-pomodoro.waiting { color: #ff1744; }
```

This configuration:

- Shows remaining time in the status bar
- Left-click to signal "working"
- Middle-click to pause/resume the timer
- Right-click to signal "wasting"

## Workflow Example

1. Start your work session:

    ```bash
    taskbeep start "Implement new feature" 1500
    ```

2. Work on your task for 25 minutes

3. When the beep sounds, assess your productivity

4. Signal your response (click in Waybar or run command):

    ```bash
    taskbeep working  # or wasting
    ```

5. Take a break or start another session

6. Review your statistics:

    ```bash
    taskbeep stats
    ```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/taskbeep`

## Requirements

- Linux system with audio output
- Rust 2024 edition or later
- Audio file: `taskbeep.wav` in project root
