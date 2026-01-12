# TaskBeep Example Scripts

This directory contains example scripts demonstrating various TaskBeep integrations.

## Directory Structure

- **`on_beep/`** - Scripts to run when the timer finishes (using
`on_timer_finish` config)
- **`waybar/`** - Waybar integration examples

## on_beep/ Scripts

Scripts in this directory demonstrate how to use the `on_timer_finish`
configuration option.

### Interactive Prompts

These scripts automatically prompt you to respond whether the time was productive:

- `rofi_prompt.sh`
- `fuzzel_prompt.sh`
- `wofi_prompt.sh`
- `zenity_prompt.sh`

### Non-Interactive

- `notify_only.sh`
- `log_session.sh`
- `motivational_messages.sh`

## Usage

1. Choose a script that fits your setup from `on_beep/`
2. Copy it to your preferred location (e.g., `~/.config/taskbeep/`)
3. Make it executable:

   ```bash
   chmod +x ~/.config/taskbeep/rofi_prompt.sh
   ```

4. Configure in `~/.config/taskbeep/config.toml`:

   ```toml
   on_timer_finish = "/home/your-username/.config/taskbeep/rofi_prompt.sh"
   ```

## Environment Variables

All scripts receive these environment variables:

- `TASKBEEP_TOPIC` - The current task topic
- `TASKBEEP_DURATION` - Session duration in seconds
- `TASKBEEP_SESSION_COUNT` - Number of completed sessions

## Customization

Feel free to modify these scripts to fit your needs:

- Change notification styles
- Add custom sounds
- Integrate with your task management system
- Log to different formats (JSON, CSV, etc.)
- Send data to external services
- Add time-based logic (different behavior for different times of day)
