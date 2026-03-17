use std::collections::HashMap;

use super::{
    App, DayStats, HeatCell, HeatmapAccent, HeatmapModel, TimeDuration, TimerBanner, UiMode,
    UtcOffset, render,
};
use ratatui::{Terminal, backend::TestBackend};
use time::{Date, Month};

fn sample_app() -> App {
    let base = Date::from_calendar_date(2026, Month::January, 4).expect("valid date"); // Sunday
    let mut cells = Vec::with_capacity(14);
    let mut day_stats = HashMap::new();
    for i in 0..14 {
        let date = base + TimeDuration::days(i as i64);
        let working_ms = if i % 3 == 0 { 3_600_000 } else { 0 };
        cells.push(HeatCell {
            date,
            in_window: true,
            working_ms,
        });
        day_stats.insert(
            date,
            DayStats {
                working_ms,
                wasting_ms: if i % 4 == 0 { 1_800_000 } else { 0 },
                sessions: if i % 2 == 0 { 1 } else { 0 },
                by_topic: HashMap::new(),
            },
        );
    }

    App {
        offset: UtcOffset::UTC,
        default_year: 2026,
        all_entries: Vec::new(),
        model: HeatmapModel {
            title: "Heatmap (2026)".to_string(),
            weeks: 2,
            max_working_ms: 3_600_000,
            cells,
            day_stats,
            topics_best_streak: HashMap::new(),
            overall_best_streak: None,
        },
        selected_index: 0,
        timer: TimerBanner {
            state_line: "State: idle".to_string(),
        },
        mode: UiMode::Normal,
        topic_filter: None,
        range_filter: None,
        pending_interval_secs: 1_500,
        last_status: None,
        footer_notice: None,
        next_status_refresh_ms: 0,
        accent: HeatmapAccent::Green,
    }
}

fn render_lines(app: &App, width: u16, height: u16) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    terminal
        .draw(|frame| render::draw(frame, app))
        .expect("draw");

    let buffer = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(height as usize);
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push_str(buffer[(x, y)].symbol());
        }
        lines.push(line);
    }
    lines
}

fn find_line(lines: &[String], needle: &str) -> Option<usize> {
    lines.iter().position(|line| line.contains(needle))
}

#[test]
fn ui_render_contains_core_panels() {
    let app = sample_app();
    let lines = render_lines(&app, 120, 36);
    let screen = lines.join("\n");

    for anchor in [
        "Timer",
        "Heatmap",
        "Working vs Wasting",
        "Selected Day",
        "Streak Highlights",
        "Less",
        "More",
        "days",
        "hours",
    ] {
        assert!(screen.contains(anchor), "missing anchor: {anchor}");
    }
}

#[test]
fn ui_layout_keeps_top_body_footer_order() {
    let app = sample_app();
    let lines = render_lines(&app, 120, 36);

    let timer_row = find_line(&lines, "Timer").expect("timer row");
    let body_row = find_line(&lines, "Heatmap").expect("body row");
    let footer_row = find_line(&lines, "State: idle").expect("footer row");

    assert!(timer_row < body_row, "timer should be above body");
    assert!(body_row < footer_row, "body should be above footer");
    assert_eq!(
        footer_row,
        lines.len() - 1,
        "footer should stay on last row"
    );
}
