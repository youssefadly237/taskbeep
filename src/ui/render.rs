use super::{
    App, HEATMAP_PANEL_HEIGHT, STREAKS_PANEL_HEIGHT, day_label, heatmap_cell_level,
    heatmap_legend_levels, level_glyph, level_style, render_month_line,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    prelude::{Buffer, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Widget, Wrap},
};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &App) {
    frame.render_widget(AppWidget::new(app), frame.area());
}

struct AppWidget<'a> {
    app: &'a App,
}

impl<'a> AppWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for AppWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let app = self.app;
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(11),
                Constraint::Min(12),
                Constraint::Length(1),
            ])
            .split(area);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(outer[1]);

        TimerWidget::new(app).render(outer[0], buf);
        LeftBodyWidget::new(app).render(body[0], buf);
        RightBodyWidget::new(app).render(body[1], buf);
        FooterWidget::new(app).render(outer[2], buf);
    }
}

struct TimerWidget<'a> {
    app: &'a App,
}

impl<'a> TimerWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for TimerWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let timer_block = Block::default()
            .borders(Borders::ALL)
            .title(self.app.timer_title())
            .title(self.app.timer_corner_title().right_aligned());
        let timer_inner = timer_block.inner(area);
        timer_block.render(area, buf);

        let timer_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3)])
            .split(timer_inner);
        let countdown =
            Paragraph::new(self.app.timer_countdown_lines()).alignment(Alignment::Center);
        countdown.render(timer_layout[0], buf);
    }
}

struct LeftBodyWidget<'a> {
    app: &'a App,
}

impl<'a> LeftBodyWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for LeftBodyWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let left_panels = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(HEATMAP_PANEL_HEIGHT), Constraint::Min(1)])
            .split(area);

        HeatmapWidget::new(self.app).render(left_panels[0], buf);

        ChartWidget::new(self.app)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.app.daily_chart_title()),
            )
            .legend_height(2)
            .render(left_panels[1], buf);
    }
}

struct HeatmapWidget<'a> {
    app: &'a App,
}

impl<'a> HeatmapWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for HeatmapWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let app = self.app;
        let block = Block::default()
            .borders(Borders::ALL)
            .title(app.heatmap_title())
            .title(app.heatmap_corner_title().right_aligned());
        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let bottom = inner.y.saturating_add(inner.height);
        let mut y = inner.y;

        if y < bottom {
            let month_line = render_month_line(&app.model);
            buf.set_line(inner.x, y, &month_line, inner.width);
            y = y.saturating_add(1);
        }

        for row in 0..7 {
            if y >= bottom {
                break;
            }

            buf.set_stringn(
                inner.x,
                y,
                day_label(row),
                inner.width as usize,
                Style::default().fg(Color::DarkGray),
            );

            let mut x = inner.x.saturating_add(4);
            let right = inner.x.saturating_add(inner.width);
            for week in 0..app.model.weeks {
                if x >= right {
                    break;
                }

                let idx = week * 7 + row;
                let cell = &app.model.cells[idx];

                if !cell.in_window {
                    buf.set_stringn(x, y, "  ", (right - x) as usize, Style::default());
                    x = x.saturating_add(2);
                    continue;
                }

                let Some(level) =
                    heatmap_cell_level(cell.working_ms, app.model.max_working_ms, cell.in_window)
                else {
                    buf.set_stringn(x, y, "  ", (right - x) as usize, Style::default());
                    x = x.saturating_add(2);
                    continue;
                };
                let mut style = level_style(level, app.accent);
                if idx == app.selected_index {
                    style = style.fg(Color::LightYellow).add_modifier(Modifier::BOLD);
                }

                let glyph = level_glyph(level).to_string();
                buf.set_stringn(x, y, glyph, 1, style);
                if x.saturating_add(1) < right {
                    buf.set_stringn(x.saturating_add(1), y, " ", 1, Style::default());
                }
                x = x.saturating_add(2);
            }

            y = y.saturating_add(1);
        }

        if y < bottom {
            y = y.saturating_add(1);
        }

        if y < bottom {
            let legend_levels = heatmap_legend_levels(app.model.max_working_ms);
            let legend = Line::from(vec![
                Span::styled("Less ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} ", level_glyph(legend_levels[0])),
                    level_style(legend_levels[0], app.accent),
                ),
                Span::styled(
                    format!("{} ", level_glyph(legend_levels[1])),
                    level_style(legend_levels[1], app.accent),
                ),
                Span::styled(
                    format!("{} ", level_glyph(legend_levels[2])),
                    level_style(legend_levels[2], app.accent),
                ),
                Span::styled(
                    format!("{} ", level_glyph(legend_levels[3])),
                    level_style(legend_levels[3], app.accent),
                ),
                Span::styled(
                    format!("{} ", level_glyph(legend_levels[4])),
                    level_style(legend_levels[4], app.accent),
                ),
                Span::styled(" More", Style::default().fg(Color::DarkGray)),
            ]);
            buf.set_line(inner.x, y, &legend, inner.width);
        }
    }
}

struct ChartWidget<'a> {
    app: &'a App,
    block: Option<Block<'a>>,
    legend_height: u16,
}

impl<'a> ChartWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self {
            app,
            block: None,
            legend_height: 2,
        }
    }

    fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    fn legend_height(mut self, rows: u16) -> Self {
        self.legend_height = rows;
        self
    }
}

impl Widget for ChartWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chart_data = self.app.work_waste_chart_data();
        let chart_panel = self.block.unwrap_or_else(|| {
            Block::default()
                .borders(Borders::ALL)
                .title(self.app.daily_chart_title())
        });
        let chart_inner = chart_panel.inner(area);
        chart_panel.render(area, buf);

        let chart_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(self.legend_height), Constraint::Min(1)])
            .split(chart_inner);

        let chart_legend =
            Paragraph::new(self.app.daily_chart_legend_lines()).alignment(Alignment::Right);
        chart_legend.render(chart_layout[0], buf);

        let chart = Chart::new(vec![
            Dataset::default()
                .name("work")
                .style(Style::default().fg(Color::LightGreen))
                .marker(ratatui::symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .data(&chart_data.work_points),
            Dataset::default()
                .name("waste")
                .style(Style::default().fg(Color::Yellow))
                .marker(ratatui::symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .data(&chart_data.waste_points),
        ])
        .legend_position(None)
        .x_axis(
            Axis::default()
                .title("days")
                .style(Style::default().fg(Color::DarkGray))
                .bounds(chart_data.x_bounds)
                .labels(chart_data.x_labels),
        )
        .y_axis(
            Axis::default()
                .title("hours")
                .style(Style::default().fg(Color::DarkGray))
                .bounds(chart_data.y_bounds)
                .labels(chart_data.y_labels),
        );
        chart.render(chart_layout[1], buf);
    }
}

struct RightBodyWidget<'a> {
    app: &'a App,
}

impl<'a> RightBodyWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for RightBodyWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let side_panels = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(STREAKS_PANEL_HEIGHT)])
            .split(area);

        let selected_day = Paragraph::new(self.app.selected_day_lines())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.app.selected_day_title()),
            )
            .wrap(Wrap { trim: false });
        selected_day.render(side_panels[0], buf);

        let streaks = Paragraph::new(self.app.streaks_lines())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.app.streaks_title()),
            )
            .wrap(Wrap { trim: false });
        streaks.render(side_panels[1], buf);
    }
}

struct FooterWidget<'a> {
    app: &'a App,
}

impl<'a> FooterWidget<'a> {
    fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for FooterWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let footer_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(self.app.footer_state_width()),
            ])
            .split(area);
        let footer_notice = Paragraph::new(self.app.footer_notice_line());
        footer_notice.render(footer_layout[0], buf);
        let footer_state = Paragraph::new(self.app.footer_state_line())
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::DarkGray));
        footer_state.render(footer_layout[1], buf);
    }
}
