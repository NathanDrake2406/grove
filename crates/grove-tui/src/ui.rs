use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::app::{App, FocusedPanel, ViewState};
use grove_lib::{OrthogonalityScore, Overlap, WorkspacePairAnalysis};

/// Truncate a string to fit within `max_width` columns, appending "…" if truncated.
fn truncate_with_ellipsis(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if s.len() <= max_width {
        return s.to_string();
    }
    if max_width <= 1 {
        return "…".to_string();
    }
    let mut truncated = s[..max_width - 1].to_string();
    truncated.push('…');
    truncated
}

pub fn render(app: &App, frame: &mut Frame) {
    let area = frame.area();

    match &app.view_state {
        ViewState::Loading => render_loading(frame, area),
        ViewState::NoWorktrees => render_no_worktrees(frame, area),
        ViewState::Dashboard => render_dashboard(app, frame, area),
        ViewState::Error(err) => render_error(err, frame, area),
    }
}

fn render_loading(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Grove Dashboard ")
        .borders(Borders::ALL);
    let p = Paragraph::new("Connecting to daemon and loading worktrees...")
        .block(block)
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(p, area);
}

fn render_no_worktrees(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Grove Dashboard ")
        .borders(Borders::ALL);
    let p = Paragraph::new(
        "Not enough worktrees detected.\nGrove requires at least two worktrees to analyze orthogonality.",
    )
    .block(block)
    .style(Style::default().fg(Color::Yellow));
    frame.render_widget(p, area);
}

fn render_error(err: &str, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Red));
    let p = Paragraph::new(format!("Fatal Error: {}\n\nPress 'q' or 'ESC' to exit.", err))
        .block(block)
        .style(Style::default().fg(Color::Red));
    frame.render_widget(p, area);
}

fn render_dashboard(app: &App, frame: &mut Frame, area: Rect) {
    // Full-width vertical stack: header | worktrees | conflicts | detail | footer
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // summary bar
            Constraint::Fill(1),  // worktrees panel
            Constraint::Fill(1),  // conflicts panel
            Constraint::Fill(1),  // detail panel
            Constraint::Length(1), // footer
        ])
        .split(area);

    let header_area = rows[0];
    let worktrees_area = rows[1];
    let pairs_area = rows[2];
    let detail_area = rows[3];
    let footer_area = rows[4];

    render_summary_bar(app, frame, header_area);
    render_worktrees_panel(app, frame, worktrees_area);
    render_pairs_panel(app, frame, pairs_area);
    render_detail_panel(app, frame, detail_area);
    render_footer(app, frame, footer_area);
}

fn render_summary_bar(app: &App, frame: &mut Frame, area: Rect) {
    let (worktree_count, base, conflict_count, clean_count) = app.summary_stats();

    let line = Line::from(vec![
        Span::styled("  \u{25cf} ", Style::default().fg(Color::Green)),
        Span::raw(format!("{} worktrees", worktree_count)),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("base: {}", base)),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} conflict(s)", conflict_count),
            Style::default().fg(if conflict_count > 0 {
                Color::Red
            } else {
                Color::Green
            }),
        ),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} clean", clean_count),
            Style::default().fg(Color::Green),
        ),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("updated {}", app.last_updated_label()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let block = Block::default()
        .title(" Grove Status ")
        .borders(Borders::ALL);
    let p = Paragraph::new(line).block(block);
    frame.render_widget(p, area);
}

fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let _ = app; // available for future context-sensitive hints
    let line = Line::from(vec![
        Span::styled(" \u{2190}\u{2192}", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" panel  ", Style::default().fg(Color::DarkGray)),
        Span::styled("\u{2191}\u{2193}", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" refresh  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]);
    let p = Paragraph::new(line);
    frame.render_widget(p, area);
}

fn render_worktrees_panel(app: &App, frame: &mut Frame, area: Rect) {
    let focused = app.focused_panel == FocusedPanel::Worktrees;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Available width: total minus borders (2) minus prefix "  "/" > " (2) minus suffix " ✔"/" !" (2)
    let available_name_width = (area.width as usize).saturating_sub(2 + 2 + 2);

    let items: Vec<ListItem> = app
        .workspaces
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let selected = i == app.selected_worktree_index;
            let pairs = app.get_pairs_for_worktree(&w.id);
            let has_conflicts = !pairs.is_empty();

            let name_style = if selected && focused {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            let indicator = if selected && focused { "> " } else { "  " };

            let truncated_name = truncate_with_ellipsis(&w.name, available_name_width);

            let conflict_indicator = if has_conflicts {
                Span::styled(" !", Style::default().fg(Color::Red))
            } else {
                Span::styled(" \u{2714}", Style::default().fg(Color::Green))
            };

            ListItem::new(Line::from(vec![
                Span::raw(indicator),
                Span::styled(truncated_name, name_style),
                conflict_indicator,
            ]))
        })
        .collect();

    let title = if focused { " > Worktrees " } else { " Worktrees " };
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    frame.render_widget(list, area);
}

fn render_pairs_panel(app: &App, frame: &mut Frame, area: Rect) {
    let focused = app.focused_panel == FocusedPanel::Pairs;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let title = if focused { " > Conflicts " } else { " Conflicts " };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    let selected_ws = match app.workspaces.get(app.selected_worktree_index) {
        Some(ws) => ws,
        None => {
            let p = Paragraph::new("No worktrees available.").block(block);
            frame.render_widget(p, area);
            return;
        }
    };

    let pairs = app.get_pairs_for_worktree(&selected_ws.id);

    if pairs.is_empty() {
        let p = Paragraph::new(
            "\n  No conflicts \u{2014} this worktree is clean.",
        )
        .block(block)
        .style(Style::default().fg(Color::Green));
        frame.render_widget(p, area);
        return;
    }

    // Layout: borders consume 2 cols. Score badge is fixed 11 chars " ■ SCORE  ".
    // Overlap count suffix like " (N) " is at most 6 chars. Name gets the rest.
    let total_width = area.width as usize;
    let inner_width = total_width.saturating_sub(2); // minus borders
    // Score badge: " ■ SCORE  " = 1 space + "■" + 1 space + 6-char score + 2 spaces = 11 chars
    let score_badge_width: usize = 11;
    // Overlap count: " (N) " — reserve 6 chars to accommodate up to 3-digit counts
    let count_suffix_width: usize = 6;
    let name_width = inner_width
        .saturating_sub(score_badge_width)
        .saturating_sub(count_suffix_width);

    let pair_items: Vec<ListItem> = pairs
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let target_id = if p.workspace_a == selected_ws.id {
                p.workspace_b
            } else {
                p.workspace_a
            };

            let target_name = app
                .workspaces
                .iter()
                .find(|w| w.id == target_id)
                .map(|w| w.name.as_str())
                .unwrap_or("Unknown");

            let score_color = match p.score {
                OrthogonalityScore::Green => Color::Green,
                OrthogonalityScore::Yellow => Color::Yellow,
                OrthogonalityScore::Red => Color::Red,
                OrthogonalityScore::Black => Color::Magenta,
            };

            // Score label padded to 6 chars for alignment
            let score_label = match p.score {
                OrthogonalityScore::Green => "GREEN ",
                OrthogonalityScore::Yellow => "YELLOW",
                OrthogonalityScore::Red => "RED   ",
                OrthogonalityScore::Black => "BLACK ",
            };

            let selected = i == app.selected_pair_index && focused;
            let row_style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            let truncated_name = truncate_with_ellipsis(target_name, name_width);
            let count_str = format!(" ({}) ", p.overlaps.len());

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" \u{25a0} {}  ", score_label),
                    if selected {
                        row_style.fg(score_color)
                    } else {
                        Style::default().fg(score_color)
                    },
                ),
                Span::styled(truncated_name, row_style),
                Span::styled(
                    count_str,
                    if selected {
                        row_style.fg(Color::DarkGray)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
            ]))
        })
        .collect();

    let list = List::new(pair_items).block(block);
    frame.render_widget(list, area);
}

fn render_detail_panel(app: &App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let selected_ws = match app.workspaces.get(app.selected_worktree_index) {
        Some(ws) => ws,
        None => {
            let p = Paragraph::new("No worktree selected.").block(block);
            frame.render_widget(p, area);
            return;
        }
    };

    match app.focused_panel {
        FocusedPanel::Worktrees => {
            // Show worktree details — full untruncated fields
            let pairs = app.get_pairs_for_worktree(&selected_ws.id);
            let conflict_summary = if pairs.is_empty() {
                "none".to_string()
            } else {
                format!("{} pair(s) with overlaps", pairs.len())
            };

            let label_style = Style::default().fg(Color::DarkGray);
            let value_style = Style::default();

            let lines: Vec<Line<'static>> = vec![
                Line::from(vec![
                    Span::styled("  name        ".to_string(), label_style),
                    Span::styled(selected_ws.name.clone(), value_style),
                ]),
                Line::from(vec![
                    Span::styled("  branch      ".to_string(), label_style),
                    Span::styled(selected_ws.branch.clone(), value_style),
                ]),
                Line::from(vec![
                    Span::styled("  path        ".to_string(), label_style),
                    Span::styled(
                        selected_ws.path.to_string_lossy().into_owned(),
                        value_style,
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  conflicts   ".to_string(), label_style),
                    Span::styled(
                        conflict_summary,
                        if pairs.is_empty() {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::Red)
                        },
                    ),
                ]),
            ];

            let p = Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false });
            frame.render_widget(p, area);
        }
        FocusedPanel::Pairs => {
            // Show overlap details for the selected pair
            let pairs = app.get_pairs_for_worktree(&selected_ws.id);

            if pairs.is_empty() {
                let p = Paragraph::new("\n  No conflicts \u{2014} this worktree is clean.")
                    .block(block)
                    .style(Style::default().fg(Color::Green));
                frame.render_widget(p, area);
                return;
            }

            match pairs.get(app.selected_pair_index) {
                Some(analysis) => {
                    let lines = build_overlap_lines(analysis, app);
                    let p = Paragraph::new(lines)
                        .block(block)
                        .wrap(Wrap { trim: false });
                    frame.render_widget(p, area);
                }
                None => {
                    let p =
                        Paragraph::new("Select a conflict pair to view details.").block(block);
                    frame.render_widget(p, area);
                }
            }
        }
    }
}

/// Build the grouped overlap display lines for a given pair analysis.
fn build_overlap_lines<'a>(analysis: &'a WorkspacePairAnalysis, app: &'a App) -> Vec<Line<'a>> {
    let ws_a_name = app
        .workspaces
        .iter()
        .find(|w| w.id == analysis.workspace_a)
        .map(|w| w.name.as_str())
        .unwrap_or("Unknown");

    let ws_b_name = app
        .workspaces
        .iter()
        .find(|w| w.id == analysis.workspace_b)
        .map(|w| w.name.as_str())
        .unwrap_or("Unknown");

    if analysis.overlaps.is_empty() {
        return vec![Line::from(Span::styled(
            format!("  No overlaps between {} and {}.", ws_a_name, ws_b_name),
            Style::default().fg(Color::Green),
        ))];
    }

    // Group overlaps by type
    let mut files: Vec<String> = vec![];
    let mut hunks: Vec<(String, u32, u32, u32)> = vec![];
    let mut symbols: Vec<(String, String)> = vec![];
    let mut deps: Vec<(String, String)> = vec![];
    let mut schemas: Vec<(String, String, String, String)> = vec![];

    for overlap in &analysis.overlaps {
        match overlap {
            Overlap::File { path, .. } => {
                files.push(path.to_string_lossy().into_owned());
            }
            Overlap::Hunk {
                path,
                a_range,
                distance,
                ..
            } => {
                hunks.push((
                    path.to_string_lossy().into_owned(),
                    a_range.start,
                    a_range.end,
                    *distance,
                ));
            }
            Overlap::Symbol {
                path, symbol_name, ..
            } => {
                symbols.push((
                    path.to_string_lossy().into_owned(),
                    symbol_name.clone(),
                ));
            }
            Overlap::Dependency {
                changed_file,
                affected_file,
                ..
            } => {
                deps.push((
                    changed_file.to_string_lossy().into_owned(),
                    affected_file.to_string_lossy().into_owned(),
                ));
            }
            Overlap::Schema {
                category,
                a_file,
                b_file,
                detail,
            } => {
                schemas.push((
                    format!("{:?}", category),
                    a_file.to_string_lossy().into_owned(),
                    b_file.to_string_lossy().into_owned(),
                    detail.clone(),
                ));
            }
        }
    }

    let mut lines: Vec<Line<'static>> = vec![];

    if !files.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Both branches edit the same files:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for path in files {
            lines.push(Line::from(format!("    {path}")));
        }
        lines.push(Line::from(""));
    }

    if !hunks.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Both branches change the same lines:",
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )));
        for (path, start, end, distance) in hunks {
            let color = if distance == 0 {
                Color::Red
            } else {
                Color::Yellow
            };
            lines.push(Line::from(Span::styled(
                format!("    {path}:{start}-{end}"),
                Style::default().fg(color),
            )));
        }
        lines.push(Line::from(""));
    }

    if !symbols.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Both branches modify the same functions:",
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )));
        for (path, name) in symbols {
            lines.push(Line::from(format!("    {name}() in {path}")));
        }
        lines.push(Line::from(""));
    }

    if !deps.is_empty() {
        lines.push(Line::from(Span::styled(
            "  One branch's changes affect the other's imports:",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));
        for (changed, affected) in deps {
            lines.push(Line::from(format!("    {changed} \u{2192} {affected}")));
        }
        lines.push(Line::from(""));
    }

    if !schemas.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Both branches touch shared config/schemas:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for (category, a_file, b_file, detail) in schemas {
            lines.push(Line::from(format!(
                "    [{category}] {a_file} vs {b_file} ({detail})"
            )));
        }
        lines.push(Line::from(""));
    }

    lines
}
