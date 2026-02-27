use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use std::path::Path;

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

/// Truncate a path from the left, keeping the most meaningful trailing components.
/// E.g. "~/Projects/movies-ranking/.claude/worktrees/foo" → "…/.claude/worktrees/foo"
fn truncate_path_left(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if s.len() <= max_width {
        return s.to_string();
    }
    // Walk backward through '/' separators to find the longest suffix that fits.
    // Reserve 1 char for the "…" prefix.
    let budget = max_width.saturating_sub(1);
    for (i, _) in s.match_indices('/').rev() {
        let suffix = &s[i..]; // includes the leading '/'
        if suffix.len() <= budget {
            return format!("…{suffix}");
        }
    }
    // No '/' boundary fits — fall back to right-truncation.
    truncate_with_ellipsis(s, max_width)
}

/// Render a workspace path for display: repo-relative when possible, tilde-shortened otherwise.
fn display_path(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_string_lossy().into_owned()
    } else if path.as_os_str().is_empty() {
        return "(path unavailable)".to_string();
    } else {
        // Already relative — use as-is (e.g. "." for the main worktree).
        return path.to_string_lossy().into_owned();
    };

    // Strip the project root (CWD) to show a repo-relative path.
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy();
        if let Some(relative) = absolute.strip_prefix(cwd_str.as_ref()) {
            let relative = relative.strip_prefix('/').unwrap_or(relative);
            if relative.is_empty() {
                return ".".to_string();
            }
            return relative.to_string();
        }
    }

    // Outside the project — tilde-shorten the absolute path.
    tilde_shorten(&absolute)
}

fn tilde_shorten(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && path.starts_with(&home) => {
            format!("~{}", &path[home.len()..])
        }
        _ => path.to_owned(),
    }
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
    let p = Paragraph::new(format!(
        "Fatal Error: {}\n\nPress 'q' or 'ESC' to exit.",
        err
    ))
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
            Constraint::Fill(1),   // worktrees panel
            Constraint::Fill(1),   // conflicts panel
            Constraint::Fill(1),   // detail panel
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
        Span::styled(
            " \u{2190}\u{2192}",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" panel  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "\u{2191}\u{2193}",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "r",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" refresh  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "q",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
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

    let title = if focused {
        " > Worktrees "
    } else {
        " Worktrees "
    };
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    let mut state = ListState::default();
    if !app.workspaces.is_empty() {
        state.select(Some(app.selected_worktree_index));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_pairs_panel(app: &App, frame: &mut Frame, area: Rect) {
    let focused = app.focused_panel == FocusedPanel::Pairs;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let title = if focused {
        " > Conflicts "
    } else {
        " Conflicts "
    };

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
        let p = Paragraph::new("\n  No conflicts \u{2014} this worktree is clean.")
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
    let mut state = ListState::default();
    state.select(Some(app.selected_pair_index));
    frame.render_stateful_widget(list, area, &mut state);
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

            // 2 for borders, 14 for label width ("  path        ")
            let max_value_width = area.width.saturating_sub(2 + 14) as usize;

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
                        truncate_path_left(&display_path(&selected_ws.path), max_value_width),
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
                    let p = Paragraph::new("Select a conflict pair to view details.").block(block);
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
                symbols.push((path.to_string_lossy().into_owned(), symbol_name.clone()));
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
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
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

#[cfg(test)]
mod tests {
    use super::*;
    use grove_cli::client::DaemonClient;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use serde_json::json;
    use std::path::PathBuf;

    fn make_workspace(id: &str, name: &str, branch: &str, path: &str) -> grove_lib::Workspace {
        serde_json::from_value(json!({
            "id": id,
            "name": name,
            "branch": branch,
            "path": path,
            "base_ref": "refs/heads/main",
            "created_at": "2026-01-01T00:00:00Z",
            "last_activity": "2026-01-01T00:00:00Z",
            "metadata": {}
        }))
        .unwrap()
    }

    fn make_analysis(
        workspace_a: &str,
        workspace_b: &str,
        score: &str,
        overlaps: Vec<serde_json::Value>,
    ) -> WorkspacePairAnalysis {
        serde_json::from_value(json!({
            "workspace_a": workspace_a,
            "workspace_b": workspace_b,
            "score": score,
            "overlaps": overlaps,
            "merge_order_hint": "Either",
            "last_computed": "2026-01-01T00:00:00Z"
        }))
        .unwrap()
    }

    fn app_with_defaults() -> App {
        App::new(DaemonClient::new(
            "/tmp/nonexistent-grove-tui-ui-tests.sock",
        ))
    }

    fn render_to_text(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(app, frame)).unwrap();

        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                let idx = (y as usize * buffer.area.width as usize) + x as usize;
                out.push_str(buffer.content[idx].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn truncate_with_ellipsis_handles_boundaries() {
        assert_eq!(truncate_with_ellipsis("abcdef", 0), "");
        assert_eq!(truncate_with_ellipsis("abcdef", 1), "…");
        assert_eq!(truncate_with_ellipsis("abc", 3), "abc");
        assert_eq!(truncate_with_ellipsis("abcdef", 4), "abc…");
    }

    #[test]
    fn build_overlap_lines_empty_overlaps_is_clean_message() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "alpha",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "beta",
            "feature/b",
            "/tmp/b",
        );

        let mut app = app_with_defaults();
        app.workspaces = vec![ws_a, ws_b];

        let analysis = make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Green",
            vec![],
        );

        let lines = build_overlap_lines(&analysis, &app);
        let rendered = lines
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("No overlaps between alpha and beta."));
    }

    #[test]
    fn build_overlap_lines_groups_all_overlap_kinds() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "alpha",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "beta",
            "feature/b",
            "/tmp/b",
        );

        let mut app = app_with_defaults();
        app.workspaces = vec![ws_a, ws_b];

        let analysis = make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Black",
            vec![
                json!({
                    "File": {
                        "path": "src/lib.rs",
                        "a_change": "Modified",
                        "b_change": "Modified"
                    }
                }),
                json!({
                    "Hunk": {
                        "path": "src/lib.rs",
                        "a_range": {"start": 10, "end": 20},
                        "b_range": {"start": 15, "end": 25},
                        "distance": 0
                    }
                }),
                json!({
                    "Symbol": {
                        "path": "src/lib.rs",
                        "symbol_name": "process",
                        "a_modification": "branch-a",
                        "b_modification": "branch-b"
                    }
                }),
                json!({
                    "Dependency": {
                        "changed_in": "00000000-0000-0000-0000-000000000001",
                        "changed_file": "src/api.rs",
                        "changed_export": {
                            "Added": {
                                "name": "new_fn",
                                "kind": "Function",
                                "range": {"start": 1, "end": 1},
                                "signature": null
                            }
                        },
                        "affected_file": "src/use_api.rs",
                        "affected_usage": [{
                            "file": "src/use_api.rs",
                            "line": 10,
                            "column": 5
                        }]
                    }
                }),
                json!({
                    "Schema": {
                        "category": "Route",
                        "a_file": "routes/api.yaml",
                        "b_file": "routes/internal.yaml",
                        "detail": "route files touched"
                    }
                }),
            ],
        );

        let lines = build_overlap_lines(&analysis, &app);
        let rendered = lines
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("Both branches edit the same files"));
        assert!(rendered.contains("Both branches change the same lines"));
        assert!(rendered.contains("Both branches modify the same functions"));
        assert!(rendered.contains("affect the other's imports"));
        assert!(rendered.contains("touch shared config/schemas"));
    }

    #[test]
    fn render_loading_view_includes_loading_copy() {
        let mut app = app_with_defaults();
        app.view_state = ViewState::Loading;
        let rendered = render_to_text(&app, 90, 20);

        assert!(rendered.contains("Grove Dashboard"));
        assert!(rendered.contains("Connecting to daemon and loading worktrees"));
    }

    #[test]
    fn render_no_worktrees_view_includes_guidance() {
        let mut app = app_with_defaults();
        app.view_state = ViewState::NoWorktrees;
        let rendered = render_to_text(&app, 90, 20);

        assert!(rendered.contains("Not enough worktrees detected"));
        assert!(rendered.contains("requires at least two worktrees"));
    }

    #[test]
    fn render_error_view_includes_error_and_exit_hint() {
        let mut app = app_with_defaults();
        app.view_state = ViewState::Error("socket timeout".to_string());
        let rendered = render_to_text(&app, 90, 20);

        assert!(rendered.contains("Fatal Error: socket timeout"));
        assert!(rendered.contains("Press 'q' or 'ESC' to exit"));
    }

    #[test]
    fn render_dashboard_includes_sections_and_pair_details() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "alpha",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "beta",
            "feature/b",
            "/tmp/b",
        );

        let analysis = make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Red",
            vec![json!({
                "Symbol": {
                    "path": "src/lib.rs",
                    "symbol_name": "process",
                    "a_modification": "A",
                    "b_modification": "B"
                }
            })],
        );

        let mut app = app_with_defaults();
        app.view_state = ViewState::Dashboard;
        app.base_commit = "12345678".to_string();
        app.workspaces = vec![ws_a, ws_b];
        app.analyses = vec![analysis];
        app.focused_panel = FocusedPanel::Pairs;

        let rendered = render_to_text(&app, 120, 34);

        assert!(rendered.contains("Grove Status"));
        assert!(rendered.contains("Worktrees"));
        assert!(rendered.contains("Conflicts"));
        assert!(rendered.contains("Details"));
        assert!(rendered.contains("RED"));
        assert!(rendered.contains("Both branches modify the same functions"));
    }

    #[test]
    fn render_dashboard_shows_clean_message_for_selected_workspace_with_no_pairs() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "alpha",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "beta",
            "feature/b",
            "/tmp/b",
        );
        let ws_c = make_workspace(
            "00000000-0000-0000-0000-000000000003",
            "clean",
            "feature/c",
            "/tmp/c",
        );

        let analysis = make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Yellow",
            vec![json!({
                "File": {
                    "path": "src/lib.rs",
                    "a_change": "Modified",
                    "b_change": "Modified"
                }
            })],
        );

        let mut app = app_with_defaults();
        app.view_state = ViewState::Dashboard;
        app.workspaces = vec![ws_a, ws_b, ws_c];
        app.analyses = vec![analysis];
        app.selected_worktree_index = 2;
        app.focused_panel = FocusedPanel::Pairs;

        let rendered = render_to_text(&app, 120, 34);
        assert!(rendered.contains("No conflicts"));
        assert!(rendered.contains("this worktree is clean"));
    }

    #[test]
    fn render_dashboard_details_shows_hidden_folder_absolute_path() {
        let ws = make_workspace(
            "00000000-0000-0000-0000-000000000009",
            "worktree-peaceful-humming-whistle",
            "refs/heads/worktree-peaceful-humming-whistle",
            ".claude/worktrees/worktree-peaceful-humming-whistle",
        );

        let mut app = app_with_defaults();
        app.view_state = ViewState::Dashboard;
        app.workspaces = vec![ws];
        app.focused_panel = FocusedPanel::Worktrees;

        let rendered = render_to_text(&app, 160, 34);
        assert!(rendered.contains("path"));
        // Relative paths are kept as-is (no leading '/')
        assert!(rendered.contains(".claude/worktrees/worktree-peaceful-humming-whistle"));
    }

    #[test]
    fn display_path_never_returns_empty_string() {
        assert!(!display_path(Path::new("")).trim().is_empty());
    }

    #[test]
    fn tilde_shorten_replaces_home_prefix() {
        let home = std::env::var("HOME").unwrap();
        let long_path =
            format!("{home}/Projects/movies-ranking/.claude/worktrees/peaceful-humming-whistle");
        let shortened = tilde_shorten(&long_path);
        assert!(shortened.starts_with("~/"));
        assert!(shortened.contains(".claude/worktrees/peaceful-humming-whistle"));
        assert!(shortened.len() < long_path.len());
    }

    #[test]
    fn tilde_shorten_leaves_non_home_paths_unchanged() {
        assert_eq!(tilde_shorten("/tmp/foo"), "/tmp/foo");
    }

    #[test]
    fn display_path_tilde_shortens_paths_outside_cwd() {
        let home = std::env::var("HOME").unwrap();
        // Use a path that's definitely NOT under CWD
        let p = PathBuf::from(format!("{home}/some-nonexistent-project-xyz"));
        let result = display_path(&p);
        assert!(result.starts_with("~/"));
        assert!(!result.contains(&home));
    }

    #[test]
    fn display_path_returns_repo_relative_for_cwd_children() {
        let cwd = std::env::current_dir().unwrap();
        let p = cwd.join(".claude/worktrees/my-worktree");
        let result = display_path(&p);
        assert_eq!(result, ".claude/worktrees/my-worktree");
    }

    #[test]
    fn display_path_returns_dot_for_cwd_itself() {
        let cwd = std::env::current_dir().unwrap();
        let result = display_path(&cwd);
        assert_eq!(result, ".");
    }

    #[test]
    fn truncate_path_left_keeps_trailing_components() {
        let path = "~/Projects/movies-ranking/.claude/worktrees/peaceful-humming-whistle";
        // Budget of 50 should keep the meaningful end
        let result = truncate_path_left(path, 50);
        assert!(result.starts_with('…'));
        assert!(result.ends_with("peaceful-humming-whistle"));
        assert!(result.len() <= 50);
    }

    #[test]
    fn truncate_path_left_returns_full_path_when_fits() {
        let path = "~/short/path";
        assert_eq!(truncate_path_left(path, 80), "~/short/path");
    }

    #[test]
    fn truncate_path_left_falls_back_to_right_truncation() {
        // Single component longer than budget — no '/' boundary fits
        let path = "/very-long-single-component-name";
        let result = truncate_path_left(path, 10);
        assert!(result.ends_with('…'));
        // truncate_with_ellipsis counts display columns, not bytes;
        // '…' is 1 column but 3 UTF-8 bytes.
        assert_eq!(result, "/very-lon…");
    }

    #[test]
    fn render_dashboard_path_visible_at_narrow_width() {
        let ws = make_workspace(
            "00000000-0000-0000-0000-000000000009",
            "worktree-peaceful-humming-whistle",
            "refs/heads/worktree-peaceful-humming-whistle",
            "/Users/test/Projects/movies-ranking/.claude/worktrees/peaceful-humming-whistle",
        );

        let mut app = app_with_defaults();
        app.view_state = ViewState::Dashboard;
        app.workspaces = vec![ws];
        app.focused_panel = FocusedPanel::Worktrees;

        // 80 columns — the scenario that was failing
        let rendered = render_to_text(&app, 80, 30);
        assert!(rendered.contains("path"));
        assert!(rendered.contains("peaceful-humming-whistle"));
    }
}
