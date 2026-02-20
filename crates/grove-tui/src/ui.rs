use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::app::{App, ViewState};
use grove_lib::{OrthogonalityScore, Overlap, WorkspacePairAnalysis};

pub fn render(app: &App, frame: &mut Frame) {
    let area = frame.area();

    match &app.view_state {
        ViewState::Loading => render_loading(frame, area),
        ViewState::NoWorktrees => render_no_worktrees(frame, area),
        ViewState::Dashboard => render_dashboard(app, frame, area),
        ViewState::PairDetail { analysis } => render_pair_detail(app, analysis, frame, area),
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
    let p = Paragraph::new("Not enough worktrees detected.\nGrove requires at least two worktrees to analyze orthogonality.")
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
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(area);

    let left_chunk = chunks[0];
    let right_chunk = chunks[1];

    let items: Vec<ListItem> = app
        .workspaces
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let style = if i == app.selected_worktree_index {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", w.name), style),
                Span::styled(
                    format!(" ({})", w.branch),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Worktrees ")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, left_chunk);

    if let Some(selected_ws) = app.workspaces.get(app.selected_worktree_index) {
        let pairs = app.get_pairs_for_worktree(&selected_ws.id);

        if pairs.is_empty() {
            let p = Paragraph::new("No overlapping pairs found or analysis pending.")
                .block(Block::default().title(" Conflict Matrix ").borders(Borders::ALL));
            frame.render_widget(p, right_chunk);
            return;
        }

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
                    OrthogonalityScore::Black => Color::Magenta, // No 'Black' color that stands out well on dark terminals, magenta serves as Critical/Black here
                };

                let score_str = match p.score {
                    OrthogonalityScore::Green => "■ GREEN",
                    OrthogonalityScore::Yellow => "■ YELLOW",
                    OrthogonalityScore::Red => "■ RED",
                    OrthogonalityScore::Black => "■ BLACK",
                };

                let sel_style = if i == app.selected_pair_index {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<10} ", score_str), Style::default().fg(score_color)),
                    Span::styled(format!("{} ", target_name), sel_style),
                    Span::styled(
                        format!("({} overlaps)", p.overlaps.len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let pairs_list = List::new(pair_items).block(
            Block::default()
                .title(" Conflict Matrix (Navigate Contextually) ")
                .borders(Borders::ALL),
        );
        frame.render_widget(pairs_list, right_chunk);
    }
}

fn render_pair_detail(app: &App, analysis: &WorkspacePairAnalysis, frame: &mut Frame, area: Rect) {
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

    let block = Block::default()
        .title(format!(" {} ←→ {} View ", ws_a_name, ws_b_name))
        .borders(Borders::ALL);

    if analysis.overlaps.is_empty() {
        let p = Paragraph::new("No overlaps detected between these two worktrees.")
            .block(block)
            .style(Style::default().fg(Color::Green));
        frame.render_widget(p, area);
        return;
    }

    // Group overlaps by type.
    let mut files = vec![];
    let mut hunks = vec![];
    let mut symbols = vec![];
    let mut deps = vec![];
    let mut schemas = vec![];

    for overlap in &analysis.overlaps {
        match overlap {
            Overlap::File { path, .. } => files.push(path),
            Overlap::Hunk { path, a_range, distance, .. } => hunks.push((path, a_range, *distance)),
            Overlap::Symbol { path, symbol_name, .. } => symbols.push((path, symbol_name)),
            Overlap::Dependency { changed_file, affected_file, .. } => deps.push((changed_file, affected_file)),
            Overlap::Schema { category, a_file, b_file, detail } => schemas.push((category, a_file, b_file, detail)),
        }
    }

    let mut lines: Vec<Line> = vec![];

    if !files.is_empty() {
        lines.push(Line::from(Span::styled(
            "Both branches edit the same files:",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        for path in &files {
            lines.push(Line::from(format!("  {}", path.to_string_lossy())));
        }
        lines.push(Line::from(""));
    }

    if !hunks.is_empty() {
        lines.push(Line::from(Span::styled(
            "Both branches change the same lines:",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for (path, range, distance) in &hunks {
            let color = if *distance == 0 { Color::Red } else { Color::Yellow };
            lines.push(Line::from(Span::styled(
                format!("  {}:{}-{}", path.to_string_lossy(), range.start, range.end),
                Style::default().fg(color),
            )));
        }
        lines.push(Line::from(""));
    }

    if !symbols.is_empty() {
        lines.push(Line::from(Span::styled(
            "Both branches modify the same functions:",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for (path, name) in &symbols {
            lines.push(Line::from(format!("  {name}() in {}", path.to_string_lossy())));
        }
        lines.push(Line::from(""));
    }

    if !deps.is_empty() {
        lines.push(Line::from(Span::styled(
            "One branch's changes affect the other's imports:",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        )));
        for (changed, affected) in &deps {
            lines.push(Line::from(format!(
                "  {} \u{2192} {}",
                changed.to_string_lossy(),
                affected.to_string_lossy()
            )));
        }
        lines.push(Line::from(""));
    }

    if !schemas.is_empty() {
        lines.push(Line::from(Span::styled(
            "Both branches touch shared config/schemas:",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        for (category, a_file, b_file, detail) in &schemas {
            lines.push(Line::from(format!(
                "  [{:?}] {} vs {} ({})",
                category,
                a_file.to_string_lossy(),
                b_file.to_string_lossy(),
                detail
            )));
        }
        lines.push(Line::from(""));
    }

    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(p, area);
}
