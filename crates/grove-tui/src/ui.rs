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

    let mut lines = vec![];

    for overlap in &analysis.overlaps {
        match overlap {
            Overlap::File { path, .. } => {
                lines.push(Line::from(vec![
                    Span::styled("same file      ", Style::default().fg(Color::Yellow)),
                    Span::raw(path.to_string_lossy().to_string()),
                ]));
            }
            Overlap::Hunk { path, a_range, distance, .. } => {
                let color = if *distance == 0 { Color::Red } else { Color::Yellow };
                lines.push(Line::from(vec![
                    Span::styled("same lines     ", Style::default().fg(color)),
                    Span::raw(format!("{}:{}-{}", path.to_string_lossy(), a_range.start, a_range.end)),
                ]));
            }
            Overlap::Symbol { path, symbol_name, .. } => {
                lines.push(Line::from(vec![
                    Span::styled("same function  ", Style::default().fg(Color::Red)),
                    Span::raw(format!("{}() in {}", symbol_name, path.to_string_lossy())),
                ]));
            }
            Overlap::Dependency { changed_file, affected_file, .. } => {
                lines.push(Line::from(vec![
                    Span::styled("import chain   ", Style::default().fg(Color::Magenta)),
                    Span::raw(format!(
                        "{} -> {}",
                        changed_file.to_string_lossy(),
                        affected_file.to_string_lossy()
                    )),
                ]));
            }
            Overlap::Schema { category, a_file, b_file, detail } => {
                lines.push(Line::from(vec![
                    Span::styled("config conflict ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!(
                        "[{:?}] {} vs {} ({})",
                        category,
                        a_file.to_string_lossy(),
                        b_file.to_string_lossy(),
                        detail
                    )),
                ]));
            }
        }
    }

    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    
    frame.render_widget(p, area);
}
