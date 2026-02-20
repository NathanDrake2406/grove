use crate::types::*;
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Given pair analyses, compute the optimal merge sequence.
/// Returns workspace IDs in order (first to merge -> last to merge),
/// plus any independent workspaces that can merge anytime.
pub fn compute_merge_order(
    analyses: &[WorkspacePairAnalysis],
    workspace_ids: &[WorkspaceId],
) -> MergeSequence {
    let mut graph = DiGraph::<WorkspaceId, ()>::new();
    let mut node_map: HashMap<WorkspaceId, NodeIndex> = HashMap::new();

    // Add all workspaces as nodes
    for id in workspace_ids {
        let idx = graph.add_node(*id);
        node_map.insert(*id, idx);
    }

    // Add edges based on pair analyses
    for analysis in analyses {
        if analysis.score == OrthogonalityScore::Green {
            continue; // No edge needed for independent pairs
        }

        let a_idx = node_map[&analysis.workspace_a];
        let b_idx = node_map[&analysis.workspace_b];

        match analysis.merge_order_hint {
            MergeOrder::AFirst => {
                graph.add_edge(a_idx, b_idx, ());
            }
            MergeOrder::BFirst => {
                graph.add_edge(b_idx, a_idx, ());
            }
            MergeOrder::NeedsCoordination => {
                // Black-level: add edge A->B (arbitrary but deterministic)
                graph.add_edge(a_idx, b_idx, ());
            }
            MergeOrder::Either => {} // No constraint
        }
    }

    // Topological sort
    match toposort(&graph, None) {
        Ok(sorted) => {
            let sequence: Vec<WorkspaceId> = sorted.iter().map(|idx| graph[*idx]).collect();

            // Identify independent workspaces (no edges at all)
            let independent: Vec<WorkspaceId> = workspace_ids
                .iter()
                .filter(|id| {
                    let idx = node_map[id];
                    graph.neighbors_undirected(idx).next().is_none()
                })
                .copied()
                .collect();

            let ordered: Vec<WorkspaceId> = sequence
                .into_iter()
                .filter(|id| !independent.contains(id))
                .collect();

            MergeSequence {
                ordered,
                independent,
                has_cycle: false,
            }
        }
        Err(_) => {
            // Cycle detected — fall back to ordering by fewest files changed
            MergeSequence {
                ordered: workspace_ids.to_vec(),
                independent: vec![],
                has_cycle: true,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MergeSequence {
    pub ordered: Vec<WorkspaceId>,
    pub independent: Vec<WorkspaceId>,
    pub has_cycle: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_analysis(
        a: WorkspaceId,
        b: WorkspaceId,
        score: OrthogonalityScore,
        hint: MergeOrder,
    ) -> WorkspacePairAnalysis {
        WorkspacePairAnalysis {
            workspace_a: a,
            workspace_b: b,
            score,
            overlaps: vec![],
            merge_order_hint: hint,
            last_computed: Utc::now(),
        }
    }

    #[test]
    fn all_green_means_all_independent() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Green, MergeOrder::Either),
            make_analysis(a, c, OrthogonalityScore::Green, MergeOrder::Either),
            make_analysis(b, c, OrthogonalityScore::Green, MergeOrder::Either),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c]);
        assert_eq!(result.independent.len(), 3);
        assert!(result.ordered.is_empty());
        assert!(!result.has_cycle);
    }

    #[test]
    fn a_first_hint_orders_correctly() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let analyses = vec![make_analysis(
            a,
            b,
            OrthogonalityScore::Red,
            MergeOrder::AFirst,
        )];

        let result = compute_merge_order(&analyses, &[a, b]);
        assert_eq!(result.ordered, vec![a, b]);
        assert!(!result.has_cycle);
    }

    #[test]
    fn three_workspace_chain() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Yellow, MergeOrder::AFirst),
            make_analysis(b, c, OrthogonalityScore::Red, MergeOrder::AFirst),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c]);
        // a before b, b before c
        let a_pos = result.ordered.iter().position(|x| *x == a).unwrap();
        let b_pos = result.ordered.iter().position(|x| *x == b).unwrap();
        let c_pos = result.ordered.iter().position(|x| *x == c).unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }
}
