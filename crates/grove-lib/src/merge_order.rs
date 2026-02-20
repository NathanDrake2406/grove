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

    #[test]
    fn merge_order_contains_all_workspace_ids_exactly_once() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Yellow, MergeOrder::AFirst),
            make_analysis(b, c, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(c, d, OrthogonalityScore::Yellow, MergeOrder::AFirst),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c, d]);
        let mut seen = result.ordered.clone();
        seen.extend(result.independent.clone());
        seen.sort();
        seen.dedup();
        let mut expected = vec![a, b, c, d];
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[test]
    fn merge_order_is_valid_topological_ordering() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Yellow, MergeOrder::AFirst),
            make_analysis(a, c, OrthogonalityScore::Yellow, MergeOrder::AFirst),
            make_analysis(c, d, OrthogonalityScore::Red, MergeOrder::AFirst),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c, d]);
        assert!(!result.has_cycle);

        let pos = |id: WorkspaceId| {
            result
                .ordered
                .iter()
                .position(|x| *x == id)
                .unwrap_or(usize::MAX)
        };
        assert!(pos(a) < pos(b));
        assert!(pos(a) < pos(c));
        assert!(pos(c) < pos(d));
    }

    #[test]
    fn cycle_detection_with_five_workspaces() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();
        let e = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(b, c, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(c, d, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(d, e, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(e, a, OrthogonalityScore::Red, MergeOrder::AFirst),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c, d, e]);
        assert!(result.has_cycle);
        assert_eq!(result.ordered.len(), 5);
        assert!(result.independent.is_empty());
    }

    #[test]
    fn single_workspace_is_independent() {
        let a = Uuid::new_v4();
        let result = compute_merge_order(&[], &[a]);
        assert!(!result.has_cycle);
        assert!(result.ordered.is_empty());
        assert_eq!(result.independent, vec![a]);
    }

    #[test]
    fn green_score_ignores_directional_hint_constraints() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let analyses = vec![make_analysis(
            a,
            b,
            OrthogonalityScore::Green,
            MergeOrder::AFirst,
        )];

        let result = compute_merge_order(&analyses, &[a, b]);
        assert!(!result.has_cycle);
        assert!(result.ordered.is_empty());
        assert_eq!(result.independent.len(), 2);
        assert!(result.independent.contains(&a));
        assert!(result.independent.contains(&b));
    }

    #[test]
    fn needs_coordination_adds_deterministic_a_to_b_edge() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let analyses = vec![make_analysis(
            a,
            b,
            OrthogonalityScore::Black,
            MergeOrder::NeedsCoordination,
        )];

        let result = compute_merge_order(&analyses, &[a, b]);
        assert!(!result.has_cycle);
        assert_eq!(result.ordered, vec![a, b]);
        assert!(result.independent.is_empty());
    }

    #[test]
    fn duplicate_constraints_preserve_unique_workspace_membership() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let mut analyses = Vec::new();
        for _ in 0..25 {
            analyses.push(make_analysis(
                a,
                b,
                OrthogonalityScore::Red,
                MergeOrder::AFirst,
            ));
        }
        analyses.push(make_analysis(
            b,
            c,
            OrthogonalityScore::Green,
            MergeOrder::Either,
        ));

        let result = compute_merge_order(&analyses, &[a, b, c]);
        assert!(!result.has_cycle);
        assert!(result.independent.contains(&c));
        let a_pos = result.ordered.iter().position(|id| *id == a).unwrap();
        let b_pos = result.ordered.iter().position(|id| *id == b).unwrap();
        assert!(a_pos < b_pos);

        let mut all = result.ordered.clone();
        all.extend(result.independent.clone());
        all.sort();
        all.dedup();
        let mut expected = vec![a, b, c];
        expected.sort();
        assert_eq!(all, expected);
    }

    #[test]
    fn cycle_fallback_preserves_workspace_input_order() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(b, c, OrthogonalityScore::Red, MergeOrder::AFirst),
            make_analysis(c, a, OrthogonalityScore::Red, MergeOrder::AFirst),
        ];

        let workspace_ids = vec![c, a, b];
        let result = compute_merge_order(&analyses, &workspace_ids);
        assert!(result.has_cycle);
        assert_eq!(result.ordered, workspace_ids);
        assert!(result.independent.is_empty());
    }

    #[test]
    fn large_chain_graph_respects_ordering_constraints() {
        let workspace_ids: Vec<_> = (0..80).map(|_| Uuid::new_v4()).collect();
        let analyses: Vec<_> = workspace_ids
            .windows(2)
            .map(|pair| {
                make_analysis(
                    pair[0],
                    pair[1],
                    OrthogonalityScore::Yellow,
                    MergeOrder::AFirst,
                )
            })
            .collect();

        let result = compute_merge_order(&analyses, &workspace_ids);
        assert!(!result.has_cycle);
        assert!(result.independent.is_empty());

        let mut pos = std::collections::HashMap::new();
        for (i, id) in result.ordered.iter().enumerate() {
            pos.insert(*id, i);
        }
        for pair in workspace_ids.windows(2) {
            assert!(pos[&pair[0]] < pos[&pair[1]]);
        }
    }

    #[test]
    fn dense_acyclic_graph_is_returned_as_valid_topological_order() {
        let workspace_ids: Vec<_> = (0..24).map(|_| Uuid::new_v4()).collect();
        let mut analyses = Vec::new();

        for i in 0..workspace_ids.len() {
            for j in (i + 1)..workspace_ids.len() {
                analyses.push(make_analysis(
                    workspace_ids[i],
                    workspace_ids[j],
                    OrthogonalityScore::Red,
                    MergeOrder::AFirst,
                ));
            }
        }

        let result = compute_merge_order(&analyses, &workspace_ids);
        assert!(!result.has_cycle);
        assert!(result.independent.is_empty());
        assert_eq!(result.ordered.len(), workspace_ids.len());

        let mut pos = std::collections::HashMap::new();
        for (idx, id) in result.ordered.iter().enumerate() {
            pos.insert(*id, idx);
        }

        for i in 0..workspace_ids.len() {
            for j in (i + 1)..workspace_ids.len() {
                assert!(pos[&workspace_ids[i]] < pos[&workspace_ids[j]]);
            }
        }
    }
}
