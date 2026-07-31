use std::collections::VecDeque;

/// A directed edge between two nodes in the connectivity graph.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub allowed: bool,
}

/// Intermediate representation of pod connectivity.
#[derive(Debug, Clone)]
pub struct ConnectivityGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<Edge>,
}

/// Render a connectivity graph as an ASCII box-and-arrow diagram.
///
/// Layout strategy:
/// - Assigns pods to layers (columns) via topological sort on allowed edges.
/// - Pods in the same layer are stacked vertically.
/// - Horizontal edges between layers are drawn as `──▶` or `◀──▶`.
/// - Cross-row edges (same or different layer) are listed as text below the diagram.
pub fn build_ascii(graph: &ConnectivityGraph, include_denied: bool) -> String {
    if graph.nodes.is_empty() {
        return String::from("(no pods found)\n");
    }

    let visible_edges: Vec<&Edge> = graph
        .edges
        .iter()
        .filter(|e| e.from != e.to)
        .filter(|e| e.allowed || include_denied)
        .collect();

    let layers = assign_layers(graph);
    let layer_groups = group_by_layer(&layers, graph.nodes.len());

    let mut node_layer_row: Vec<(usize, usize)> = vec![(0, 0); graph.nodes.len()];
    for (li, group) in layer_groups.iter().enumerate() {
        for (ri, &ni) in group.iter().enumerate() {
            node_layer_row[ni] = (li, ri);
        }
    }

    // Separate edges into "drawable" (same row, adjacent layers, no intermediate
    // box blocking the path) and "extra" (everything else → text list).
    let mut drawable_h: Vec<(usize, usize, bool)> = vec![];
    let mut extra: Vec<(usize, usize, bool)> = vec![];

    for edge in &visible_edges {
        let (fl, fr) = node_layer_row[edge.from];
        let (tl, tr) = node_layer_row[edge.to];
        let denied = !edge.allowed;

        if fr == tr && fl != tl {
            // Same row, different layer — check if any intermediate layer
            // has a pod on this row that the arrow would cross through.
            let (min_l, max_l) = if fl < tl { (fl, tl) } else { (tl, fl) };
            let blocked = (min_l + 1..max_l).any(|mid_l| {
                layer_groups[mid_l].len() > fr // there's a box at this row in the intermediate layer
            });

            if blocked {
                extra.push((edge.from, edge.to, denied));
            } else {
                drawable_h.push((edge.from, edge.to, denied));
            }
        } else {
            extra.push((edge.from, edge.to, denied));
        }
    }

    // Layout constants.
    let box_height: usize = 3;
    let row_gap: usize = 2;
    let col_gap: usize = 5;

    let layer_widths: Vec<usize> = layer_groups
        .iter()
        .map(|g| g.iter().map(|&i| box_width(&graph.nodes[i])).max().unwrap_or(0))
        .collect();

    let num_layers = layer_groups.len();
    let mut layer_x: Vec<usize> = Vec::with_capacity(num_layers);
    let mut x = 0;
    for i in 0..num_layers {
        layer_x.push(x);
        if i < num_layers - 1 {
            x += layer_widths[i] + col_gap;
        }
    }

    let max_rows = layer_groups.iter().map(|g| g.len()).max().unwrap_or(1);
    let canvas_w = *layer_x.last().unwrap() + *layer_widths.last().unwrap() + 2;
    let canvas_h = max_rows * box_height + max_rows.saturating_sub(1) * row_gap;

    let mut canvas = Canvas::new(canvas_w, canvas_h);

    // Draw boxes.
    let mut node_pos: Vec<(usize, usize, usize)> = vec![(0, 0, 0); graph.nodes.len()];
    for (li, group) in layer_groups.iter().enumerate() {
        let lx = layer_x[li];
        for (ri, &ni) in group.iter().enumerate() {
            let by = ri * (box_height + row_gap);
            let bw = box_width(&graph.nodes[ni]);
            node_pos[ni] = (lx, by, bw);
            canvas.draw_box(lx, by, &graph.nodes[ni]);
        }
    }

    // Detect bidirectional horizontal pairs.
    let mut bidir_pairs: Vec<(usize, usize)> = vec![];
    for &(f, t, d) in &drawable_h {
        if !d {
            let has_rev = drawable_h.iter().any(|&(f2, t2, d2)| f2 == t && t2 == f && !d2);
            if has_rev && f < t && !bidir_pairs.contains(&(f, t)) {
                bidir_pairs.push((f, t));
            }
        }
    }

    // Draw horizontal arrows.
    for &(f, t, denied) in &drawable_h {
        if bidir_pairs.iter().any(|&(a, b)| a == t && b == f) {
            continue; // Skip reverse of bidir pair.
        }
        let bidir = bidir_pairs.iter().any(|&(a, b)| a == f && b == t);

        let (fx, fy, fw) = node_pos[f];
        let (tx, _ty, _tw) = node_pos[t];
        let mid_y = fy + 1;

        if fx < tx {
            canvas.draw_horizontal_arrow(fx + fw, tx, mid_y, denied, bidir);
        } else {
            canvas.draw_horizontal_arrow(tx + _tw, fx, mid_y, denied, bidir);
        }
    }

    let mut output = canvas.render();

    // Append cross-row edges as a text list below the diagram.
    if !extra.is_empty() {
        output.push('\n');
        for &(f, t, denied) in &extra {
            let arrow = if denied { "╌╌▶" } else { "──▶" };
            let tag = if denied { " [denied]" } else { "" };
            output.push_str(&format!(
                "  {} {} {}{}\n",
                graph.nodes[f], arrow, graph.nodes[t], tag
            ));
        }
    }

    output
}

/// Width of a box for a given label: │ label │ → len + 4.
fn box_width(label: &str) -> usize {
    label.len() + 4
}

/// Assign each node to a layer (column) using BFS-based topological ordering
/// on allowed edges.
fn assign_layers(graph: &ConnectivityGraph) -> Vec<usize> {
    let n = graph.nodes.len();
    if n == 0 {
        return vec![];
    }

    let mut in_degree = vec![0usize; n];
    let mut adj: Vec<Vec<usize>> = vec![vec![]; n];
    let mut has_any_allowed = false;

    for edge in &graph.edges {
        if edge.allowed {
            adj[edge.from].push(edge.to);
            in_degree[edge.to] += 1;
            has_any_allowed = true;
        }
    }

    if !has_any_allowed {
        return vec![0; n];
    }

    let mut layers = vec![0usize; n];
    let mut queue = VecDeque::new();

    for i in 0..n {
        if in_degree[i] == 0 {
            queue.push_back(i);
        }
    }

    if queue.is_empty() {
        let min_node = (0..n).min_by_key(|&i| in_degree[i]).unwrap();
        queue.push_back(min_node);
        in_degree[min_node] = 0;
    }

    let mut visited = vec![false; n];
    while let Some(node) = queue.pop_front() {
        visited[node] = true;
        for &next in &adj[node] {
            if visited[next] {
                continue;
            }
            layers[next] = layers[next].max(layers[node] + 1);
            in_degree[next] = in_degree[next].saturating_sub(1);
            if in_degree[next] == 0 {
                queue.push_back(next);
            }
        }
    }

    for i in 0..n {
        if !visited[i] {
            layers[i] = 0;
        }
    }

    // If all nodes ended up in the same layer (fully-connected or cyclic),
    // spread them into separate layers so they render as a horizontal row.
    let max_layer = *layers.iter().max().unwrap_or(&0);
    if max_layer == 0 && n > 1 {
        for i in 0..n {
            layers[i] = i;
        }
    }

    layers
}

/// Group node indices by their layer assignment.
fn group_by_layer(layers: &[usize], n: usize) -> Vec<Vec<usize>> {
    let max_layer = layers.iter().copied().max().unwrap_or(0);
    let mut groups = vec![vec![]; max_layer + 1];
    for i in 0..n {
        groups[layers[i]].push(i);
    }
    groups
}

/// A 2D character canvas for rendering ASCII graphics.
struct Canvas {
    grid: Vec<Vec<char>>,
    width: usize,
    height: usize,
}

impl Canvas {
    fn new(width: usize, height: usize) -> Self {
        Self {
            grid: vec![vec![' '; width]; height],
            width,
            height,
        }
    }

    fn set(&mut self, x: usize, y: usize, ch: char) {
        if y < self.height && x < self.width {
            self.grid[y][x] = ch;
        }
    }

    fn draw_box(&mut self, x: usize, y: usize, label: &str) {
        let w = label.len() + 4;
        self.set(x, y, '┌');
        for i in 1..w - 1 {
            self.set(x + i, y, '─');
        }
        self.set(x + w - 1, y, '┐');

        self.set(x, y + 1, '│');
        self.set(x + 1, y + 1, ' ');
        for (i, ch) in label.chars().enumerate() {
            self.set(x + 2 + i, y + 1, ch);
        }
        self.set(x + w - 2, y + 1, ' ');
        self.set(x + w - 1, y + 1, '│');

        self.set(x, y + 2, '└');
        for i in 1..w - 1 {
            self.set(x + i, y + 2, '─');
        }
        self.set(x + w - 1, y + 2, '┘');
    }

    fn draw_horizontal_arrow(
        &mut self,
        x_start: usize,
        x_end: usize,
        y: usize,
        denied: bool,
        bidir: bool,
    ) {
        if x_start >= x_end {
            return;
        }

        let shaft = if denied { '╌' } else { '─' };

        if bidir {
            self.set(x_start, y, '◀');
        }

        for x in (x_start + 1)..x_end.saturating_sub(1) {
            self.set(x, y, shaft);
        }

        if x_end > x_start + 1 {
            self.set(x_end - 1, y, '▶');
        }
    }

    fn render(&self) -> String {
        let mut output = String::new();
        for row in &self.grid {
            let line: String = row.iter().collect();
            let trimmed = line.trim_end();
            output.push_str(trimmed);
            output.push('\n');
        }
        while output.ends_with("\n\n") {
            output.pop();
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph(nodes: &[&str], edges: &[(usize, usize, bool)]) -> ConnectivityGraph {
        ConnectivityGraph {
            nodes: nodes.iter().map(|s| s.to_string()).collect(),
            edges: edges
                .iter()
                .map(|&(from, to, allowed)| Edge { from, to, allowed })
                .collect(),
        }
    }

    #[test]
    fn single_pod_renders_box() {
        let graph = simple_graph(&["api"], &[]);
        let output = build_ascii(&graph, false);
        assert!(output.contains("┌─────┐"));
        assert!(output.contains("│ api │"));
        assert!(output.contains("└─────┘"));
    }

    #[test]
    fn two_pods_with_edge() {
        let graph = simple_graph(&["frontend", "api"], &[(0, 1, true)]);
        let output = build_ascii(&graph, false);
        assert!(output.contains("│ frontend │"));
        assert!(output.contains("│ api │"));
        assert!(output.contains('▶'));
    }

    #[test]
    fn denied_edge_hidden_by_default() {
        let graph = simple_graph(&["frontend", "db"], &[(0, 1, false)]);
        let output = build_ascii(&graph, false);
        assert!(output.contains("│ frontend │"));
        assert!(output.contains("│ db │"));
        assert!(!output.contains('▶'));
        assert!(!output.contains('◀'));
    }

    #[test]
    fn denied_edge_shown_when_included() {
        let graph = simple_graph(&["frontend", "db"], &[(0, 1, false)]);
        let output = build_ascii(&graph, true);
        // Denied edge shown as text with dashed arrow
        assert!(output.contains("╌╌▶"));
        assert!(output.contains("[denied]"));
    }

    #[test]
    fn three_pod_chain() {
        let graph = simple_graph(
            &["frontend", "api", "db"],
            &[(0, 1, true), (1, 2, true)],
        );
        let output = build_ascii(&graph, false);
        assert!(output.contains("│ frontend │"));
        assert!(output.contains("│ api │"));
        assert!(output.contains("│ db │"));
        let arrow_count = output.matches('▶').count();
        assert!(arrow_count >= 2, "expected at least 2 arrows, got {arrow_count}");
    }

    #[test]
    fn bidirectional_edge_horizontal() {
        let graph = simple_graph(
            &["api", "cache"],
            &[(0, 1, true), (1, 0, true)],
        );
        let output = build_ascii(&graph, false);
        assert!(output.contains('◀'));
        assert!(output.contains('▶'));
    }

    #[test]
    fn empty_graph() {
        let graph = simple_graph(&[], &[]);
        let output = build_ascii(&graph, false);
        assert!(output.contains("no pods found"));
    }

    #[test]
    fn no_self_loops_in_rendering() {
        let graph = simple_graph(&["api"], &[(0, 0, true)]);
        let output = build_ascii(&graph, false);
        assert!(output.contains("│ api │"));
    }

    #[test]
    fn branching_graph_has_cross_row_text() {
        // gateway -> api and gateway -> worker
        // api and worker are in same layer (layer 1), different rows.
        // gateway -> api is horizontal (same row 0), gateway -> worker is cross-row.
        let graph = simple_graph(
            &["gateway", "api", "worker"],
            &[(0, 1, true), (0, 2, true)],
        );
        let output = build_ascii(&graph, false);
        assert!(output.contains("│ gateway │"));
        assert!(output.contains("│ api │"));
        // worker is on a different row, so the gateway->worker edge
        // is rendered as a text line below.
        assert!(output.contains("gateway ──▶ worker"));
    }

    #[test]
    fn cross_row_edges_dont_corrupt_boxes() {
        let graph = simple_graph(
            &["gateway", "api", "worker"],
            &[(0, 1, true), (0, 2, true), (1, 2, true)],
        );
        let output = build_ascii(&graph, false);
        // All boxes must be intact — no arrows cutting through them.
        assert!(output.contains("│ gateway │"));
        assert!(output.contains("│ api │"));
        // Cross-row edges appear as text.
        assert!(output.contains("──▶ worker"));
    }

    #[test]
    fn box_width_calculation() {
        assert_eq!(box_width("api"), 7);
        assert_eq!(box_width("frontend"), 12);
        assert_eq!(box_width("a"), 5);
    }

    #[test]
    fn layer_assignment_chain() {
        let graph = simple_graph(&["A", "B", "C"], &[(0, 1, true), (1, 2, true)]);
        let layers = assign_layers(&graph);
        assert_eq!(layers, vec![0, 1, 2]);
    }

    #[test]
    fn layer_assignment_no_edges() {
        let graph = simple_graph(&["A", "B", "C"], &[]);
        let layers = assign_layers(&graph);
        assert_eq!(layers, vec![0, 0, 0]);
    }

    #[test]
    fn layer_assignment_branching() {
        let graph = simple_graph(&["A", "B", "C"], &[(0, 1, true), (0, 2, true)]);
        let layers = assign_layers(&graph);
        assert_eq!(layers[0], 0);
        assert_eq!(layers[1], 1);
        assert_eq!(layers[2], 1);
    }

    #[test]
    fn denied_cross_row_edge_shows_tag() {
        let graph = simple_graph(
            &["gateway", "api", "db"],
            &[(0, 1, true), (0, 2, false)],
        );
        let output = build_ascii(&graph, true);
        // The denied cross-row edge should have a [denied] tag.
        assert!(output.contains("gateway ╌╌▶ db [denied]"));
    }
}
