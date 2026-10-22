#![expect(clippy::unwrap_used, reason = "tests")]

use super::*;

/// Builds a tree from leaf `0`, applying `(new_leaf_id, target, side)` splits in order.
fn build(ops: &[(u32, u32, Side)]) -> SplitTree<u32> {
    let mut t = SplitTree::new(0);
    for &(new_leaf, target, side) in ops {
        assert!(t.split(&target, side, new_leaf), "split target not found");
    }
    t
}

fn area() -> Rect {
    Rect {
        x: 0.0,
        y: 0.0,
        w: 200.0,
        h: 100.0,
    }
}

#[test]
fn new_single_leaf_fills_the_area() {
    let t = SplitTree::new("only");
    assert_eq!(t.leaves(), vec![&"only"]);
    assert_eq!(t.layout(area(), 4.0), vec![("only", area())]);
    assert_eq!(t.dividers(area(), 4.0).len(), 0);
}

#[test]
fn split_right_adds_leaf_in_order() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    assert_eq!(t.leaves(), vec![&0, &1]);
}

#[test]
fn split_left_puts_new_leaf_first() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Left, 1));
    assert_eq!(t.leaves(), vec![&1, &0]);
}

#[test]
fn split_missing_target_returns_false_and_is_a_no_op() {
    let mut t = SplitTree::new(0u32);
    let before = t.clone();
    assert!(!t.split(&99, Side::Right, 1));
    assert_eq!(t, before);
}

#[test]
fn remove_last_leaf_empties_the_tree() {
    let mut t = SplitTree::new(0u32);
    assert_eq!(t.remove(&0), Some(0));
    assert!(t.is_empty());
    assert_eq!(t.remove(&0), None);
}

#[test]
fn remove_collapses_parent_onto_sibling() {
    let mut t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom)]);
    assert_eq!(t.leaves(), vec![&0, &1, &2]);
    assert_eq!(t.remove(&1), Some(1));
    assert_eq!(t.leaves(), vec![&0, &2]);
    assert_eq!(t, build(&[(2, 0, Side::Right)]));
}

#[test]
fn split_then_remove_round_trips_for_several_shapes() {
    let shapes: &[&[(u32, u32, Side)]] = &[
        &[(1, 0, Side::Right)],
        &[(1, 0, Side::Right), (2, 0, Side::Bottom)],
        &[(1, 0, Side::Right), (2, 1, Side::Bottom), (3, 0, Side::Top)],
    ];
    for ops in shapes {
        let original = build(ops);
        let (new_leaf, target, side) = *ops.last().unwrap();
        let mut rebuilt = original.clone();
        assert_eq!(rebuilt.remove(&new_leaf), Some(new_leaf));
        assert!(rebuilt.split(&target, side, new_leaf));
        assert_eq!(rebuilt, original);
    }
}

fn rects_overlap(a: Rect, b: Rect) -> bool {
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
}

#[test]
fn layout_tiles_the_area_without_overlap() {
    let t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom), (3, 0, Side::Top)]);
    let a = area();
    let rects = t.layout(a, 4.0);
    assert_eq!(rects.len(), 4);

    for (_, r) in &rects {
        assert!(r.x >= a.x - f32::EPSILON);
        assert!(r.y >= a.y - f32::EPSILON);
        assert!(r.x + r.w <= a.x + a.w + f32::EPSILON);
        assert!(r.y + r.h <= a.y + a.h + f32::EPSILON);
    }
    for i in 0..rects.len() {
        for j in (i + 1)..rects.len() {
            assert!(!rects_overlap(rects[i].1, rects[j].1));
        }
    }
}

#[test]
fn single_split_areas_sum_to_area_minus_gap() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    let a = area();
    let gap = 4.0;
    let rects = t.layout(a, gap);
    let covered: f32 = rects.iter().map(|(_, r)| r.w * r.h).sum();
    let expected = (a.w - gap) * a.h;
    assert!((covered - expected).abs() < 0.01);
}

#[test]
fn dividers_count_matches_split_count() {
    let t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom), (3, 0, Side::Top)]);
    assert_eq!(t.dividers(area(), 4.0).len(), 3);
    assert_eq!(t.leaves().len(), 4);
}

#[test]
fn set_ratio_clamps_to_bounds() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    let path = t.dividers(area(), 4.0)[0].path.clone();

    assert!(t.set_ratio(&path, 5.0));
    let wide_a = t.layout(area(), 4.0)[0].1.w;

    assert!(t.set_ratio(&path, -5.0));
    let narrow_a = t.layout(area(), 4.0)[0].1.w;

    assert!(narrow_a < wide_a);
    assert!(!t.set_ratio(&[true], 0.5)); // no split at that path (leaf, not a Split)
}

#[test]
fn divider_ratio_at_inverts_the_layout() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Bottom, 1));
    assert!(t.set_ratio(&[], 0.3));
    let d = t.dividers(area(), 4.0)[0].clone();
    assert_eq!(d.area, area());
    let centre_y = d.rect.y + d.rect.h / 2.0;
    assert!((d.ratio_at(0.0, centre_y, 4.0) - 0.3).abs() < 1e-4);
    assert!(
        d.ratio_at(0.0, -100.0, 4.0) < 0.0,
        "unclamped; set_ratio clamps"
    );
}

#[test]
fn equalize_resets_every_ratio() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    let path = t.dividers(area(), 0.0)[0].path.clone();
    assert!(t.set_ratio(&path, 0.8));
    t.equalize();
    let rects = t.layout(area(), 0.0);
    assert!((rects[0].1.w - rects[1].1.w).abs() < 0.01);
}

#[test]
fn resize_step_adjusts_the_nearest_enclosing_split() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    let before = t.layout(area(), 0.0)[0].1.w;
    assert!(t.resize_step(&0, Dir::Right, 0.1));
    let after = t.layout(area(), 0.0)[0].1.w;
    assert!(after > before);
}

#[test]
fn resize_step_without_a_matching_ancestor_returns_false() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    // `0` is the `a` (left) child; there's nothing further left to grow into.
    assert!(!t.resize_step(&0, Dir::Left, 0.1));
    assert!(!t.resize_step(&99, Dir::Right, 0.1));
}

#[test]
fn neighbor_is_symmetric_for_two_leaves() {
    let mut t = SplitTree::new(0u32);
    assert!(t.split(&0, Side::Right, 1));
    assert_eq!(t.neighbor(&0, Dir::Right), Some(&1));
    assert_eq!(t.neighbor(&1, Dir::Left), Some(&0));
    assert_eq!(t.neighbor(&0, Dir::Left), None);
    assert_eq!(t.neighbor(&1, Dir::Right), None);
}

#[test]
fn neighbor_picks_the_nearest_candidate() {
    // 0 | 1 on top of 2 (right column split top/bottom); skew the inner split so 1's centre
    // is unambiguously closer to 0's than 2's is.
    let mut t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom)]);
    let inner_path = t.dividers(area(), 0.0)[1].path.clone();
    assert!(t.set_ratio(&inner_path, 0.8));
    assert_eq!(t.neighbor(&0, Dir::Right), Some(&1));
}

#[test]
fn swap_exchanges_leaf_values_in_place() {
    let mut t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom)]);
    let shape_before = t.clone().map(|_| ());
    assert!(t.swap(&0, &2));
    assert_eq!(t.leaves(), vec![&2, &1, &0]);
    assert_eq!(t.clone().map(|_| ()), shape_before);
    assert!(!t.swap(&0, &0));
    assert!(!t.swap(&0, &999));
}

#[test]
fn move_leaf_relocates_without_losing_other_leaves() {
    let mut t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom)]);
    assert!(t.move_leaf(&2, &0, Side::Top));
    assert_eq!(t.leaves(), vec![&2, &0, &1]);
    assert!(!t.move_leaf(&0, &0, Side::Top));
    assert!(!t.move_leaf(&99, &0, Side::Top));
}

#[test]
fn map_transforms_leaves_and_preserves_shape() {
    let t = build(&[(1, 0, Side::Right), (2, 1, Side::Bottom)]);
    let mapped = t.clone().map(|v| v.to_string());
    assert_eq!(
        mapped.leaves(),
        vec![&"0".to_string(), &"1".to_string(), &"2".to_string()]
    );
    // Shape (splits/ratios) is unchanged: mapping back by parsing restores the original.
    let round_tripped = mapped.map(|s| s.parse::<u32>().unwrap());
    assert_eq!(round_tripped, t);
}

#[test]
fn graft_puts_a_whole_tree_beside_the_target_and_still_tiles() {
    let mut tree = build(&[(2, 0, Side::Right)]);
    let mut other = SplitTree::new(10);
    assert!(other.split(&10, Side::Bottom, 11));
    assert!(tree.graft(&2, Side::Bottom, other));
    assert_eq!(tree.leaves(), vec![&0, &2, &10, &11]);
    let rects = tree.layout(area(), 0.0);
    let total: f32 = rects.iter().map(|(_, r)| r.w * r.h).sum();
    assert!((total - area().w * area().h).abs() < 1.0, "tiles the area");
    for (i, (_, a)) in rects.iter().enumerate() {
        for (_, b) in rects.iter().skip(i + 1) {
            assert!(!rects_overlap(*a, *b));
        }
    }
    // 0 keeps the left half; 2 and the grafted 10/11 share the right half.
    let one = rects.iter().find(|(v, _)| *v == 0).unwrap().1;
    assert!((one.w - area().w / 2.0).abs() < 1.0);
    assert!(
        !tree.graft(&99, Side::Left, SplitTree::new(5)),
        "unknown target"
    );
    assert_eq!(tree.leaves().len(), 4);
}
