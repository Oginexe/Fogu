//! `SplitContainer` geometry tests.

use super::*;

#[test]
fn hit_area_is_wider_than_the_gap_and_centred() {
    let mut tree = SplitTree::new(PaneId(1));
    assert!(tree.split(&PaneId(1), fogu_core::Side::Right, PaneId(2)));
    let bounds = Rectangle::new(Point::ORIGIN, Size::new(202.0, 102.0));
    let divider = tree.dividers(inner(bounds), GAP).remove(0);
    let hit = hit_area(&divider);
    assert!((hit.width - HIT).abs() < f32::EPSILON);
    let gap_centre = divider.rect.x + divider.rect.w / 2.0;
    assert!((hit.center_x() - gap_centre).abs() < 1e-4);
    assert!(hit.contains(Point::new(gap_centre + 3.5, 50.0)));
    assert!(!hit.contains(Point::new(gap_centre + 4.5, 50.0)));
    let line = across(&divider, 1.0);
    assert!((line.width - 1.0).abs() < f32::EPSILON);
}

#[test]
fn frame_strips_tile_the_border_without_overlap() {
    let outer = Rectangle::new(Point::new(0.0, 0.0), Size::new(100.0, 50.0));
    let inner = Rectangle::new(Point::new(2.0, 2.0), Size::new(96.0, 46.0));
    let strips = frame(outer, inner);
    let area: f32 = strips.iter().map(|r| r.width * r.height).sum();
    assert!((area - (100.0 * 50.0 - 96.0 * 46.0)).abs() < 1e-3);
    assert!(strips.iter().all(|r| {
        r.intersection(&inner)
            .is_none_or(|i| i.width * i.height == 0.0)
    }));
}
