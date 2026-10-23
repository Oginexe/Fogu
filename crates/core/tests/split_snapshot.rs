//! Serde round-trip of a `SplitTree` through TOML. The snapshot doubles as the recovery-format
//! reference.

use fogu_core::{Side, SplitTree};

fn five_leaf_tree() -> SplitTree<u32> {
    let mut t = SplitTree::new(0);
    assert!(t.split(&0, Side::Right, 1));
    assert!(t.split(&1, Side::Bottom, 2));
    assert!(t.split(&0, Side::Top, 3));
    assert!(t.split(&2, Side::Left, 4));
    t
}

#[test]
fn toml_round_trip_of_a_five_leaf_tree() {
    let tree = five_leaf_tree();
    assert_eq!(tree.leaves().len(), 5);

    let toml = toml::to_string_pretty(&tree).expect("serialize");
    insta::assert_snapshot!(toml);

    let back: SplitTree<u32> = toml::from_str(&toml).expect("deserialize");
    assert_eq!(back, tree);
}
