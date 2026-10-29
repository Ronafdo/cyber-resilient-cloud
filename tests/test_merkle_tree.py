from cyber_resilient_cloud.merkle.tree import build_tree, insert_leaf, verify_leaf


def test_build_tree_and_verify_leaf():
    leaves = [b"alpha", b"beta", b"gamma"]
    tree = build_tree(leaves)

    assert tree["root"]
    assert verify_leaf(tree, b"alpha", 0) is True
    assert verify_leaf(tree, b"delta", 0) is False


def test_insert_leaf_updates_tree_and_verifies_new_leaf():
    tree = build_tree([b"one", b"two"])
    updated_tree = insert_leaf(tree, b"three")

    assert len(updated_tree["levels"][0]) == 3
    assert verify_leaf(updated_tree, b"three", 2) is True
